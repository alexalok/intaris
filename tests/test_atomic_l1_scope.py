"""No executable L1 approval can commit after its scope revision changes."""

import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig
from intaris.db import Database
from intaris.decision import EvaluationResult
from intaris.evaluator import Evaluator
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "scope.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(session_id="parent", user_id="u", intention="Inspect project")
    sessions.create(
        session_id="s",
        user_id="u",
        intention="Inspect files",
        parent_session_id="parent",
        details={"working_directory": "/work/project"},
        policy={"maximum_outcome": "approve"},
    )
    yield db, sessions, audit
    db.close()


def user_message(audit, session_id="s"):
    audit.insert(
        call_id="stop",
        user_id="u",
        session_id=session_id,
        agent_id=None,
        tool=None,
        args_redacted=None,
        classification=None,
        evaluation_path="reasoning",
        decision="approve",
        risk=None,
        reasoning=None,
        latency_ms=0,
        record_type="reasoning",
        content="User message: Stop reading these files",
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("unattended", [False, True])
@pytest.mark.parametrize(
    "change", ["message", "parent", "status", "policy", "noise", "none"]
)
def test_late_scope_change_cannot_return_or_cache_approval(
    stores, monkeypatch, backend, unattended, change
):
    db, sessions, audit = stores
    if unattended:
        sessions.update_session(
            "s",
            user_id="u",
            policy={"maximum_outcome": "approve", "interaction_mode": "none"},
        )
    llm, jev = MagicMock(), MagicMock() if backend == "jev" else None
    result = dict(
        aligned=True, risk="low", decision="approve", reasoning="Earlier scope"
    )
    llm.generate.return_value = json.dumps(result)
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**result)
    evaluator = Evaluator(llm=llm, jev=jev, session_store=sessions, audit_store=audit)
    learn = MagicMock(wraps=evaluator._approve_path_prefix)
    monkeypatch.setattr(evaluator, "_approve_path_prefix", learn)
    original = audit.insert
    changed = False

    def race(**kwargs):
        nonlocal changed
        if kwargs.get("record_type", "tool_call") == "tool_call" and not changed:
            changed = True
            if change in {"message", "parent"}:
                user_message(audit, "parent" if change == "parent" else "s")
            elif change == "status":
                sessions.update_status("s", "suspended", user_id="u")
            elif change == "policy":
                sessions.update_session(
                    "s", user_id="u", policy={"deny_tools": ["read"]}
                )
            elif change == "noise":
                sessions.update_activity("s", user_id="u")
        return original(**kwargs)

    monkeypatch.setattr(audit, "insert", race)
    result = evaluator.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"filePath": "/other/file.txt"},
        judge_unattended=unattended,
    )
    stored = audit.get_by_call_id(result["call_id"], user_id="u")
    if change in {"noise", "none"}:
        assert result["decision"] == stored["decision"] == "approve"
    else:
        expected = "deny" if unattended else "escalate"
        assert result["decision"] == stored["decision"] == expected
        assert stored["raw_decision"] == "approve"
        assert stored["outcome_override"] == "intent_evidence_changed"
        assert stored["effective_decision"] == expected
        learn.assert_not_called()
        state = sessions.get("s", user_id="u")
        assert state["approved_count"] == 0
        assert state["total_calls"] == 1
        assert state["denied_count" if unattended else "escalated_count"] == 1
    with db.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM audit_log WHERE session_id = 's' AND record_type = 'tool_call'"
        )
        assert cur.fetchone()[0] == 1


def test_scope_guard_and_insert_share_atomic_boundary(stores, monkeypatch):
    db, sessions, audit = stores
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(aligned=True, risk="low", decision="approve", reasoning="Old scope")
    )
    cursor = db.cursor
    fired = False

    class RacingCursor:
        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def execute(self, statement, parameters=()):
            nonlocal fired
            if not fired and "INSERT INTO audit_log" in statement:
                fired = True
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pool.submit(user_message, audit).result(timeout=5)
            return self.inner.execute(statement, parameters)

    @contextmanager
    def raced_cursor():
        with cursor() as cur:
            yield RacingCursor(cur)

    monkeypatch.setattr(db, "cursor", raced_cursor)
    result = Evaluator(llm=llm, session_store=sessions, audit_store=audit).evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    assert fired
    assert result["decision"] == "escalate"
    assert (
        audit.get_by_call_id(result["call_id"], user_id="u")["decision"] == "escalate"
    )


def test_retry_evidence_cannot_replace_older_classifier_scope(stores, monkeypatch):
    _, sessions, audit = stores
    sessions.create(session_id="retry", user_id="u", intention="Edit files")
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(aligned=False, risk="medium", decision="escalate", reasoning="Review")
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    args = dict(
        user_id="u",
        session_id="retry",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    first = evaluator.evaluate(**args)
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    lookup = audit.find_approved_escalation

    def race(**kwargs):
        sessions.update_session("retry", user_id="u", policy={"deny_tools": ["edit"]})
        return lookup(**kwargs)

    monkeypatch.setattr(audit, "find_approved_escalation", race)
    result = evaluator.evaluate(**args)
    assert result["decision"] != "approve"
    assert (
        audit.get_by_call_id(result["call_id"], user_id="u")["outcome_override"]
        == "intent_evidence_changed"
    )


@pytest.mark.parametrize("resolved_by", ["user", "judge"])
@pytest.mark.parametrize("expired", [False, True])
def test_retry_grant_expiration_at_commit_invalidates_approval(
    stores, monkeypatch, resolved_by, expired
):
    _, sessions, audit = stores
    sessions.create(session_id="retry-expiry", user_id="u", intention="Edit files")
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(aligned=False, risk="medium", decision="escalate", reasoning="Review")
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    args = dict(
        user_id="u",
        session_id="retry-expiry",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    first = evaluator.evaluate(**args)
    assert first["decision"] == "escalate"
    audit.resolve_escalation(
        first["call_id"], "approve", user_id="u", resolved_by=resolved_by
    )
    original = audit.insert
    fired = False

    def race(**kwargs):
        nonlocal fired
        if not fired and kwargs.get("record_type", "tool_call") == "tool_call":
            fired = True
            if expired:
                audit.expire_escalation(
                    first["call_id"],
                    user_id="u",
                    session_id="retry-expiry",
                    reason="cancelled",
                )
        return original(**kwargs)

    monkeypatch.setattr(audit, "insert", race)
    result = evaluator.evaluate(**args)
    stored = audit.get_by_call_id(result["call_id"], user_id="u")
    assert fired
    assert (
        result["decision"]
        == stored["decision"]
        == ("escalate" if expired else "approve")
    )
    if expired:
        assert stored["outcome_override"] == "intent_evidence_changed"
    llm.generate.assert_called_once()
