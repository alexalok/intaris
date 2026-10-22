"""Race user authority changes against the final Judge approval write."""

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig, JudgeConfig
from intaris.db import Database
from intaris.intent_evidence import collect_intent_evidence
from intaris.judge import JudgeReviewer
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "scope.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(session_id="parent", user_id="u", intention="Maintain project")
    sessions.create(
        session_id="s", user_id="u", intention="Edit file", parent_session_id="parent"
    )
    yield sessions, audit
    db.close()


def message(
    audit,
    call_id="message",
    session_id="s",
    content="User message: Stop editing",
    metadata=None,
):
    audit.insert(
        call_id=call_id,
        user_id="u",
        session_id=session_id,
        agent_id=None,
        tool=None,
        args_redacted=metadata,
        classification=None,
        evaluation_path="reasoning",
        decision="approve",
        risk=None,
        reasoning=None,
        latency_ms=0,
        record_type="reasoning",
        content=content,
    )


def pending(audit, call_id="call", session_id="s"):
    audit.insert(
        call_id=call_id,
        user_id="u",
        session_id=session_id,
        agent_id=None,
        tool="edit",
        args_redacted={"path": "/work/a"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )


@pytest.mark.parametrize("mode", ["auto", "advisory"])
@pytest.mark.parametrize(
    "change",
    [
        "user_message",
        "parent_message",
        "event_audit",
        "human_deny",
        "parent_policy",
        "status",
        "expire_grant",
        "agent_chatter",
        "activity",
        "idle",
        "unchanged",
    ],
)
def test_scope_change_after_last_evidence_read(stores, monkeypatch, mode, change):
    sessions, audit = stores
    pending(audit)
    pending(audit, "other")
    if change == "event_audit":
        sessions.allocate_event_sequences("s", user_id="u", user_message_flags=[True])
    if change == "expire_grant":
        audit.resolve_escalation("other", "approve", user_id="u")
    real_resolve = audit.resolve_escalation

    def raced_resolve(*args, **kwargs):
        if change == "user_message":
            message(audit)
        elif change == "parent_message":
            message(audit, session_id="parent")
        elif change == "event_audit":
            message(audit, metadata={"source_event_seq": 1})
        elif change == "human_deny":
            real_resolve("other", "deny", "Do not edit any files", user_id="u")
        elif change == "parent_policy":
            sessions.update_session(
                "parent", user_id="u", policy={"deny_tools": ["edit"]}
            )
        elif change == "status":
            sessions.update_status("s", "suspended", user_id="u")
        elif change == "expire_grant":
            audit.expire_escalation(
                "other", user_id="u", session_id="s", reason="cancelled"
            )
        elif change == "agent_chatter":
            message(audit, content="Agent reasoning: Reviewing source")
        elif change == "idle":
            sessions.update_status("s", "idle", user_id="u")
        elif change == "activity":
            sessions.update_activity("s", user_id="u")
            sessions.increment_counter("s", "escalate", user_id="u")
        return real_resolve(*args, **kwargs)

    monkeypatch.setattr(audit, "resolve_escalation", raced_resolve)
    llm, metrics, evaluator = MagicMock(), MagicMock(), MagicMock()
    metrics.judge_deferrals_total = metrics.judge_approvals_total = (
        metrics.judge_reviews_total
    ) = 0
    llm.generate.return_value = json.dumps(
        dict(
            decision="approve", risk="low", confidence="high", reasoning="Earlier scope"
        )
    )
    reviewer = JudgeReviewer(
        config=JudgeConfig(mode=mode, notify_mode="never"),
        llm=llm,
        audit_store=audit,
        session_store=sessions,
        evaluator=evaluator,
        metrics=metrics,
    )
    asyncio.run(
        reviewer.review_and_resolve(call_id="call", user_id="u", session_id="s")
    )
    record = audit.get_by_call_id("call", user_id="u")
    if change in {"agent_chatter", "activity", "idle", "unchanged"}:
        assert record["user_decision"] == "approve"
        assert metrics.judge_approvals_total == 1
    else:
        assert record["user_decision"] is None
        assert record["judge_decision"] == "defer"
        assert metrics.judge_deferrals_total == 1
        assert metrics.judge_approvals_total == 0
        evaluator.learn_from_approved_escalation.assert_not_called()


def test_final_write_guards_scope_changed_on_another_connection(stores, monkeypatch):
    import intaris.audit as audit_module

    sessions, audit = stores
    pending(audit)
    evidence = collect_intent_evidence(sessions.get("s", user_id="u"), audit)
    original = audit_module.validate_approval_policy

    def race(*args, **kwargs):
        original(*args, **kwargs)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(message, audit).result(timeout=5)

    monkeypatch.setattr(audit_module, "validate_approval_policy", race)
    with pytest.raises(ValueError, match="scope changed"):
        audit.resolve_escalation(
            "call",
            "approve",
            user_id="u",
            resolved_by="judge",
            scope_versions=evidence["scope_versions"],
        )
    assert audit.get_by_call_id("call", user_id="u")["user_decision"] is None


@pytest.mark.parametrize(
    "change",
    [
        "message",
        "policy",
        "intention",
        "profile",
        "status",
        "alignment",
        "restricted",
        "event",
    ],
)
def test_authority_mutations_advance_scope_version(stores, change):
    sessions, audit = stores
    version = sessions.get("s", user_id="u")["scope_version"]
    if change == "message":
        message(audit)
    elif change == "policy":
        sessions.update_session("s", user_id="u", policy={"deny_tools": ["edit"]})
    elif change == "intention":
        sessions.update_session("s", user_id="u", intention="Read only")
    elif change == "profile":
        sessions.update_generated_intention(
            "s",
            user_id="u",
            intention="Read only",
            intention_source="user",
            title=None,
            intent_profile={"version": 1, "facts": []},
        )
    elif change == "status":
        sessions.update_status("s", "suspended", user_id="u")
    elif change == "alignment":
        sessions.set_alignment_overridden("s", user_id="u", overridden=True)
    elif change == "restricted":
        sessions.restrict_agent_session("s", user_id="u")
    elif change == "event":
        sessions.allocate_event_sequences("s", user_id="u", user_message_flags=[True])
    assert sessions.get("s", user_id="u")["scope_version"] == version + 1


def test_noise_and_repeated_restriction_do_not_invalidate_scope(stores):
    sessions, audit = stores
    sessions.restrict_agent_session("s", user_id="u")
    version = sessions.get("s", user_id="u")["scope_version"]
    sessions.restrict_agent_session("s", user_id="u")
    sessions.update_status("s", "active", user_id="u")
    sessions.set_alignment_overridden("s", user_id="u", overridden=False)
    sessions.update_activity("s", user_id="u")
    sessions.increment_counter("s", "escalate", user_id="u")
    sessions.allocate_event_sequences("s", user_id="u", user_message_flags=[False])
    message(audit, content="Agent reasoning: Work in progress")
    message(audit, "ineligible", metadata={"intention_eligible": False})
    assert sessions.get("s", user_id="u")["scope_version"] == version


def test_human_resolution_keeps_final_override_semantics(stores):
    sessions, audit = stores
    pending(audit)
    audit.resolve_escalation("call", "deny", user_id="u", resolved_by="judge")
    message(audit)
    audit.resolve_escalation(
        "call", "approve", "Proceed with this exact edit", user_id="u"
    )
    assert audit.get_by_call_id("call", user_id="u")["resolved_by"] == "user"


def test_source_insert_revision_rolls_back_with_duplicate_audit_record(stores):
    sessions, audit = stores
    message(audit)
    version = sessions.get("s", user_id="u")["scope_version"]
    with pytest.raises(Exception, match="UNIQUE constraint"):
        message(audit)
    assert sessions.get("s", user_id="u")["scope_version"] == version


def test_scope_revision_migration_is_additive_and_idempotent(tmp_path):
    import sqlite3

    from intaris.db import _SCHEMA_SQL_SQLITE

    path = str(tmp_path / "legacy.db")
    with sqlite3.connect(path) as conn:
        conn.executescript(
            _SCHEMA_SQL_SQLITE.replace(
                "    scope_version INTEGER NOT NULL DEFAULT 0,\n", ""
            )
        )
        conn.execute(
            "INSERT INTO sessions (user_id, session_id, intention, created_at, updated_at) "
            "VALUES ('u', 's', 'Maintain project', '2026-01-01', '2026-01-01')"
        )
    for _ in range(2):
        db = Database(DBConfig(path=path))
        record = SessionStore(db).get("s", user_id="u")
        assert record["intention"] == "Maintain project"
        assert record["scope_version"] == 0
        db.close()
    conn = MagicMock()
    conn.cursor.return_value.fetchone.return_value = None
    Database.__new__(Database)._migrate_pg(conn)
    statements = [
        call.args[0] for call in conn.cursor.return_value.execute.call_args_list
    ]
    assert (
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS scope_version BIGINT NOT NULL DEFAULT 0"
        in statements
    )
