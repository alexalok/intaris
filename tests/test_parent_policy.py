"""Ancestor prohibitions apply to every child approval path."""

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig, JudgeConfig
from intaris.db import Database
from intaris.evaluator import Evaluator
from intaris.judge import JudgeReviewer
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "parents.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(session_id="grandparent", user_id="u", intention="Work")
    sessions.create(
        session_id="parent",
        user_id="u",
        intention="Work",
        parent_session_id="grandparent",
    )
    sessions.create(
        session_id="child",
        user_id="u",
        intention="Work",
        parent_session_id="parent",
        details={"working_directory": "/child"},
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            aligned=True,
            risk="low",
            decision="approve",
            reasoning="Safe",
            confidence="high",
        )
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    yield db, sessions, audit, llm, evaluator
    db.close()


CASES = [
    ({"deny_tools": ["read"]}, "read", {"filePath": "/child/a"}),
    ({"deny_commands": ["git push*"]}, "bash", {"command": "git push"}),
    ({"deny_paths": ["/child/private/*"]}, "read", {"filePath": "private/a"}),
]


@pytest.mark.parametrize("ancestor", ["parent", "grandparent"])
@pytest.mark.parametrize("restricted", [False, True])
@pytest.mark.parametrize("policy,tool,args", CASES)
def test_ancestor_hard_denies_win_over_child_allow_and_cap(
    stores, ancestor, restricted, policy, tool, args
):
    _, sessions, audit, llm, _ = stores
    sessions.update_session(ancestor, user_id="u", policy=policy)
    permissive = {"allow_tools": [tool], "maximum_outcome": "approve"}
    sessions.update_session("child", user_id="u", policy=permissive)
    evaluator = Evaluator(
        llm=llm, session_store=sessions, audit_store=audit, agent_policy=permissive
    )
    result = evaluator.evaluate(
        session_id="child",
        user_id="u",
        agent_id=None,
        tool=tool,
        args=args,
        restricted_agent=restricted,
    )
    assert result["decision"] == "deny"
    assert result["classification"] == "critical"
    llm.generate.assert_not_called()


@pytest.mark.parametrize("resolver", ["user", "judge"])
@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize("change", ["deny", "restricted", "reparent", "stop"])
def test_pending_approval_rechecks_current_ancestor_state(
    stores, monkeypatch, resolver, late, change
):
    import intaris.audit as module

    db, sessions, audit, _, _ = stores
    audit.set_agent_policy(db, {"deny_tools": ["edit"]})
    audit.insert(
        call_id="pending",
        session_id="child",
        user_id="u",
        agent_id=None,
        tool="edit",
        args_redacted={"filePath": "/child/a"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )

    def mutate():
        if change == "deny":
            sessions.update_session(
                "grandparent", user_id="u", policy={"deny_tools": ["edit"]}
            )
        elif change == "restricted":
            sessions.restrict_agent_session("grandparent", user_id="u")
        elif change == "stop":
            sessions.update_status("grandparent", "suspended", user_id="u")
        else:
            sessions.create(
                session_id="blocked",
                user_id="u",
                intention="Work",
                policy={"deny_tools": ["edit"]},
            )
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE sessions SET parent_session_id = ? WHERE session_id = ? AND user_id = ?",
                    ("blocked", "parent", "u"),
                )

    if late:
        original = module.validate_approval_policy

        def race(*args, **kwargs):
            original(*args, **kwargs)
            mutate()

        monkeypatch.setattr(module, "validate_approval_policy", race)
    else:
        mutate()
    with pytest.raises(ValueError):
        audit.resolve_escalation(
            "pending", "approve", user_id="u", resolved_by=resolver
        )
    assert audit.get_by_call_id("pending", user_id="u")["user_decision"] is None


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_semantic_parent_deny_is_rendered_and_read_does_not_fast_path(stores, backend):
    from intaris.decision import EvaluationResult

    _, sessions, audit, llm, _ = stores
    clause = "Never inspect billing records."
    sessions.update_session("parent", user_id="u", policy={"deny_policies": [clause]})
    jev = MagicMock()
    jev.evaluate_tool_call.return_value = EvaluationResult(
        aligned=False, risk="high", decision="deny", reasoning=clause
    )
    llm.generate.return_value = json.dumps(
        dict(aligned=False, risk="high", decision="deny", reasoning=clause)
    )
    evaluator = Evaluator(
        llm=llm,
        jev=jev if backend == "jev" else None,
        session_store=sessions,
        audit_store=audit,
    )
    result = evaluator.evaluate(
        session_id="child",
        user_id="u",
        agent_id=None,
        tool="read",
        args={"filePath": "/child/billing"},
    )
    assert result["decision"] == "deny"
    assert result["path"] == "llm"
    assert clause in str(
        jev.evaluate_tool_call.call_args if backend == "jev" else llm.generate.call_args
    )


def test_judge_sees_ancestor_policy_and_cannot_override_deterministic_deny(stores):
    _, sessions, audit, llm, evaluator = stores
    sessions.update_session(
        "parent",
        user_id="u",
        policy={
            "deny_tools": ["edit"],
            "deny_policies": ["Do not change billing records."],
        },
    )
    audit.insert(
        call_id="pending",
        session_id="child",
        user_id="u",
        agent_id=None,
        tool="edit",
        args_redacted={"filePath": "/child/a"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )
    reviewer = JudgeReviewer(
        llm=llm,
        config=JudgeConfig(mode="auto", notify_mode="never"),
        audit_store=audit,
        session_store=sessions,
        evaluator=evaluator,
    )
    asyncio.run(
        reviewer.review_and_resolve(call_id="pending", user_id="u", session_id="child")
    )
    assert "Do not change billing records." in str(llm.generate.call_args)
    assert audit.get_by_call_id("pending", user_id="u")["user_decision"] != "approve"


@pytest.mark.parametrize("bad_chain", ["missing", "foreign", "cycle", "deep"])
def test_unavailable_ancestry_cannot_grant_fast_read_or_pending_approval(
    stores, bad_chain
):
    db, sessions, audit, _, evaluator = stores
    target = "absent"
    if bad_chain == "foreign":
        sessions.create(
            session_id=target,
            user_id="foreign",
            intention="Other",
            policy={"deny_tools": ["read"]},
        )
    elif bad_chain == "cycle":
        target = "child"
    elif bad_chain == "deep":
        for i in range(3):
            sessions.create(
                session_id=f"deep-{i}",
                user_id="u",
                intention="Work",
                parent_session_id=f"deep-{i - 1}" if i else None,
            )
        target = "deep-2"
    with db.cursor() as cur:
        cur.execute(
            "UPDATE sessions SET parent_session_id = ? WHERE session_id = ? AND user_id = ?",
            (target, "grandparent", "u"),
        )
    with pytest.raises(ValueError, match="ancestr"):
        evaluator.evaluate(
            session_id="child",
            user_id="u",
            agent_id=None,
            tool="read",
            args={"filePath": "/child/a"},
        )
    audit.insert(
        call_id="pending",
        session_id="child",
        user_id="u",
        agent_id=None,
        tool="edit",
        args_redacted={},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )
    with pytest.raises(ValueError, match="ancestr"):
        audit.resolve_escalation("pending", "approve", user_id="u")


@pytest.mark.parametrize("cwd", [None, "/parent", "/child"])
def test_absolute_ancestor_denied_paths_do_not_need_or_borrow_parent_cwd(stores, cwd):
    _, sessions, _, _, evaluator = stores
    sessions.update_session(
        "parent",
        user_id="u",
        policy={"deny_paths": ["/child/private/*"]},
        details={"working_directory": "/parent"},
    )
    sessions.update_session("child", user_id="u", details={"working_directory": cwd})
    result = evaluator.evaluate(
        session_id="child",
        user_id="u",
        agent_id=None,
        tool="read",
        args={"filePath": "/child/private/a"},
    )
    assert result["decision"] == "deny"


def test_parent_allows_caps_and_cwd_do_not_become_child_permission(stores):
    _, sessions, _, llm, evaluator = stores
    sessions.update_session(
        "parent",
        user_id="u",
        policy={
            "allow_tools": ["edit"],
            "maximum_outcome": "approve",
            "interaction_mode": "none",
            "deny_paths": ["/parent/private/*"],
        },
        details={"working_directory": "/parent"},
    )
    llm.generate.return_value = json.dumps(
        dict(
            aligned=False, risk="medium", decision="escalate", reasoning="Needs review"
        )
    )
    result = evaluator.evaluate(
        session_id="child",
        user_id="u",
        agent_id=None,
        tool="edit",
        args={"filePath": "private/a"},
    )
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"
    assert sessions.get("child", user_id="u")["policy"] is None


@pytest.mark.parametrize(
    "tool,args",
    [("read", {"filePath": "private/a"}), ("terminal", {"command": "cat private/a"})],
)
def test_relative_path_cannot_skip_ancestor_deny_without_executor_cwd(
    stores, tool, args
):
    _, sessions, _, llm, evaluator = stores
    sessions.update_session(
        "parent", user_id="u", policy={"deny_paths": ["/child/private/*"]}
    )
    sessions.update_session(
        "child",
        user_id="u",
        details={"working_directory": None},
        policy={"allow_tools": [tool], "maximum_outcome": "approve"},
    )
    result = evaluator.evaluate(
        session_id="child", user_id="u", agent_id=None, tool=tool, args=args
    )
    assert result["decision"] == "deny"
    assert "working directory" in result["reasoning"]
    llm.generate.assert_not_called()


@pytest.mark.parametrize("state", ["active", "idle", "completed"])
def test_non_stopped_ancestor_does_not_prevent_child_reads(stores, state):
    _, sessions, _, _, evaluator = stores
    sessions.update_status("grandparent", state, user_id="u")
    result = evaluator.evaluate(
        session_id="child",
        user_id="u",
        agent_id=None,
        tool="read",
        args={"filePath": "/child/a"},
    )
    assert result["decision"] == "approve"


@pytest.mark.parametrize("clauses", [["", {}], "  ", [{"id": "blank", "text": ""}]])
def test_empty_ancestor_semantic_clauses_do_not_escalate_reads(stores, clauses):
    _, sessions, _, llm, evaluator = stores
    sessions.update_session("parent", user_id="u", policy={"deny_policies": clauses})
    result = evaluator.evaluate(
        session_id="child",
        user_id="u",
        agent_id=None,
        tool="read",
        args={"filePath": "/child/a"},
    )
    assert result["decision"] == "approve"
    assert result["path"] == "fast"
    llm.generate.assert_not_called()
