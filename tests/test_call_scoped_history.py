"""Call-scoped approvals must not authorize later model evaluations."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig, JudgeConfig
from intaris.db import Database
from intaris.decision import EvaluationResult
from intaris.evaluator import Evaluator
from intaris.judge import JudgeReviewer, _build_judge_prompt
from intaris.prompts import build_evaluation_user_prompt
from intaris.session import SessionStore

_NATIVE_NOTE = "Allow native writes in /native-only for this invocation"
_REUSABLE_NOTE = "Allow documentation changes throughout this session"


@pytest.fixture(params=["user", "judge"])
def stores(tmp_path, request):
    db = Database(DBConfig(path=str(tmp_path / "history.db")))
    sessions = SessionStore(db)
    audit = AuditStore(db)
    sessions.create(
        session_id="session",
        user_id="owner",
        intention="Review project documentation",
    )
    for call_id, tool, args, note, scope in (
        (
            "reusable-approval",
            "edit",
            {"file_path": "/docs/readme.md"},
            _REUSABLE_NOTE,
            "reusable",
        ),
        (
            "native-approval",
            "terminal",
            {"command": "touch /native-only/allowed.txt"},
            _NATIVE_NOTE,
            "call",
        ),
    ):
        audit.insert(
            call_id=call_id,
            user_id="owner",
            session_id="session",
            agent_id="hermes",
            tool=tool,
            args_redacted=args,
            classification="write",
            evaluation_path="llm",
            decision="escalate",
            risk="medium",
            reasoning="Requires human approval",
            latency_ms=1,
        )
        # Native approval registration persists this scope before resolution.
        with db.cursor() as cur:
            cur.execute(
                "UPDATE audit_log SET approval_scope = ? WHERE call_id = ?",
                (scope, call_id),
            )
        resolver = request.param if scope == "call" else "user"
        audit.resolve_escalation(
            call_id,
            "approve",
            user_note=note,
            user_id="owner",
            resolved_by=resolver,
            judge_decision="approve" if resolver == "judge" else None,
            judge_reasoning=note if resolver == "judge" else None,
            judge_risk="medium" if resolver == "judge" else None,
        )
    yield sessions, audit
    db.close()


def _assert_approval_history_is_preserved(audit: AuditStore) -> None:
    record = audit.get_by_call_id("native-approval", user_id="owner")
    assert record["approval_scope"] == "call"
    assert record["user_decision"] == "approve"
    assert record["user_note"] == _NATIVE_NOTE
    assert {r["call_id"] for r in audit.get_recent("session", user_id="owner")} >= {
        "native-approval",
        "reusable-approval",
    }


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_evaluator_excludes_native_approval_from_model_history(stores, backend):
    sessions, audit = stores
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        {
            "aligned": False,
            "risk": "medium",
            "reasoning": "Unrelated write requires approval",
            "decision": "escalate",
        }
    )
    jev = MagicMock() if backend == "jev" else None
    if jev is not None:
        jev.evaluate_tool_call.return_value = EvaluationResult(
            aligned=False,
            risk="medium",
            reasoning="Unrelated write requires approval",
            decision="escalate",
        )
    evaluator = Evaluator(
        llm=llm,
        jev=jev,
        session_store=sessions,
        audit_store=audit,
    )

    result = evaluator.evaluate(
        user_id="owner",
        session_id="session",
        agent_id="hermes",
        tool="terminal",
        args={"command": "touch /unrelated/new.txt"},
    )

    assert result["decision"] == "escalate"
    if jev is not None:
        model_input = json.dumps(jev.evaluate_tool_call.call_args.kwargs["state"])
    else:
        model_input = llm.generate.call_args.args[0][1]["content"]
    assert "native-only" not in model_input
    assert _NATIVE_NOTE not in model_input
    assert _REUSABLE_NOTE in model_input
    assert "/unrelated/new.txt" in model_input
    _assert_approval_history_is_preserved(audit)


def test_judge_excludes_native_approval_from_model_history(stores):
    sessions, audit = stores
    audit.insert(
        call_id="later-write",
        user_id="owner",
        session_id="session",
        agent_id="hermes",
        tool="terminal",
        args_redacted={"command": "touch /unrelated/new.txt"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Unrelated write requires approval",
        latency_ms=1,
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        {
            "decision": "deny",
            "reasoning": "No authorization for this unrelated write",
            "risk": "medium",
            "confidence": "high",
        }
    )
    reviewer = JudgeReviewer(
        llm=llm,
        config=JudgeConfig(mode="auto"),
        audit_store=audit,
        session_store=sessions,
        evaluator=None,
    )

    asyncio.run(
        reviewer.review_and_resolve(
            call_id="later-write", user_id="owner", session_id="session"
        )
    )

    result = audit.get_by_call_id("later-write", user_id="owner")
    assert result["user_decision"] == "deny"
    model_input = llm.generate.call_args.args[0][1]["content"]
    assert "native-only" not in model_input
    assert _NATIVE_NOTE not in model_input
    assert _REUSABLE_NOTE in model_input
    assert "/unrelated/new.txt" in model_input
    _assert_approval_history_is_preserved(audit)


@pytest.mark.parametrize("builder", ["evaluator", "judge"])
@pytest.mark.parametrize("approval_scope", ["call", "reusable", None])
def test_prompt_builders_enforce_call_scope_without_mutating_history(
    builder, approval_scope
):
    record = {
        "tool": "terminal",
        "args_redacted": {"command": "touch /native-only/allowed.txt"},
        "decision": "escalate",
        "user_decision": "approve",
        "user_note": _NATIVE_NOTE,
    }
    if approval_scope is not None:
        record["approval_scope"] = approval_scope
    history = [record.copy()]
    common = {
        "intention": "Review documentation",
        "policy": None,
        "recent_history": history,
        "session_stats": {},
        "tool": "terminal",
        "agent_id": None,
    }
    if builder == "evaluator":
        prompt = build_evaluation_user_prompt(
            **common, args={"command": "touch /unrelated/new.txt"}
        )
    else:
        prompt = _build_judge_prompt(
            **common,
            args_redacted={"command": "touch /unrelated/new.txt"},
            evaluator_reasoning="Needs approval",
            evaluator_risk="medium",
            evaluation_path="llm",
        )

    if approval_scope == "call":
        assert "native-only" not in prompt
        assert "escalate→user:approve" not in prompt
    else:
        assert _NATIVE_NOTE in prompt
        assert "escalate→user:approve" in prompt
    assert history == [record]
