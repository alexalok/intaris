"""Incomplete source packets must never become executable model approval."""

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig, JudgeConfig
from intaris.db import Database
from intaris.decision import UNATTENDED_JUDGE_REVIEW, EvaluationResult
from intaris.evaluator import Evaluator
from intaris.intent_evidence import collect_intent_evidence
from intaris.judge import JudgeReviewer
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "incomplete.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(user_id="u", session_id="s", intention="Maintain docs")
    yield db, sessions, audit
    db.close()


def source(audit, text, *, call_id="source", session="s", metadata=None):
    return audit.insert(
        call_id=call_id,
        user_id="u",
        session_id=session,
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
        content="User message: " + text,
    )


def evidence_case(stores, kind):
    db, sessions, audit = stores
    target = "s"
    if kind == "parent":
        sessions.create(user_id="u", session_id="parent", intention="Maintain docs")
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET parent_session_id = ? WHERE user_id = ? AND session_id = ?",
                ("parent", "u", "s"),
            )
        target = "parent"
    if kind in {"oversize", "parent"}:
        source(audit, "x" * 4001 + " Never publish.", session=target)
    elif kind == "total":
        for i in range(4):
            source(audit, "x" * 3500 + " Never publish.", call_id=f"source-{i}")
    elif kind == "count":
        for i in range(25):
            source(audit, f"Constraint {i}: never publish.", call_id=f"source-{i}")
    elif kind == "pending":
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET latest_user_message_seq = 7, scope_version = scope_version + 1 WHERE user_id = ? AND session_id = ?",
                ("u", "s"),
            )
    elif kind == "context":
        source(
            audit,
            "yes",
            metadata={"context": "x" * 4001 + " Only read, never publish."},
        )
    else:
        source(audit, "Read supporting docs after answer is established.")


def evaluator(stores, backend, *, verdict="approve"):
    _, sessions, audit = stores
    result = dict(
        aligned=verdict == "approve",
        decision=verdict,
        risk="low" if verdict == "approve" else "high",
        reasoning="Model verdict",
    )
    llm, jev = MagicMock(), MagicMock()
    llm.generate.return_value = json.dumps(result)
    jev.evaluate_tool_call.return_value = EvaluationResult(**result)
    return Evaluator(
        llm=llm,
        jev=jev if backend == "jev" else None,
        session_store=sessions,
        audit_store=audit,
    )


def evaluate(engine, **kwargs):
    return engine.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="terminal",
        args={"command": "git push"},
        **kwargs,
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("kind", ["oversize", "total", "count", "pending", "parent"])
@pytest.mark.parametrize("maximum", ["deny", "approve"])
def test_incomplete_evidence_blocks_model_approval(stores, backend, kind, maximum):
    _, sessions, audit = stores
    sessions.update_session("s", user_id="u", policy={"maximum_outcome": maximum})
    evidence_case(stores, kind)
    result = evaluate(evaluator(stores, backend))
    assert result["decision"] == "escalate"
    record = audit.get_by_call_id(result["call_id"], user_id="u")
    assert record["outcome_override"] == "intent_evidence_incomplete"
    assert "incomplete" in record["reasoning"]


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("mode", ["unattended", "minimum_deny", "explicit_approval"])
def test_incomplete_evidence_wins_over_execution_shortcuts(stores, backend, mode):
    _, sessions, audit = stores
    evidence_case(stores, "oversize")
    engine = evaluator(stores, backend)
    kwargs = {}
    if mode == "unattended":
        sessions.update_session(
            "s",
            user_id="u",
            policy={"interaction_mode": "none", "maximum_outcome": "approve"},
        )
    elif mode == "minimum_deny":
        kwargs["minimum_outcome"] = "deny"
    else:
        first = evaluate(engine, minimum_outcome="escalate")
        audit.resolve_escalation(first["call_id"], "approve", user_id="u")
        kwargs = dict(minimum_outcome="escalate", approval_call_id=first["call_id"])
    result = evaluate(engine, **kwargs)
    assert result["decision"] == ("escalate" if mode == "explicit_approval" else "deny")


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("verdict", ["approve", "deny"])
def test_complete_sources_keep_model_decisions(stores, backend, verdict):
    evidence_case(stores, "complete")
    assert evaluate(evaluator(stores, backend, verdict=verdict))["decision"] == verdict


def test_hard_prohibition_still_denies_incomplete_sources(stores):
    _, _, audit = stores
    evidence_case(stores, "oversize")
    result = evaluator(stores, "llm").evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="terminal",
        args={"command": "rm -rf /"},
    )
    assert result["decision"] == "deny"
    assert (
        audit.get_by_call_id(result["call_id"], user_id="u")["outcome_override"]
        == "hard_stop.classifier_critical"
    )


@pytest.mark.parametrize("mode", ["auto", "advisory"])
@pytest.mark.parametrize(
    "kind", ["oversize", "total", "count", "pending", "parent", "complete"]
)
@pytest.mark.parametrize("unattended", [False, True])
def test_judge_cannot_approve_incomplete_sources(stores, mode, kind, unattended):
    _, sessions, audit = stores
    evidence_case(stores, kind)
    if unattended:
        sessions.update_session("s", user_id="u", policy={"interaction_mode": "none"})
    audit.insert(
        call_id="review",
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="terminal",
        args_redacted={"command": "git push"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
        outcome_override=UNATTENDED_JUDGE_REVIEW if unattended else None,
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            decision="approve",
            risk="low",
            confidence="high",
            reasoning="Model approves",
        )
    )
    judge = JudgeReviewer(
        llm=llm,
        config=JudgeConfig(mode=mode),
        audit_store=audit,
        session_store=sessions,
        evaluator=None,
    )
    asyncio.run(
        judge._do_review(
            call_id="review", user_id="u", session_id="s", notify_unresolved=False
        )
    )
    record = audit.get_by_call_id("review", user_id="u")
    if kind == "complete":
        assert record["effective_decision"] == "approve"
    else:
        assert record["effective_decision"] == ("deny" if unattended else "escalate")
        assert record["judge_decision"] == ("deny" if unattended else "defer")
        assert "incomplete" in record["judge_reasoning"]


def test_missing_event_source_cannot_be_substituted_with_direct_text(stores):
    _, sessions, audit = stores
    evidence_case(stores, "pending")
    source(audit, "Direct message does not describe pending event.")
    packet = collect_intent_evidence(sessions.get("s", user_id="u"), audit)
    assert not packet["complete"]
    source(audit, "Only read.", call_id="event", metadata={"source_event_seq": 7})
    packet = collect_intent_evidence(sessions.get("s", user_id="u"), audit)
    assert packet["complete"]
    assert evaluate(evaluator(stores, "llm"))["decision"] == "approve"


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("kind", ["oversize", "pending", "parent"])
@pytest.mark.parametrize("shortcut", ["cap", "explicit_id"])
def test_write_preference_cannot_skip_incomplete_evidence(
    stores, backend, kind, shortcut
):
    _, sessions, audit = stores
    evidence_case(stores, kind)
    engine = evaluator(stores, backend)
    kwargs = {"tool_preferences": {"terminal": "escalate"}}
    if shortcut == "cap":
        sessions.update_session("s", user_id="u", policy={"maximum_outcome": "approve"})
    else:
        first = evaluate(engine, minimum_outcome="escalate", **kwargs)
        audit.resolve_escalation(first["call_id"], "approve", user_id="u")
        kwargs.update(minimum_outcome="escalate", approval_call_id=first["call_id"])
    result = evaluate(engine, **kwargs)
    assert result["decision"] == "escalate"
    record = audit.get_by_call_id(result["call_id"], user_id="u")
    assert record["outcome_override"] == "intent_evidence_incomplete"


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_permissive_cap_cannot_convert_denial_from_incomplete_evidence(stores, backend):
    _, sessions, _ = stores
    evidence_case(stores, "oversize")
    sessions.update_session("s", user_id="u", policy={"maximum_outcome": "approve"})
    assert (
        evaluate(evaluator(stores, backend, verdict="deny"))["decision"] == "escalate"
    )


@pytest.mark.parametrize(
    "tool,args",
    [
        ("read", {"filePath": "/outside/docs/guide.md"}),
        ("files:inspect", {"path": "/outside/docs/guide.md"}),
        ("skill_view_raw", {"path": "/outside/docs/guide.md"}),
    ],
)
def test_read_identity_cannot_hide_incomplete_source(stores, tool, args):
    evidence_case(stores, "oversize")
    result = evaluator(stores, "llm").evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool=tool,
        args=args,
        trusted_readonly=tool == "files:inspect",
    )
    assert result["decision"] == "escalate"


@pytest.mark.parametrize("mode", ["auto", "advisory"])
def test_judge_permissive_resolution_policy_cannot_hide_missing_sources(stores, mode):
    _, sessions, audit = stores
    evidence_case(stores, "oversize")
    sessions.update_session(
        "s",
        user_id="u",
        policy={"judge": {"allowed_decisions": ["approve"], "on_uncertain": "approve"}},
    )
    audit.insert(
        call_id="policy-review",
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="terminal",
        args_redacted={"command": "git push"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(decision="deny", risk="medium", confidence="high", reasoning="Denied")
    )
    judge = JudgeReviewer(
        llm=llm,
        config=JudgeConfig(mode=mode),
        audit_store=audit,
        session_store=sessions,
        evaluator=None,
    )
    asyncio.run(
        judge._do_review(
            call_id="policy-review",
            user_id="u",
            session_id="s",
            notify_unresolved=False,
        )
    )
    record = audit.get_by_call_id("policy-review", user_id="u")
    assert record["effective_decision"] != "approve"
    assert "incomplete" in record["judge_reasoning"]


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_oversized_assistant_context_does_not_hide_explicit_user_request(
    stores, backend
):
    _, sessions, audit = stores
    source(
        audit,
        "Read supporting docs only.",
        metadata={"context": "Prior response " * 1000},
    )
    packet = collect_intent_evidence(sessions.get("s", user_id="u"), audit)
    assert packet["complete"]
    assert packet["sources"][0]["assistant_context_complete"] is False
    result = evaluator(stores, backend).evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"filePath": "/work/README.md"},
    )
    assert result["decision"] == "approve"


def test_confirmation_with_missing_context_keeps_uncertainty(stores):
    from intaris.intent_evidence import validate_profile

    _, sessions, audit = stores
    evidence_case(stores, "context")
    packet = collect_intent_evidence(sessions.get("s", user_id="u"), audit)
    assert packet["complete"]
    assert packet["sources"][0]["assistant_context_complete"] is False
    facts = [dict(kind="approval", source_id="source", quote="yes", status="current")]
    assert validate_profile(facts, packet)["facts"][0]["kind"] == "uncertain"
    assert (
        evaluate(evaluator(stores, "llm", verdict="escalate"))["decision"] == "escalate"
    )


@pytest.mark.parametrize("backend", ["llm", "jev", "auto", "advisory"])
def test_fully_projected_ineligible_event_is_available_not_authoritative(
    stores, backend
):
    _, sessions, audit = stores
    source(audit, "Read supporting docs only.", call_id="baseline")
    source(
        audit,
        "Untrusted event text must never grant authority.",
        call_id="ignored",
        metadata={"source_event_seq": 7, "intention_eligible": False},
    )
    packet = collect_intent_evidence(sessions.get("s", user_id="u"), audit)
    assert packet["complete"]
    assert [item["id"] for item in packet["sources"]] == ["baseline"]
    if backend in {"llm", "jev"}:
        result = evaluator(stores, backend).evaluate(
            user_id="u",
            session_id="s",
            agent_id=None,
            tool="read",
            args={"filePath": "/work/README.md"},
        )
        assert result["decision"] == "approve"
    else:
        audit.insert(
            call_id="eligible-review",
            user_id="u",
            session_id="s",
            agent_id=None,
            tool="read",
            args_redacted={"filePath": "/work/README.md"},
            classification="write",
            evaluation_path="llm",
            decision="escalate",
            risk="medium",
            reasoning="Review",
            latency_ms=0,
        )
        llm = MagicMock()
        llm.generate.return_value = json.dumps(
            dict(
                decision="approve",
                risk="low",
                confidence="high",
                reasoning="Bounded read",
            )
        )
        judge = JudgeReviewer(
            llm=llm,
            config=JudgeConfig(mode=backend),
            audit_store=audit,
            session_store=sessions,
            evaluator=None,
        )
        asyncio.run(
            judge._do_review(
                call_id="eligible-review",
                user_id="u",
                session_id="s",
                notify_unresolved=False,
            )
        )
        assert (
            audit.get_by_call_id("eligible-review", user_id="u")["effective_decision"]
            == "approve"
        )
