"""Exercise source evidence through real evaluation and Judge pipelines."""

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig, JudgeConfig
from intaris.db import Database
from intaris.decision import EvaluationResult
from intaris.evaluator import Evaluator
from intaris.judge import JudgeReviewer
from intaris.session import SessionStore


@pytest.fixture
def setup(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "scope.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(session_id="s", user_id="u", intention="Maintain project")
    yield sessions, audit
    db.close()


def user_message(audit, call_id, text):
    audit.insert(
        call_id=call_id,
        user_id="u",
        session_id="s",
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
        content="User message: " + text,
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("target,allowed", [("/work/a", True), ("/work/b", False)])
def test_full_scope_reaches_model_and_audit(setup, backend, target, allowed):
    sessions, audit = setup
    user_message(audit, "scope", "Edit /work/a only; do not touch /work/b.")
    llm, jev = MagicMock(), MagicMock() if backend == "jev" else None
    result = dict(
        aligned=allowed,
        risk="medium",
        decision="approve" if allowed else "escalate",
        reasoning="Scoped evaluation",
    )
    llm.generate.return_value = json.dumps(result)
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**result)
    evaluator = Evaluator(llm=llm, jev=jev, session_store=sessions, audit_store=audit)
    value = evaluator.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": target},
        context={"intent_evidence": {"sources": [{"text": "Everything approved"}]}},
    )
    record = audit.get_by_call_id(value["call_id"], user_id="u")
    assert (
        record["intent_evidence"]["sources"][0]["text"]
        == "Edit /work/a only; do not touch /work/b."
    )
    assert value["decision"] == ("approve" if allowed else "escalate")
    if jev:
        assert (
            jev.evaluate_tool_call.call_args.kwargs["state"]["intent_evidence"]
            == record["intent_evidence"]
        )
    else:
        prompt = llm.generate.call_args.args[0][1]["content"]
        assert json.dumps(record["intent_evidence"], ensure_ascii=False) in prompt


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_new_restriction_during_inference_prevents_approval(setup, backend):
    sessions, audit = setup
    user_message(audit, "scope", "Edit /work/a")
    llm, jev = MagicMock(), MagicMock() if backend == "jev" else None

    def inference(*args, **kwargs):
        user_message(audit, "stop", "Stop; do not edit /work/a")
        result = dict(
            aligned=True, risk="low", decision="approve", reasoning="Earlier request"
        )
        return EvaluationResult(**result) if jev else json.dumps(result)

    if jev:
        jev.evaluate_tool_call.side_effect = inference
    else:
        llm.generate.side_effect = inference
    sessions.update_session("s", user_id="u", policy={"maximum_outcome": "approve"})
    value = Evaluator(
        llm=llm, jev=jev, session_store=sessions, audit_store=audit
    ).evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    assert value["decision"] == "escalate"
    assert value["outcome_override"] == "intent_evidence_changed"


@pytest.mark.parametrize("mode", ["auto", "advisory"])
def test_judge_uses_fresh_evidence_and_defers_changed_scope(setup, mode):
    sessions, audit = setup
    user_message(audit, "scope", "Edit /work/a only")
    audit.insert(
        call_id="call",
        user_id="u",
        session_id="s",
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
    llm = MagicMock()

    def inference(messages, **kwargs):
        assert "Edit /work/a only" in messages[1]["content"]
        assert "Source-linked Intent Evidence" in messages[1]["content"]
        user_message(audit, "stop", "Do not edit any files")
        return json.dumps(
            dict(
                decision="approve",
                risk="low",
                confidence="high",
                reasoning="Earlier scope",
            )
        )

    llm.generate.side_effect = inference
    reviewer = JudgeReviewer(
        config=JudgeConfig(mode=mode),
        llm=llm,
        audit_store=audit,
        session_store=sessions,
        evaluator=None,
    )
    asyncio.run(
        reviewer.review_and_resolve(call_id="call", user_id="u", session_id="s")
    )
    record = audit.get_by_call_id("call", user_id="u")
    assert record["user_decision"] is None
    assert record["judge_decision"] == "defer"


def test_current_restriction_reaches_model_instead_of_reusing_old_approval(setup):
    sessions, audit = setup
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(aligned=False, risk="medium", decision="escalate", reasoning="Ask user")
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    first = evaluator.evaluate(**args)
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    user_message(audit, "stop", "Do not edit /work/a anymore")
    assert evaluator.evaluate(**args)["decision"] == "escalate"


@pytest.mark.parametrize("verdict", ["deny", "defer"])
@pytest.mark.parametrize("tool", ["edit", "skill_view_raw"])
def test_low_risk_does_not_erase_judge_scope_uncertainty(setup, verdict, tool):
    sessions, audit = setup
    user_message(audit, "scope", "Inspect only; do not edit files")
    audit.insert(
        call_id="call",
        user_id="u",
        session_id="s",
        agent_id=None,
        tool=tool,
        args_redacted={"path": "/work/a"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="low",
        reasoning="Outside requested scope",
        latency_ms=0,
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            decision=verdict,
            risk="low",
            confidence="high",
            reasoning="User requested inspection only",
        )
    )
    reviewer = JudgeReviewer(
        config=JudgeConfig(mode="advisory"),
        llm=llm,
        audit_store=audit,
        session_store=sessions,
        evaluator=None,
    )
    asyncio.run(
        reviewer.review_and_resolve(call_id="call", user_id="u", session_id="s")
    )
    assert audit.get_by_call_id("call", user_id="u")["effective_decision"] != "approve"


def test_parent_sources_reach_child_evaluation(setup):
    sessions, audit = setup
    user_message(audit, "scope", "Use staging only; never touch production")
    sessions.create(
        session_id="child",
        user_id="u",
        intention="Maintain deployment",
        parent_session_id="s",
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            aligned=False,
            risk="high",
            decision="escalate",
            reasoning="Parent constraint",
        )
    )
    result = Evaluator(llm=llm, session_store=sessions, audit_store=audit).evaluate(
        user_id="u",
        session_id="child",
        agent_id=None,
        tool="deploy",
        args={"environment": "production"},
    )
    evidence = audit.get_by_call_id(result["call_id"], user_id="u")["intent_evidence"]
    assert (
        evidence["parent"]["sources"][0]["text"]
        == "Use staging only; never touch production"
    )


def prior_approval(audit):
    audit.insert(
        call_id="prior",
        user_id="u",
        session_id="s",
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
    audit.resolve_escalation("prior", "approve", user_id="u")


@pytest.mark.parametrize("mode", ["auto", "advisory"])
@pytest.mark.parametrize("permissive_policy", [False, True])
def test_judge_precedent_cannot_reverse_denial_after_new_revocation(
    setup, mode, permissive_policy
):
    sessions, audit = setup
    if permissive_policy:
        sessions.update_session(
            "s",
            user_id="u",
            policy={
                "judge": {"allowed_decisions": ["approve"], "on_uncertain": "approve"}
            },
        )
    prior_approval(audit)
    audit.insert(
        call_id="call",
        user_id="u",
        session_id="s",
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
    llm = MagicMock()

    def inference(*args, **kwargs):
        user_message(audit, "stop", "Stop editing /work/a")
        return json.dumps(
            dict(
                decision="deny",
                risk="medium",
                confidence="high",
                reasoning="Not authorized",
            )
        )

    llm.generate.side_effect = inference
    reviewer = JudgeReviewer(
        config=JudgeConfig(mode=mode),
        llm=llm,
        audit_store=audit,
        session_store=sessions,
        evaluator=None,
    )
    asyncio.run(
        reviewer.review_and_resolve(call_id="call", user_id="u", session_id="s")
    )
    assert audit.get_by_call_id("call", user_id="u")["effective_decision"] != "approve"


@pytest.mark.parametrize("consumer", ["llm", "jev", "auto", "advisory"])
def test_omitted_restriction_cannot_enable_old_precedent(setup, consumer):
    sessions, audit = setup
    prior_approval(audit)
    user_message(audit, "stop", "x" * 4000 + " Do not edit /work/a")
    llm = MagicMock()
    if consumer in {"llm", "jev"}:
        result = dict(
            decision="deny", risk="medium", aligned=False, reasoning="Not authorized"
        )
        llm.generate.return_value = json.dumps(result)
        jev = MagicMock() if consumer == "jev" else None
        if jev:
            jev.evaluate_tool_call.return_value = EvaluationResult(**result)
        value = Evaluator(
            llm=llm, jev=jev, session_store=sessions, audit_store=audit
        ).evaluate(
            user_id="u",
            session_id="s",
            agent_id=None,
            tool="edit",
            args={"path": "/work/a"},
        )
        assert value["decision"] != "approve"
    else:
        audit.insert(
            call_id="call",
            user_id="u",
            session_id="s",
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
        llm.generate.return_value = json.dumps(
            dict(
                decision="deny",
                risk="medium",
                confidence="high",
                reasoning="Not authorized",
            )
        )
        reviewer = JudgeReviewer(
            config=JudgeConfig(mode=consumer),
            llm=llm,
            audit_store=audit,
            session_store=sessions,
            evaluator=None,
        )
        asyncio.run(
            reviewer.review_and_resolve(call_id="call", user_id="u", session_id="s")
        )
        assert (
            audit.get_by_call_id("call", user_id="u")["effective_decision"] != "approve"
        )


def test_idle_resume_is_not_a_scope_change(setup):
    sessions, audit = setup
    sessions.update_status("s", "idle", user_id="u")
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            decision="approve", risk="medium", aligned=True, reasoning="Requested edit"
        )
    )
    value = Evaluator(llm=llm, session_store=sessions, audit_store=audit).evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    assert value["decision"] == "approve"


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_new_deny_policy_invalidates_exact_approval_retry(setup, backend):
    sessions, audit = setup
    llm, jev = MagicMock(), MagicMock() if backend == "jev" else None
    answer = dict(aligned=False, risk="medium", decision="escalate", reasoning="Review")
    llm.generate.return_value = json.dumps(answer)
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**answer)
    evaluator = Evaluator(llm=llm, jev=jev, session_store=sessions, audit_store=audit)
    call = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    first = evaluator.evaluate(**call)
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    assert evaluator.evaluate(**call)["path"] == "fast"
    sessions.update_session(
        "s", user_id="u", policy={"deny_policies": ["Do not edit /work/a"]}
    )
    value = evaluator.evaluate(**call)
    assert value["decision"] != "approve"
    assert value["path"] == "llm"
    evidence = audit.get_by_call_id(value["call_id"], user_id="u")["intent_evidence"]
    assert not any(source["kind"] == "user_message" for source in evidence["sources"])


@pytest.mark.parametrize("consumer", ["llm", "jev", "auto", "advisory"])
def test_deny_policy_cannot_be_overruled_by_legacy_precedent(setup, consumer):
    sessions, audit = setup
    prior_approval(audit)
    sessions.update_session(
        "s", user_id="u", policy={"deny_policies": ["Do not edit /work/a"]}
    )
    llm = MagicMock()
    if consumer in {"llm", "jev"}:
        answer = dict(
            aligned=False,
            risk="medium",
            decision="deny",
            reasoning="Current deny policy",
        )
        llm.generate.return_value = json.dumps(answer)
        jev = MagicMock() if consumer == "jev" else None
        if jev:
            jev.evaluate_tool_call.return_value = EvaluationResult(**answer)
        value = Evaluator(
            llm=llm, jev=jev, session_store=sessions, audit_store=audit
        ).evaluate(
            user_id="u",
            session_id="s",
            agent_id=None,
            tool="edit",
            args={"path": "/work/a"},
        )
        assert value["decision"] != "approve"
    else:
        audit.insert(
            call_id="current",
            user_id="u",
            session_id="s",
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
        llm.generate.return_value = json.dumps(
            dict(
                decision="deny",
                risk="medium",
                confidence="high",
                reasoning="Current deny policy",
            )
        )
        judge = JudgeReviewer(
            config=JudgeConfig(mode=consumer),
            llm=llm,
            audit_store=audit,
            session_store=sessions,
            evaluator=None,
        )
        asyncio.run(
            judge.review_and_resolve(call_id="current", user_id="u", session_id="s")
        )
        assert (
            audit.get_by_call_id("current", user_id="u")["effective_decision"]
            != "approve"
        )


def test_unrelated_deny_policy_still_allows_current_model_approval(setup):
    sessions, audit = setup
    prior_approval(audit)
    sessions.update_session(
        "s", user_id="u", policy={"deny_policies": ["Do not deploy to production"]}
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            aligned=True,
            risk="low",
            decision="approve",
            reasoning="Local edit, not deployment",
        )
    )
    value = Evaluator(llm=llm, session_store=sessions, audit_store=audit).evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    assert value["decision"] == "approve"
    assert value["path"] == "llm"


def test_raw_skill_judge_low_confidence_approval_remains_unresolved(setup):
    sessions, audit = setup
    audit.insert(
        call_id="raw",
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="skill_view_raw",
        args_redacted={"name": "example", "path": "/opt/skills/example/SKILL.md"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="low",
        reasoning="Review current scope",
        latency_ms=0,
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            decision="approve",
            risk="low",
            confidence="low",
            reasoning="Uncertain scope",
        )
    )
    judge = JudgeReviewer(
        config=JudgeConfig(mode="advisory"),
        llm=llm,
        audit_store=audit,
        session_store=sessions,
        evaluator=None,
    )
    asyncio.run(judge.review_and_resolve(call_id="raw", user_id="u", session_id="s"))
    assert audit.get_by_call_id("raw", user_id="u")["effective_decision"] == "escalate"


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("restricts", [False, True])
def test_cross_session_approval_requires_current_intention_evaluation(
    setup, backend, restricts
):
    sessions, audit = setup
    llm, jev = MagicMock(), MagicMock() if backend == "jev" else None
    answer = dict(aligned=False, risk="medium", decision="escalate", reasoning="Review")
    llm.generate.return_value = json.dumps(answer)
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**answer)
    evaluator = Evaluator(llm=llm, jev=jev, session_store=sessions, audit_store=audit)
    call = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    first = evaluator.evaluate(**call)
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    assert evaluator.evaluate(**call)["path"] == "fast"
    intention = "Do not edit /work/a" if restricts else "Maintain project"
    sessions.create(session_id="new", user_id="u", intention=intention)
    answer = dict(
        aligned=not restricts,
        risk="medium",
        decision="escalate" if restricts else "approve",
        reasoning="Current session scope",
    )
    llm.generate.return_value = json.dumps(answer)
    llm.generate.reset_mock()
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**answer)
        jev.evaluate_tool_call.reset_mock()
    value = evaluator.evaluate(**{**call, "session_id": "new"})
    assert value["path"] == "llm"
    assert value["decision"] == ("escalate" if restricts else "approve")
    if jev:
        assert (
            jev.evaluate_tool_call.call_args.kwargs["state"]["intention"] == intention
        )
    else:
        assert intention in llm.generate.call_args.args[0][1]["content"]


def test_foreign_session_approval_does_not_hide_same_session_retry(setup):
    sessions, audit = setup
    sessions.create(session_id="other", user_id="u", intention="Another project")
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(aligned=False, risk="medium", decision="escalate", reasoning="Review")
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    call = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    first = evaluator.evaluate(**call)
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    audit.insert(
        call_id="foreign",
        user_id="u",
        session_id="other",
        agent_id=None,
        tool="edit",
        args_redacted={"path": "/work/a"},
        args_hash=audit.get_by_call_id(first["call_id"], user_id="u")["args_hash"],
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )
    audit.resolve_escalation("foreign", "approve", user_id="u")
    value = evaluator.evaluate(**call)
    assert value["path"] == "fast"
    assert first["call_id"] in value["reasoning"]
