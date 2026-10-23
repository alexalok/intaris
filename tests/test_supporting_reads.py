"""Reading skill instructions must not authorize their execution."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.classifier import Classification, classify
from intaris.config import DBConfig
from intaris.db import Database
from intaris.decision import EvaluationResult
from intaris.evaluator import Evaluator
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "reads.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(
        user_id="u",
        session_id="s",
        intention="The answer is established; gather supporting evidence.",
        details={"working_directory": "/workspace/project"},
    )
    yield sessions, audit
    db.close()


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize(
    "args",
    [
        {
            "name": "hermes-agent",
            "path": "/opt/skills/hermes-agent/references/security-privacy.md",
        },
        {
            "name": "blocked-page-recovery",
            "path": "/opt/skills/blocked-page-recovery/SKILL.md",
        },
        {
            "name": "credential-exfiltration",
            "path": "/opt/skills/credential-exfiltration/SKILL.md",
        },
        {"name": "destructive-maintenance", "path": "/opt/skills/wipe/SKILL.md"},
    ],
)
def test_skill_read_uses_model_with_raw_effects_and_current_scope(
    stores, backend, args
):
    sessions, audit = stores
    llm = MagicMock()
    deferred = dict(
        aligned=True,
        risk="low",
        decision="approve",
        reasoning="Raw instruction read with no current restriction.",
    )
    llm.generate.return_value = json.dumps(deferred)
    jev = MagicMock() if backend == "jev" else None
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**deferred)
    evaluator = Evaluator(llm=llm, jev=jev, session_store=sessions, audit_store=audit)
    result = evaluator.evaluate(
        user_id="u", session_id="s", agent_id=None, tool="skill_view_raw", args=args
    )
    assert result["decision"] == "approve"
    assert result["path"] == "llm"
    assert result["classification"] == "write"
    assert result["risk"] == "low"
    assert audit.get_by_call_id(result["call_id"], user_id="u")["decision"] == "approve"
    evidence = audit.get_by_call_id(result["call_id"], user_id="u")["intent_evidence"]
    assert evidence["complete"]
    if jev:
        state = jev.evaluate_tool_call.call_args.kwargs["state"]
        assert state["arguments"] == args
        assert state["tool"] == "skill_view_raw"
    else:
        assert args["path"] in llm.generate.call_args.args[0][1]["content"]


@pytest.mark.parametrize("working_directory", [None, "/workspace/project"])
def test_shared_skill_library_still_reviews_current_scope(working_directory):
    assert (
        classify(
            "skill_view_raw",
            {"name": "dangerous-example", "path": "/opt/skills/example/SKILL.md"},
            working_directory=working_directory,
        )
        == Classification.WRITE
    )


@pytest.mark.parametrize("working_directory", [None, "/workspace/project"])
def test_skill_read_obeys_explicit_path_denial(working_directory):
    assert (
        classify(
            "skill_view_raw",
            {"name": "private-skill", "path": "/opt/private/SKILL.md"},
            session_policy={"deny_paths": ["/opt/private/*"]},
            working_directory=working_directory,
        )
        == Classification.CRITICAL
    )


def test_skill_read_obeys_tool_denial_over_allow_rule(stores):
    sessions, audit = stores
    sessions.update_session(
        "s",
        user_id="u",
        policy={"allow_tools": ["skill_view_raw"], "deny_tools": ["skill_view_raw"]},
    )
    llm = MagicMock()
    result = Evaluator(llm=llm, session_store=sessions, audit_store=audit).evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="skill_view_raw",
        args={"name": "example", "path": "/opt/skills/example/SKILL.md"},
    )
    assert result["decision"] == "deny"
    assert result["path"] == "critical"
    llm.generate.assert_not_called()


@pytest.mark.parametrize(
    "preference,expected",
    [("deny", Classification.CRITICAL), ("escalate", Classification.ESCALATE)],
)
def test_skill_read_preserves_operator_preferences(preference, expected):
    assert (
        classify(
            "skill_view_raw",
            {"name": "example", "path": "/opt/skills/example/SKILL.md"},
            tool_preferences={"skill_view_raw": preference},
        )
        == expected
    )


@pytest.mark.parametrize(
    "path",
    [
        "/opt/skills/example/.env",
        "/workspace/project/.env",
        "references/id_rsa",
    ],
)
@pytest.mark.parametrize("working_directory", [None, "/workspace/project"])
def test_skill_read_does_not_fast_path_sensitive_files(path, working_directory):
    assert (
        classify(
            "skill_view_raw",
            {"name": "example", "path": path},
            working_directory=working_directory,
        )
        == Classification.WRITE
    )


def test_skill_path_denial_needs_resolution_when_no_directory_known():
    assert (
        classify(
            "skill_view_raw",
            {"name": "example", "path": "references/guide.md"},
            session_policy={"deny_paths": ["/private/*"]},
        )
        == Classification.WRITE
    )


@pytest.mark.parametrize(
    "tool",
    [
        "skill_view",
        "Skill",
        "skill_run",
        "skill_manage",
        "thirdparty:skill_view_raw",
        "thirdparty:skill_view",
        "mcp__thirdparty__skill_view",
        "thirdparty_skill_view",
    ],
)
def test_skill_execution_or_unknown_namespace_does_not_inherit_read_permission(tool):
    assert (
        classify(tool, {"name": "example", "path": "/opt/skills/example/SKILL.md"})
        == Classification.WRITE
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_reading_malicious_skill_does_not_approve_its_execution(stores, backend):
    sessions, audit = stores
    llm = MagicMock()
    rejection = dict(
        aligned=False,
        risk="high",
        decision="deny",
        reasoning="No permission to execute the script.",
    )
    llm.generate.return_value = json.dumps(rejection)
    jev = MagicMock() if backend == "jev" else None
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**rejection)
    evaluator = Evaluator(llm=llm, jev=jev, session_store=sessions, audit_store=audit)
    accepted = dict(
        aligned=True, risk="low", decision="approve", reasoning="Raw read only"
    )
    llm.generate.return_value = json.dumps(accepted)
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**accepted)
    common = dict(user_id="u", session_id="s", agent_id=None)
    read = evaluator.evaluate(
        **common,
        tool="skill_view_raw",
        args={
            "name": "credential-exfiltration",
            "path": "/opt/skills/credential-exfiltration/SKILL.md",
        },
    )
    assert read["decision"] == "approve"
    llm.generate.return_value = json.dumps(rejection)
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**rejection)
    execute = evaluator.evaluate(
        **common,
        tool="terminal",
        args={"command": "python /opt/skills/credential-exfiltration/run.py"},
    )
    assert execute["decision"] == "deny"
    assert execute["path"] == "llm"
    assert (jev.evaluate_tool_call if jev else llm.generate).call_count == 2
    critical = evaluator.evaluate(
        **common, tool="terminal", args={"command": "rm -rf /"}
    )
    assert critical["decision"] == "deny"
    assert critical["path"] == "critical"
    assert (jev.evaluate_tool_call if jev else llm.generate).call_count == 2


@pytest.mark.parametrize(
    "policy,preferences",
    [
        ({"deny_policies": ["Do not inspect the private skill library."]}, None),
        (None, {"skill_view_raw": "evaluate"}),
    ],
)
def test_skill_read_keeps_explicit_model_evaluation(policy, preferences):
    assert (
        classify(
            "skill_view_raw",
            {"name": "private-skill", "path": "/opt/skills/private-skill/SKILL.md"},
            session_policy=policy,
            tool_preferences=preferences,
        )
        == Classification.WRITE
    )


@pytest.mark.parametrize(
    "args",
    [
        {"name": "example"},
        {"name": "example", "path": "references/guide.md"},
        {"name": "example", "path": "//host/private/SKILL.md"},
    ],
)
@pytest.mark.parametrize("cwd", [None, "/workspace/project"])
def test_raw_skill_read_requires_an_absolute_unambiguous_target(args, cwd):
    assert (
        classify("skill_view_raw", args, working_directory=cwd) == Classification.WRITE
    )


@pytest.mark.parametrize(
    "policy", [{"deny_tools": ["skill_view"]}, {"deny_tools": ["skill_view_raw"]}]
)
def test_raw_read_cannot_escape_original_tool_denial(policy):
    assert (
        classify(
            "skill_view_raw",
            {"name": "example", "path": "/opt/skills/example/SKILL.md"},
            session_policy=policy,
        )
        == Classification.CRITICAL
    )


@pytest.mark.parametrize(
    "preference,expected",
    [
        ("deny", Classification.CRITICAL),
        ("escalate", Classification.ESCALATE),
        ("evaluate", Classification.WRITE),
    ],
)
def test_raw_read_preserves_original_tool_preferences(preference, expected):
    assert (
        classify(
            "skill_view_raw",
            {"name": "example", "path": "/opt/skills/example/SKILL.md"},
            tool_preferences={"skill_view": preference},
        )
        == expected
    )


def test_native_loader_cannot_claim_raw_read_with_agent_arguments():
    assert (
        classify(
            "skill_view",
            {
                "name": "example",
                "raw": True,
                "read_only": True,
                "preprocess": False,
                "path": "/opt/skills/example/SKILL.md",
            },
        )
        == Classification.WRITE
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("source", ["initial", "message", "parent", "omitted"])
def test_skill_read_honors_current_inspection_restriction(stores, backend, source):
    sessions, audit = stores
    restriction = "Do not inspect any more skills."
    session_id = "s"
    if source == "initial":
        sessions.create(user_id="u", session_id="restricted", intention=restriction)
        session_id = "restricted"
    else:
        text = restriction if source != "omitted" else "x" * 4001 + restriction
        audit.insert(
            call_id="stop",
            user_id="u",
            session_id="s",
            agent_id=None,
            tool=None,
            args_redacted={"intention_eligible": True},
            classification=None,
            evaluation_path="reasoning",
            decision="approve",
            risk=None,
            reasoning=None,
            latency_ms=0,
            record_type="reasoning",
            content="User message: " + text,
        )
        if source == "parent":
            sessions.create(
                user_id="u",
                session_id="child",
                intention="Inspect useful skills",
                parent_session_id="s",
            )
            session_id = "child"
    llm, jev = MagicMock(), MagicMock() if backend == "jev" else None
    answer = dict(
        aligned=False,
        risk="medium",
        decision="escalate",
        reasoning="Inspection restricted or scope incomplete",
    )
    llm.generate.return_value = json.dumps(answer)
    if jev:
        jev.evaluate_tool_call.return_value = EvaluationResult(**answer)
    value = Evaluator(
        llm=llm, jev=jev, session_store=sessions, audit_store=audit
    ).evaluate(
        user_id="u",
        session_id=session_id,
        agent_id=None,
        tool="skill_view_raw",
        args={"name": "example", "path": "/opt/skills/example/SKILL.md"},
    )
    assert value["decision"] == "escalate"
    assert value["path"] == "llm"
    evidence = audit.get_by_call_id(value["call_id"], user_id="u")["intent_evidence"]
    if source == "message":
        assert evidence["sources"][0]["text"] == restriction
    elif source == "parent":
        assert evidence["parent"]["sources"][0]["text"] == restriction
    elif source == "omitted":
        assert evidence["complete"] is False


def test_raw_read_does_not_reuse_old_approval_without_current_scope_review(stores):
    sessions, audit = stores
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            aligned=False,
            risk="medium",
            decision="escalate",
            reasoning="Current restriction",
        )
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    call = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="skill_view_raw",
        args={"name": "example", "path": "/opt/skills/example/SKILL.md"},
    )
    first = evaluator.evaluate(**call)
    assert first["decision"] == "escalate"
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    value = evaluator.evaluate(**call)
    assert value["decision"] == "escalate"
    assert value["path"] == "llm"
