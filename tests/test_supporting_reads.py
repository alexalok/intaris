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
def test_skill_read_approves_without_model_review(stores, backend, args):
    sessions, audit = stores
    llm = MagicMock()
    deferred = dict(
        aligned=False,
        risk="medium",
        decision="escalate",
        reasoning="Uncertain relevance.",
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
    assert result["path"] == "fast"
    assert result["classification"] == "read"
    assert result["risk"] == "low"
    assert audit.get_by_call_id(result["call_id"], user_id="u")["decision"] == "approve"
    llm.generate.assert_not_called()
    if jev:
        jev.evaluate_tool_call.assert_not_called()


@pytest.mark.parametrize("working_directory", [None, "/workspace/project"])
def test_shared_skill_library_is_not_a_project_boundary_violation(working_directory):
    assert (
        classify(
            "skill_view_raw",
            {"name": "dangerous-example", "path": "/opt/skills/example/SKILL.md"},
            working_directory=working_directory,
        )
        == Classification.READ
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
    execute = evaluator.evaluate(
        **common,
        tool="terminal",
        args={"command": "python /opt/skills/credential-exfiltration/run.py"},
    )
    assert execute["decision"] == "deny"
    assert execute["path"] == "llm"
    (jev.evaluate_tool_call if jev else llm.generate).assert_called_once()
    critical = evaluator.evaluate(
        **common, tool="terminal", args={"command": "rm -rf /"}
    )
    assert critical["decision"] == "deny"
    assert critical["path"] == "critical"
    (jev.evaluate_tool_call if jev else llm.generate).assert_called_once()


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
