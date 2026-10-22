"""Approval callbacks must bind cached paths to the evaluated invocation."""

import json
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig
from intaris.db import Database
from intaris.evaluator import Evaluator
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "paths.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(
        session_id="s",
        user_id="u",
        intention="Inspect project files",
        details={"working_directory": "/work/project"},
    )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(aligned=False, risk="high", decision="escalate", reasoning="Review")
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    yield sessions, audit, evaluator
    db.close()


def read(evaluator, path, *, tool="read", context=None, workdir=None):
    args = {"path": path} if tool == "read" else {"command": f"cat {path}"}
    if workdir is not None:
        args["workdir"] = workdir
    return evaluator.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool=tool,
        args=args,
        context=context,
    )


@pytest.mark.parametrize("tool", ["read", "terminal"])
@pytest.mark.parametrize("source", ["working_directory", "executor_environment"])
def test_callback_uses_invocation_directory_and_preserves_safe_reuse(
    stores, tool, source
):
    _, audit, evaluator = stores
    context = (
        {"working_directory": "/sandbox/project"}
        if source == "working_directory"
        else {"executor_environment": {"cwd": "/sandbox/project"}}
    )
    # Client attempts to replace the reserved snapshot cannot choose the cache scope.
    context["__intaris_evaluation_directory"] = "/work/project"
    pending = read(evaluator, "../private/a", tool=tool, context=context)
    assert pending["decision"] == "escalate"
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    assert (
        approved["evaluation_context"]["__intaris_evaluation_directory"]
        == "/sandbox/project"
    )
    evaluator.learn_from_approved_escalation(approved)

    wrong = read(evaluator, "/work/private/b", tool=tool)
    assert wrong["decision"] == "escalate"
    assert wrong["path"] == "llm"
    sibling = read(evaluator, "/sandbox/private/b", tool=tool)
    assert sibling["decision"] == "approve"
    assert sibling["path"] == "fast"
    assert read(evaluator, "/sandbox/other/b", tool=tool)["decision"] == "escalate"


@pytest.mark.parametrize("workdir", ["project", "/sandbox/project"])
def test_shell_workdir_is_already_included_in_snapshot(stores, workdir):
    _, audit, evaluator = stores
    pending = read(
        evaluator,
        "../private/a",
        tool="terminal",
        workdir=workdir,
        context={"executor_environment": {"cwd": "/sandbox"}},
    )
    assert pending["decision"] == "escalate"
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    assert (
        approved["evaluation_context"]["__intaris_evaluation_directory"]
        == "/sandbox/project"
    )
    evaluator.learn_from_approved_escalation(approved)
    assert read(evaluator, "/sandbox/private/b")["decision"] == "approve"
    assert read(evaluator, "/sandbox/project/private/b")["decision"] == "escalate"
    assert read(evaluator, "/work/private/b")["decision"] == "escalate"


@pytest.mark.parametrize("tool", ["read", "terminal"])
def test_session_default_is_still_reusable_when_recorded(stores, tool):
    _, audit, evaluator = stores
    pending = read(evaluator, "../private/a", tool=tool)
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    assert (
        approved["evaluation_context"]["__intaris_evaluation_directory"]
        == "/work/project"
    )
    evaluator.learn_from_approved_escalation(approved)
    result = read(evaluator, "/work/private/b", tool=tool)
    assert result["decision"] == "approve"
    assert result["path"] == "fast"


def test_invocation_snapshot_does_not_require_session_default(stores):
    sessions, audit, evaluator = stores
    sessions.update_session("s", user_id="u", details={})
    pending = read(
        evaluator, "../private/a", context={"working_directory": "/sandbox/project"}
    )
    assert pending["decision"] == "escalate"
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    evaluator.learn_from_approved_escalation(approved)
    result = read(
        evaluator, "../private/b", context={"working_directory": "/sandbox/project"}
    )
    assert result["decision"] == "approve"
    assert result["path"] == "fast"


@pytest.mark.parametrize(
    "context",
    [
        None,
        {},
        [],
        "legacy",
        {"working_directory": "/work/project"},
        {"__intaris_evaluation_directory": None},
        {"__intaris_evaluation_directory": ""},
        {"__intaris_evaluation_directory": "relative"},
        {"__intaris_evaluation_directory": 1},
        {"__intaris_evaluation_directory": ["/work/project"]},
    ],
)
def test_missing_or_invalid_snapshot_cannot_seed_cache(stores, context):
    _, audit, evaluator = stores
    pending = read(evaluator, "../private/a")
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    approved["evaluation_context"] = context
    evaluator.learn_from_approved_escalation(approved)
    assert not evaluator._approved_paths
    result = read(evaluator, "/work/private/b")
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"


def test_unknown_executor_directory_does_not_fall_back_to_session(stores):
    _, audit, evaluator = stores
    pending = evaluator.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"path": "/outside/a"},
        context={"executor_environment": {}},
        tool_preferences={"read": "escalate"},
    )
    assert pending["decision"] == "escalate"
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    assert approved["evaluation_context"]["__intaris_evaluation_directory"] is None
    evaluator.learn_from_approved_escalation(approved)
    assert not evaluator._approved_paths
    assert read(evaluator, "/outside/b")["decision"] == "escalate"
