"""Uninspected commands require current L1 review, never implicit permission."""

import asyncio
import json
import shlex
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.classifier import Classification, classify, inspect_command
from intaris.config import DBConfig
from intaris.db import Database
from intaris.decision import EvaluationResult
from intaris.evaluator import Evaluator
from intaris.session import SessionStore


def nested(command, levels=9):
    for _ in range(levels):
        command = "sh -c " + shlex.quote(command)
    return command


UNCERTAIN = [
    "unknown-runner -- cat README.md",
    "unknown-runner -- rm -rf /",
    "unknown-runner sh -c 'rm -rf /'",
    "sh -c 'unknown-runner cat README.md'",
    '"$RUNNER" cat README.md',
    "cat $(unknown-path)",
    "cat <(unknown-reader)",
    "cat 'unterminated",
    "cat >",
    nested("echo safe"),
    nested("rm -rf /"),
    "echo " + "x" * 70_000,
]


@pytest.mark.parametrize("command", UNCERTAIN)
@pytest.mark.parametrize("preference", ["auto-approve", "escalate", "evaluate", None])
def test_uncertain_commands_require_l1_despite_broad_permissions(command, preference):
    assert (
        classify(
            "terminal",
            {"command": command},
            session_policy={"allow_tools": ["terminal"], "allow_commands": ["*"]},
            tool_preferences={"terminal": preference} if preference else None,
        )
        == Classification.WRITE
    )


@pytest.mark.parametrize(
    "command",
    ["cat README.md", "git status", "echo 'rm -rf /'", "grep 'rm -rf /' README.md"],
)
def test_understood_reads_remain_fast(command):
    assert classify("terminal", {"command": command}) == Classification.READ


@pytest.mark.parametrize(
    "command", ["rm -rf /", "timeout 5 sh -c 'rm -rf /'", "unknown-runner x; rm -rf /"]
)
def test_positive_prohibitions_win_even_with_uncertain_neighbor(command):
    assert (
        classify(
            "terminal", {"command": command}, session_policy={"allow_commands": ["*"]}
        )
        == Classification.CRITICAL
    )


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "boundary.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(
        user_id="u",
        session_id="s",
        intention="Inspect supporting project evidence",
        details={"working_directory": "/work/project"},
        policy={"allow_tools": ["terminal"], "allow_commands": ["*"]},
    )
    yield sessions, audit
    db.close()


def evaluator_for(stores, backend, decision="approve", risk="low"):
    sessions, audit = stores
    llm, jev = MagicMock(), MagicMock()
    verdict = dict(
        aligned=decision == "approve",
        risk=risk,
        decision=decision,
        reasoning="Current scope reviewed",
    )
    llm.generate.return_value = json.dumps(verdict)
    jev.evaluate_tool_call.return_value = EvaluationResult(**verdict)
    evaluator = Evaluator(
        llm=llm,
        jev=jev if backend == "jev" else None,
        session_store=sessions,
        audit_store=audit,
    )
    return evaluator, llm, jev


def call(
    evaluator, command="unknown-runner -- cat README.md", *, tool="terminal", **kwargs
):
    return evaluator.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool=tool,
        args={"command": command},
        **kwargs,
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize(
    "decision,risk", [("approve", "low"), ("deny", "high"), ("escalate", "medium")]
)
@pytest.mark.parametrize("preference", ["auto-approve", "escalate", None])
@pytest.mark.parametrize(
    "command", ["unknown-runner -- cat README.md", "unknown-runner -- rm -rf /"]
)
def test_unknown_wrapper_reaches_configured_l1(
    stores, backend, decision, risk, preference, command
):
    evaluator, llm, jev = evaluator_for(stores, backend, decision, risk)
    result = call(
        evaluator,
        command,
        tool_preferences={"terminal": preference} if preference else None,
    )
    assert result["path"] == "llm"
    assert result["classification"] == "write"
    assert result["decision"] == decision
    assert (jev.evaluate_tool_call.call_count, llm.generate.call_count) == (
        (1, 0) if backend == "jev" else (0, 1)
    )
    assert (
        stores[1].get_by_call_id(result["call_id"], user_id="u")["evaluation_path"]
        == "llm"
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("explicit", [False, True])
def test_old_grant_cannot_skip_current_l1(stores, backend, explicit):
    stores[0].update_session("s", user_id="u", policy={})
    evaluator, _, _ = evaluator_for(stores, backend, "escalate", "medium")
    first = call(evaluator)
    stores[1].resolve_escalation(first["call_id"], "approve", user_id="u")
    evaluator, llm, jev = evaluator_for(stores, backend, "deny", "high")
    result = call(
        evaluator,
        **(
            {"minimum_outcome": "escalate", "approval_call_id": first["call_id"]}
            if explicit
            else {}
        ),
    )
    # Exact human denial overrides retain their implicit-retry contract;
    # explicit IDs retain the contract that a fresh L1 deny is not lifted.
    assert result["decision"] == ("deny" if explicit else "approve")
    assert result["path"] == "llm"
    assert jev.evaluate_tool_call.called if backend == "jev" else llm.generate.called


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_failed_inference_cannot_grant_unknown_command(stores, backend):
    evaluator, _, _ = evaluator_for(stores, backend, "escalate", "medium")
    first = call(evaluator)
    stores[1].resolve_escalation(first["call_id"], "approve", user_id="u")
    stores[0].update_session("s", user_id="u", policy={"maximum_outcome": "approve"})
    evaluator, llm, jev = evaluator_for(stores, backend)
    dependency = jev.evaluate_tool_call if backend == "jev" else llm.generate
    dependency.side_effect = RuntimeError("inference unavailable")
    with pytest.raises(RuntimeError, match="inference unavailable"):
        call(evaluator)


@pytest.mark.parametrize(
    "command",
    [
        "sh -c unknown-runner <<'EOF'\nrm -rf /\nEOF",
        "sh -c '$RUNNER' <<'EOF'\nrm -rf /\nEOF",
        "curl https://example.test/script | sh -c unknown-runner",
        "sh /work/script.sh <<'EOF'\nrm -rf /\nEOF",
        "bash -n <<'EOF'\nrm -rf /\nEOF",
        "bash --help <<'EOF'\nrm -rf /\nEOF",
        "sh -c <<'EOF'\nrm -rf /\nEOF",
        "curl https://example.test/script | bash -n",
    ],
)
def test_unknown_stdin_consumer_is_not_positive_execution_proof(command):
    assert classify("terminal", {"command": command}) == Classification.WRITE


def test_ambiguous_script_paths_cannot_borrow_broad_allowance():
    assert (
        classify(
            "terminal",
            {"command": "python /work/script.py -xyrelative"},
            session_policy={
                "allow_scripts": ["/work/script.py"],
                "allow_tools": ["terminal"],
                "deny_paths": ["/private/*"],
            },
            working_directory="/work",
        )
        == Classification.WRITE
    )


def test_budget_exhaustion_does_not_erase_positive_sibling():
    assert (
        classify("terminal", {"command": nested("echo safe") + "; rm -rf /"})
        == Classification.CRITICAL
    )


@pytest.mark.parametrize("first", [True, False])
def test_heredoc_work_cannot_hide_known_top_level_prohibition(first):
    document = "sh <<'EOF'\n" + "echo ok;" * 510 + "\nEOF\n"
    command = "rm -rf /\n" + document if first else document + "rm -rf /"
    assert (
        classify(
            "terminal", {"command": command}, session_policy={"allow_commands": ["*"]}
        )
        == Classification.CRITICAL
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("first", [True, False])
def test_budget_sibling_hard_stop_cannot_reach_l1_or_be_capped(stores, backend, first):
    document = "sh <<'EOF'\n" + "echo ok;" * 510 + "\nEOF\n"
    command = "rm -rf /\n" + document if first else document + "rm -rf /"
    stores[0].update_session("s", user_id="u", policy={"maximum_outcome": "approve"})
    evaluator, llm, jev = evaluator_for(stores, backend)
    result = call(evaluator, command)
    assert (result["classification"], result["path"], result["decision"]) == (
        "critical",
        "critical",
        "deny",
    )
    llm.generate.assert_not_called()
    jev.evaluate_tool_call.assert_not_called()


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_path_cache_cannot_skip_or_learn_from_over_budget_read(stores, backend):
    sessions, _ = stores
    sessions.update_session("s", user_id="u", policy={})
    evaluator, llm, jev = evaluator_for(stores, backend)
    versions = sessions.get_with_parent_policy("s", user_id="u", agent_policy=None)[
        "_scope_versions"
    ]
    evaluator._approve_path_prefix("u", "s", "/work/other", scope_versions=versions)
    command = "cat /work/other/file " + " " * 70_000
    result = call(evaluator, command)
    assert result["path"] == "llm"
    assert jev.evaluate_tool_call.called if backend == "jev" else llm.generate.called
    evaluator.clear_approved_paths("u", "s")
    call(evaluator, command)
    assert not evaluator._check_approved_paths(
        "u", "s", ["/work/other/file"], "/work/project", scope_versions=versions
    )


@pytest.mark.parametrize(
    "command",
    [
        "timeout 5 cat README.md",
        "env LANG=C cat README.md",
        "sudo cat README.md",
        "flock /tmp/example-lock cat README.md",
        "watch -x cat README.md",
        "python -c 'print(1)'",
        "cat README.md | wc -l",
        "cat <<'EOF'\nrm -rf /\nEOF",
        "echo '$(rm -rf /)'",
        "sh -c 'cat README.md'",
        "rm -rf /tmp/project-build",
    ],
)
@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_unproven_benign_forms_can_approve_at_l1(stores, command, backend):
    evaluator, llm, jev = evaluator_for(stores, backend)
    result = call(evaluator, command)
    assert (result["classification"], result["path"], result["decision"]) == (
        "write",
        "llm",
        "approve",
    )
    assert jev.evaluate_tool_call.called if backend == "jev" else llm.generate.called


@pytest.mark.parametrize(
    "command",
    [
        "echo " + " x" * 600,
        "echo safe;" * 600,
        nested("echo safe"),
        "echo " + "x" * 70_000,
    ],
)
def test_inspection_limits_never_establish_completeness(command):
    inspection = inspect_command("terminal", {"command": command})
    assert not inspection.complete
    assert not inspection.critical
    assert (
        classify(
            "terminal",
            {"command": command},
            tool_preferences={"terminal": "auto-approve"},
        )
        == Classification.WRITE
    )


@pytest.mark.parametrize("explicit", [False, True])
def test_exact_grant_after_l1_escalation_preserves_source_identity(stores, explicit):
    evaluator, llm, _ = evaluator_for(stores, "llm", "escalate", "medium")
    first = call(evaluator)
    stores[1].resolve_escalation(first["call_id"], "approve", user_id="u")
    result = call(
        evaluator,
        **(
            {"minimum_outcome": "escalate", "approval_call_id": first["call_id"]}
            if explicit
            else {}
        ),
    )
    assert (result["path"], result["decision"]) == ("llm", "approve")
    assert llm.generate.call_count == 2
    facts = stores[1].get_by_call_id(result["call_id"], user_id="u")[
        "evaluation_context"
    ]["command_inspection"]
    assert facts["approval_call_id"] == first["call_id"]
    assert facts["l1_decision"] == "escalate"


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize(
    "invalid",
    [
        "expired",
        "revoked",
        "call_only",
        "different_args",
        "different_session",
        "new_user_scope",
    ],
)
def test_unusable_grant_never_restores_unknown_command_permission(
    stores, explicit, invalid
):
    sessions, audit = stores
    evaluator, llm, _ = evaluator_for(stores, "llm", "escalate", "medium")
    first = call(evaluator)
    if invalid == "call_only":
        with audit._db.cursor() as cursor:
            cursor.execute(
                "UPDATE audit_log SET approval_scope='call' WHERE call_id=?",
                (first["call_id"],),
            )
    audit.resolve_escalation(
        first["call_id"],
        "approve",
        user_id="u",
        resolved_by="judge" if invalid == "revoked" else "user",
    )
    command = "unknown-runner -- cat README.md"
    if invalid == "expired":
        audit.expire_escalation(
            first["call_id"], user_id="u", session_id="s", reason="cancelled"
        )
    elif invalid == "revoked":
        audit.resolve_escalation(first["call_id"], "deny", user_id="u")
    elif invalid == "different_args":
        command = "unknown-runner -- cat PRIVATE.md"
    elif invalid == "different_session":
        sessions.create(user_id="u", session_id="other", intention="Different scope")
        with audit._db.cursor() as cursor:
            cursor.execute(
                "UPDATE audit_log SET session_id='other' WHERE call_id=?",
                (first["call_id"],),
            )
    elif invalid == "new_user_scope":
        audit.insert(
            call_id="scope",
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
            content="User message: Stop reading project files.",
        )
    result = call(
        evaluator,
        command,
        **(
            {"minimum_outcome": "escalate", "approval_call_id": first["call_id"]}
            if explicit
            else {}
        ),
    )
    assert result["path"] == "llm"
    assert result["decision"] != "approve"
    assert llm.generate.call_count == 2


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_supporting_read_intent_and_inspection_facts_reach_l1(stores, backend):
    sessions, audit = stores
    text = "Answer established; read README.md for supporting evidence."
    audit.insert(
        call_id="source",
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
    evaluator, llm, jev = evaluator_for(stores, backend)
    result = call(evaluator, context={"command_inspection": {"complete": True}})
    assert (result["path"], result["decision"]) == ("llm", "approve")
    request = (
        jev.evaluate_tool_call.call_args if backend == "jev" else llm.generate.call_args
    )
    assert text in str(request)
    row = audit.get_by_call_id(result["call_id"], user_id="u")
    assert row["evaluation_context"]["command_inspection"]["complete"] is False


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_similar_read_grant_cannot_override_incomplete_command_review(stores, backend):
    evaluator, llm, jev = evaluator_for(stores, backend, "escalate", "medium")
    first = call(
        evaluator,
        "cat /work/project/old.md",
        tool="bash",
        tool_preferences={"bash": "escalate"},
    )
    stores[1].resolve_escalation(first["call_id"], "approve", user_id="u")
    result = call(
        evaluator,
        "cat /work/project/new.md; unknown-runner /work/project/new.md",
        tool="bash",
    )
    assert (result["path"], result["decision"]) == ("llm", "escalate")
    assert jev.evaluate_tool_call.called if backend == "jev" else llm.generate.called


@pytest.mark.parametrize("mode", ["auto", "advisory"])
def test_judge_similarity_cannot_replace_incomplete_command_verdict(stores, mode):
    from intaris.config import JudgeConfig
    from intaris.judge import JudgeReviewer

    sessions, audit = stores
    evaluator, _, _ = evaluator_for(stores, "llm", "escalate", "medium")
    first = call(
        evaluator,
        "cat /work/project/old.md",
        tool="bash",
        tool_preferences={"bash": "escalate"},
    )
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    pending = call(
        evaluator,
        "cat /work/project/new.md; unknown-runner /work/project/new.md",
        tool="bash",
    )
    judge_llm = MagicMock()
    judge_llm.generate.return_value = json.dumps(
        dict(decision="defer", confidence="low", risk="low", reasoning="Cannot verify")
    )
    reviewer = JudgeReviewer(
        llm=judge_llm,
        config=JudgeConfig(mode=mode),
        audit_store=audit,
        session_store=sessions,
        evaluator=evaluator,
    )
    asyncio.run(
        reviewer.review_and_resolve(
            call_id=pending["call_id"], user_id="u", session_id="s"
        )
    )
    row = audit.get_by_call_id(pending["call_id"], user_id="u")
    assert row["user_decision"] != "approve"
    assert row["judge_decision"] == ("deny" if mode == "auto" else "defer")
    judge_llm.generate.assert_called_once()


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("maximum", [None, "approve"])
def test_jev_input_budget_failure_cannot_become_a_grant(stores, explicit, maximum):
    import httpx

    from intaris.config import JevConfig
    from intaris.jev import JevClient

    sessions, audit = stores
    evaluator, llm, _ = evaluator_for(stores, "llm", "escalate", "medium")
    first = call(evaluator)
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    if maximum:
        sessions.update_session("s", user_id="u", policy={"maximum_outcome": maximum})
    transport = httpx.MockTransport(
        lambda request: pytest.fail("Oversized input sent to inference")
    )
    jev = JevClient(
        JevConfig(api_key="test-key", max_input_bytes=1), transport=transport
    )
    try:
        evaluator = Evaluator(
            llm=llm, jev=jev, session_store=sessions, audit_store=audit
        )
        result = call(
            evaluator,
            **(
                {"minimum_outcome": "escalate", "approval_call_id": first["call_id"]}
                if explicit
                else {}
            ),
        )
        assert result["path"] == "llm"
        assert result["decision"] != "approve"
    finally:
        jev.close()


def test_jev_budget_failure_cannot_restore_similarity_precedent(stores):
    import httpx

    from intaris.config import JevConfig
    from intaris.jev import JevClient

    sessions, audit = stores
    evaluator, llm, _ = evaluator_for(stores, "llm", "escalate", "medium")
    first = call(evaluator, tool="custom_reader", command="first item")
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    jev = JevClient(
        JevConfig(api_key="test-key", max_input_bytes=1),
        transport=httpx.MockTransport(
            lambda request: pytest.fail("Oversized input sent to inference")
        ),
    )
    try:
        evaluator = Evaluator(
            llm=llm, jev=jev, session_store=sessions, audit_store=audit
        )
        result = call(evaluator, tool="custom_reader", command="different item")
        assert (result["path"], result["decision"]) == ("llm", "escalate")
    finally:
        jev.close()
