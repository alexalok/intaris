"""Exact Python script allowances must not authorize a second shell program."""

from __future__ import annotations

import json

import pytest

from intaris.api.schemas import IntentionRequest, SessionPolicy, SessionUpdateRequest
from intaris.classifier import Classification, classify
from intaris.config import _parse_agent_policy

SCRIPT = "/home/hermes/.hermes/skills/research/grounded-citations/scripts/sources.py"
POLICY = {"allow_scripts": [SCRIPT]}


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize(
    "command",
    [
        f"python {SCRIPT} --ledger /tmp/citations.json reset",
        f"python3 {SCRIPT} list --json",
        f"python '{SCRIPT}' render --replace-in '/tmp/my draft.md'",
        f'python3 "{SCRIPT}" add "https://example.test/?a=1&b=2"',
        f"python {SCRIPT} quote 1 --text 'literal $(id); `id` | <> * ? [x]' --from /tmp/evidence",
        f'python {SCRIPT} add https://example.test --title "A; B & C (2026)"',
        f"python {SCRIPT} add https://example.test --title escaped\\;text",
        f"python\t{SCRIPT}\tlist",
        f"python {SCRIPT}",
    ],
)
def test_exact_script_with_literal_arguments_is_allowed(tool, command):
    assert (
        classify(tool, {"command": command}, session_policy=POLICY)
        == Classification.READ
    )


@pytest.mark.parametrize(
    "command",
    [
        f"python {SCRIPT}.other list",
        "python /tmp/sources.py list",
        "python sources.py list",
        f"python {SCRIPT}/../other.py list",
        f"python -c 'print(1)' {SCRIPT}",
        f"python -m runpy {SCRIPT}",
        f"python -i {SCRIPT}",
        f"python -I {SCRIPT}",
        f"/tmp/python3 {SCRIPT} list",
        f"env python {SCRIPT} list",
        f"PYTHONPATH=/tmp python {SCRIPT} list",
        f"sh -c 'python {SCRIPT} list'",
        f"python {SCRIPT} list; printf extra",
        f"python {SCRIPT} list && printf extra",
        f"python {SCRIPT} list || printf extra",
        f"python {SCRIPT} list | cat",
        f"python {SCRIPT} list &",
        f"python {SCRIPT} list\nprintf extra",
        f"python {SCRIPT} list\rprintf extra",
        f"python {SCRIPT} list\x00",
        f"python {SCRIPT} list > /tmp/output",
        f"python {SCRIPT} list 2>> /tmp/output",
        f"python {SCRIPT} ingest < /tmp/input",
        f"python {SCRIPT} ingest <(printf data)",
        f"python {SCRIPT} add $(printf url)",
        f"python {SCRIPT} add `printf url`",
        f'python {SCRIPT} add "$(printf url)"',
        f'python {SCRIPT} add "`printf url`"',
        f"python {SCRIPT} --ledger $LEDGER reset",
        f"python {SCRIPT} --ledger ~/ledger.json reset",
        f"python {SCRIPT} --ledger /tmp/*.json reset",
        f"python {SCRIPT} --ledger /tmp/{{a,b}}.json reset",
        f"python {SCRIPT} list # comment",
        f"python {SCRIPT} list 'unterminated",
        f"python {SCRIPT} list\\\nprintf extra",
    ],
)
def test_other_execution_or_shell_syntax_is_not_allowed(command):
    assert (
        classify("terminal", {"command": command}, session_policy=POLICY)
        != Classification.READ
    )


def test_script_allowance_requires_explicit_policy_and_shell_tool():
    args = {"command": f"python {SCRIPT} list"}
    assert classify("terminal", args) == Classification.WRITE
    assert classify("custom_tool", args, session_policy=POLICY) == Classification.WRITE
    assert (
        classify("terminal", args, session_policy={"allow_scripts": ["*/sources.py"]})
        == Classification.WRITE
    )


@pytest.mark.parametrize(
    "extra_policy",
    [
        {"deny_tools": ["terminal"]},
        {"deny_commands": ["*sources.py*"]},
        {"deny_paths": [SCRIPT]},
        {"deny_paths": ["/tmp/blocked.json"]},
    ],
)
@pytest.mark.parametrize("working_directory", [None, "/home/hermes/.hermes"])
def test_explicit_denials_override_script_allowance(extra_policy, working_directory):
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} --ledger /tmp/blocked.json reset"},
            session_policy={**POLICY, **extra_policy},
            working_directory=working_directory,
        )
        == Classification.CRITICAL
    )


@pytest.mark.parametrize(
    ("preference", "expected"),
    [("deny", Classification.CRITICAL), ("escalate", Classification.ESCALATE)],
)
def test_tool_preference_override_is_preserved(preference, expected):
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} list"},
            session_policy=POLICY,
            tool_preferences={"terminal": preference},
        )
        == expected
    )


@pytest.mark.parametrize("working_directory", [None, "/home/hermes/.hermes"])
def test_quoted_delimiter_does_not_hide_denied_script(working_directory):
    assert (
        classify(
            "terminal",
            {"command": f"python '{SCRIPT}' add 'https://example.test/?a=1&b=2'"},
            session_policy={**POLICY, "deny_paths": [SCRIPT]},
            working_directory=working_directory,
        )
        == Classification.CRITICAL
    )


@pytest.mark.parametrize(
    "ledger_arg",
    [
        '--ledger="/tmp/blocked.json"',
        "--ledger blocked.json",
        "--ledger=./blocked.json",
    ],
)
def test_literal_script_argument_paths_cannot_bypass_denials(ledger_arg):
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} {ledger_arg} reset"},
            session_policy={**POLICY, "deny_paths": ["/tmp/blocked.json"]},
            working_directory="/tmp",
        )
        == Classification.CRITICAL
    )


def test_relative_script_arguments_with_path_denials_need_known_cwd():
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} --ledger blocked.json reset"},
            session_policy={**POLICY, "deny_paths": ["/tmp/blocked.json"]},
        )
        == Classification.WRITE
    )


@pytest.mark.parametrize(
    ("arguments", "denied"),
    [
        ("-- -blocked.json", "/tmp/-blocked.json"),
        ("-blocked.json", "/tmp/-blocked.json"),
        ("-o/tmp/blocked.json", "/tmp/blocked.json"),
        ("-oblocked.json", "/tmp/blocked.json"),
        ("-o=blocked.json", "/tmp/blocked.json"),
        ("-- --ledger=/tmp/blocked.json", "/tmp/--ledger=/tmp/blocked.json"),
    ],
)
def test_option_shaped_script_paths_cannot_bypass_denials(arguments, denied):
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} {arguments}"},
            session_policy={**POLICY, "deny_paths": [denied]},
            working_directory="/tmp",
        )
        == Classification.CRITICAL
    )


@pytest.mark.parametrize("arguments", ["-vo/tmp/blocked.json", "-vblocked.json"])
def test_ambiguous_short_options_with_path_denials_require_review(arguments):
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} {arguments}"},
            session_policy={**POLICY, "deny_paths": ["/tmp/blocked.json"]},
            working_directory="/tmp",
        )
        != Classification.READ
    )


@pytest.mark.parametrize("arguments", ["-- -vblocked.json", "-vblocked.json"])
def test_option_shaped_literals_remain_allowed_without_path_denials(arguments):
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} {arguments}"},
            session_policy=POLICY,
            working_directory="/tmp",
        )
        == Classification.READ
    )


def test_end_of_options_keeps_unrelated_hyphenated_operand_literal():
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} -- -vblocked.json"},
            session_policy={**POLICY, "deny_paths": ["/tmp/blocked.json"]},
            working_directory="/tmp",
        )
        == Classification.READ
    )


@pytest.mark.parametrize(
    ("ledger", "denied"),
    [
        ("//tmp/blocked.json", "/tmp/blocked.json"),
        ("'~/blocked.json'", "/home/hermes/blocked.json"),
        ('"/tmp/\\$blocked.json"', "/tmp/$blocked.json"),
        ('"/tmp/\\`blocked\\`.json"', "/tmp/`blocked`.json"),
    ],
)
def test_ambiguous_shell_path_spelling_requires_evaluation(ledger, denied):
    assert (
        classify(
            "terminal",
            {"command": f"python {SCRIPT} --ledger {ledger} reset"},
            session_policy={**POLICY, "deny_paths": [denied]},
            working_directory="/tmp",
        )
        != Classification.READ
    )


def test_policy_survives_api_and_server_config_validation(monkeypatch):
    create = IntentionRequest(session_id="s", intention="Research", policy=POLICY)
    update = SessionUpdateRequest(policy=POLICY)
    assert create.policy == update.policy == POLICY
    monkeypatch.setenv("INTARIS_AGENT_POLICY", json.dumps(POLICY))
    assert _parse_agent_policy() == POLICY


@pytest.mark.parametrize(
    "path",
    [
        "",
        "sources.py",
        "~/sources.py",
        "/tmp/*.py",
        "/tmp/[ab].py",
        "/tmp/../sources.py",
        "/tmp/script.py\n",
    ],
)
def test_script_policy_rejects_nonliteral_or_nonabsolute_paths(path):
    with pytest.raises(ValueError):
        SessionPolicy(allow_scripts=[path])
