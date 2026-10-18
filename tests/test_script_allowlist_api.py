"""Exercise script fast approval through auth, policy, evaluation and audit."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from tests.test_agent_credentials import AGENT, POLICY, create, evaluate
from tests.test_agent_credentials import client as client  # noqa: F401

SCRIPT = "/home/hermes/.hermes/skills/research/grounded-citations/scripts/sources.py"


@pytest.fixture
def script_client(monkeypatch, request):
    monkeypatch.setitem(POLICY, "allow_scripts", [SCRIPT])
    return request.getfixturevalue("client")


def test_script_reset_fast_approves_without_llm_and_is_audited(script_client):
    create(script_client, details={"working_directory": "/home/hermes/.hermes"})
    result = evaluate(
        script_client, command=f"python {SCRIPT} --ledger /tmp/ledger.json reset"
    )
    assert result["decision"] == "approve"
    assert result["path"] == "fast"
    audit = script_client.get(
        f"/api/v1/audit/{result['call_id']}", headers=AGENT
    ).json()
    assert audit["decision"] == "approve"
    assert audit["evaluation_path"] == "fast"
    assert SCRIPT in audit["reasoning"]
    assert "read-only" not in audit["reasoning"].lower()


@pytest.mark.parametrize("suffix", [" && printf extra", " > /tmp/output", ' "$(id)"'])
def test_script_compound_still_reaches_llm(script_client, suffix):
    create(script_client)
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": True,
                "risk": "low",
                "decision": "approve",
                "reasoning": "Reviewed",
            }
        ),
    ):
        result = evaluate(script_client, command=f"python {SCRIPT} list{suffix}")
    assert result["path"] == "llm"


def test_agent_cannot_grant_itself_script_allowance(client):
    create(client, policy={"allow_scripts": [SCRIPT]})
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "decision": "deny",
                "reasoning": "No script allowance",
            }
        ),
    ):
        result = evaluate(client, command=f"python {SCRIPT} list")
    assert result["decision"] == "deny"
    assert result["path"] == "llm"


def test_script_allowance_does_not_override_denial_or_session_stop(script_client):
    create(script_client)
    denied = evaluate(
        script_client, command=f"python {SCRIPT} add https://example.test/sudo"
    )
    assert denied["decision"] == "deny"
    assert denied["path"] == "critical"
    from tests.test_agent_credentials import ADMIN

    script_client.patch(
        "/api/v1/session/s/status", headers=ADMIN, json={"status": "suspended"}
    ).raise_for_status()
    stopped = evaluate(script_client, command=f"python {SCRIPT} list")
    assert stopped["decision"] == "deny"


@pytest.mark.parametrize("cwd_source", ["session", "context", "executor", "tool"])
def test_ambiguous_cwd_cannot_bypass_script_path_denials(
    monkeypatch, request, cwd_source
):
    monkeypatch.setitem(POLICY, "deny_paths", ["/tmp/blocked.json"])
    client = request.getfixturevalue("script_client")
    details = {"working_directory": "//tmp"} if cwd_source == "session" else {}
    create(client, details=details)
    args = {"command": f"python {SCRIPT} --ledger blocked.json reset"}
    context = {}
    if cwd_source == "context":
        context["working_directory"] = "//tmp"
    elif cwd_source == "executor":
        context["executor_environment"] = {"cwd": "//tmp"}
    elif cwd_source == "tool":
        args["workdir"] = "//tmp"
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": True,
                "risk": "low",
                "decision": "approve",
                "reasoning": "Reviewed ambiguous path",
            }
        ),
    ):
        result = evaluate(client, args=args, context=context)
    assert result["path"] == "llm"
