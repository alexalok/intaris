"""Restricted credential contract, exercised through the real ASGI application."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

POLICY = {
    "allow_tools": ["read_file", "search_files", "read_terminal"],
    "deny_commands": ["*sudo*"],
    "deny_paths": [],
    "maximum_outcome": "deny",
}
AGENT = {"Authorization": "Bearer agent-secret", "X-Agent-Id": "hermes"}
ADMIN = {"Authorization": "Bearer admin-secret", "X-Agent-Id": "operator"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    import intaris.server as srv

    for name in (
        "INTARIS_API_KEY",
        "INTARIS_JWT_PUBLIC_KEY",
        "INTARIS_JWKS_URL",
        "WEBHOOK_URL",
        "WEBHOOK_SECRET",
        "MCP_CONFIG_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        "LLM_API_KEY": "test",
        "DB_PATH": str(tmp_path / "test.db"),
        "DATA_DIR": str(tmp_path),
        "METRICS_ENABLED": "false",
        "ANALYSIS_ENABLED": "false",
        "EVENT_STORE_ENABLED": "true",
        "INTARIS_SEARCH_ENABLED": "false",
        "RATE_LIMIT": "0",
        "JUDGE_MODE": "advisory",
        "INTARIS_API_KEYS": json.dumps({"admin-secret": "owner"}),
        "INTARIS_AGENT_API_KEYS": json.dumps({"agent-secret": "owner"}),
        "INTARIS_AGENT_POLICY": json.dumps(POLICY),
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("_config", "_db", "_evaluator", "_jev_client"):
        monkeypatch.setattr(srv, name, None)
    # Only provider inference is mocked; routing, auth, DB, classifier and
    # human decision handling are real.
    with patch(
        "intaris.llm.LLMClient.generate",
        side_effect=AssertionError("unexpected LLM call"),
    ):
        with TestClient(srv.create_app()) as result:
            yield result


def create(client, session="s", headers=None, **extra):
    result = client.post(
        "/api/v1/intention",
        headers=headers or AGENT,
        json={
            "session_id": session,
            "intention": "Inspect repository",
            **extra,
        },
    )
    assert result.status_code == 200, result.text


def evaluate(client, session="s", command="pwd", **extra):
    result = client.post(
        "/api/v1/evaluate",
        headers=AGENT,
        json={
            "session_id": session,
            "tool": "terminal",
            "args": {"command": command},
            **extra,
        },
    )
    assert result.status_code == 200, result.text
    return result.json()


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "{",
        '{"k":"*"}',
        '{"k":""}',
        '{"k":3}',
        '{" k":"owner"}',
        '{"k":"other*"}',
        '{"k":"owner","k":"other"}',
    ],
)
def test_invalid_agent_key_mapping_fails_closed(monkeypatch, raw):
    from intaris.config import ServerConfig

    monkeypatch.setenv("INTARIS_AGENT_API_KEYS", raw)
    monkeypatch.setenv("INTARIS_AGENT_POLICY", json.dumps(POLICY))
    with pytest.raises(ValueError, match="INTARIS_AGENT_API_KEYS"):
        ServerConfig()


@pytest.mark.parametrize(
    "admin_env,value",
    [
        ("INTARIS_API_KEY", "agent-secret"),
        ("INTARIS_API_KEYS", '{"agent-secret":"owner"}'),
        ("INTARIS_API_KEYS", '{"agent-secret":"*"}'),
    ],
)
def test_overlapping_credentials_rejected(monkeypatch, admin_env, value):
    from intaris.config import ServerConfig

    monkeypatch.setenv("INTARIS_AGENT_API_KEYS", '{"agent-secret":"owner"}')
    monkeypatch.setenv("INTARIS_AGENT_POLICY", json.dumps(POLICY))
    monkeypatch.setenv(admin_env, value)
    with pytest.raises(ValueError, match="overlap"):
        ServerConfig()


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "[]",
        "{",
        '{"deny_command":["sudo*"]}',
        '{"deny_paths":"/etc"}',
        '{"maximum_outcome":"approve"}',
        '{"judge":{"allowed_decisions":["approve"]}}',
        '{"deny_paths":[],"deny_paths":["*"]}',
    ],
)
def test_invalid_agent_policy_rejected(monkeypatch, raw):
    from intaris.config import ServerConfig

    monkeypatch.setenv("INTARIS_AGENT_API_KEYS", '{"agent-secret":"owner"}')
    if raw is None:
        monkeypatch.delenv("INTARIS_AGENT_POLICY", raising=False)
    else:
        monkeypatch.setenv("INTARIS_AGENT_POLICY", raw)
    with pytest.raises(ValueError, match="INTARIS_AGENT_POLICY"):
        ServerConfig()


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/v1/decision"),
        ("POST", "/api/v1/mcp/servers"),
        ("PATCH", "/api/v1/mcp/servers/x"),
        ("DELETE", "/api/v1/mcp/servers/x"),
        ("POST", "/api/v1/mcp/call"),
        ("GET", "/api/v1/mcp/tools"),
        ("POST", "/mcp/"),
        ("POST", "/api/v1/auth/exchange"),
        ("GET", "/api/v1/config"),
        ("POST", "/api/v1/analysis/trigger"),
        ("GET", "/api/v1/action/approve"),
        ("POST", "/api/v1/search/reindex"),
    ],
)
def test_agent_cannot_access_admin_surfaces(client, method, path):
    result = client.request(
        method, path, headers=AGENT, json={"transport": "stdio", "command": "sh"}
    )
    assert result.status_code == 403, result.text


def test_agent_lifecycle_and_admin_approval(client):
    create(client, policy={"maximum_outcome": "approve", "allow_tools": ["terminal"]})
    session = client.get(
        "/api/v1/session/s", headers={**AGENT, "X-User-Id": "intruder"}
    )
    assert session.status_code == 200
    assert session.json()["user_id"] == "owner"
    assert session.json()["policy"] == POLICY
    assert evaluate(client)["path"] == "fast"
    denied = evaluate(
        client,
        command="sudo id",
        minimum_outcome="approve",
        context={"interaction_mode": "none"},
    )
    assert denied["decision"] == "deny"
    assert denied["risk"] == "critical"
    assert denied["path"] == "critical"
    audit = client.get(f"/api/v1/audit/{denied['call_id']}", headers=AGENT).json()
    assert audit["tool"] == "terminal"
    decision = {"call_id": denied["call_id"], "decision": "approve"}
    assert (
        client.post("/api/v1/decision", headers=AGENT, json=decision).status_code == 403
    )
    assert (
        client.post("/api/v1/decision", headers=ADMIN, json=decision).status_code == 200
    )
    assert (
        client.get(f"/api/v1/audit/{denied['call_id']}", headers=AGENT).json()[
            "resolved_by"
        ]
        == "user"
    )
    for path, body in [
        ("/reasoning", {"session_id": "s", "content": "Inspecting code"}),
        ("/checkpoint", {"session_id": "s", "content": "Inspection complete"}),
        ("/session/s/agent-summary", {"summary": "Inspected repository"}),
        ("/session/s/events", [{"type": "tool_result", "data": {"result": "ok"}}]),
    ]:
        result = client.post("/api/v1" + path, headers=AGENT, json=body)
        assert result.status_code == 200, result.text
    result = client.patch(
        "/api/v1/session/s",
        headers=AGENT,
        json={
            "intention": "legacy ignored field",
            "details": {"working_directory": "/tmp/project"},
        },
    )
    assert result.status_code == 200, result.text
    assert result.json()["intention"] == "Inspect repository"
    for status in ("idle", "active", "completed", "active"):
        result = client.patch(
            "/api/v1/session/s/status", headers=AGENT, json={"status": status}
        )
        assert result.status_code == 200, result.text


@pytest.mark.parametrize(
    "body",
    [
        {"policy": {"maximum_outcome": "approve"}},
        {"policy": None},
        {"parent_session_id": None},
        {"alignment_overridden": True},
        {"agent_restricted": False},
        {"judge": {"allowed_decisions": ["approve"]}},
    ],
)
def test_agent_cannot_patch_security_fields(client, body):
    create(client)
    assert (
        client.patch("/api/v1/session/s", headers=AGENT, json=body).status_code == 403
    )


@pytest.mark.parametrize("stop", ["suspended", "terminated"])
@pytest.mark.parametrize("status", ["active", "idle", "completed"])
def test_agent_cannot_clear_admin_stop(client, stop, status):
    create(client)
    client.patch(
        "/api/v1/session/s/status", headers=ADMIN, json={"status": stop}
    ).raise_for_status()
    result = client.patch(
        "/api/v1/session/s/status", headers=AGENT, json={"status": status}
    )
    assert result.status_code == 403, result.text
    assert client.get("/api/v1/session/s", headers=ADMIN).json()["status"] == stop


def test_agent_policy_applies_to_admin_session_and_survives_stored_policy_change(
    client,
):
    create(
        client,
        headers=ADMIN,
        policy={
            "maximum_outcome": "approve",
            "allow_tools": ["terminal"],
            "judge": {"allowed_decisions": ["approve"], "on_uncertain": "approve"},
        },
    )
    assert evaluate(client, command="sudo id")["decision"] == "deny"
    client.patch(
        "/api/v1/session/s",
        headers=ADMIN,
        json={"policy": {"maximum_outcome": "approve"}},
    ).raise_for_status()
    assert evaluate(client, command="sudo whoami")["decision"] == "deny"
    # Agent-origin marker survives new evaluator instances and caller role changes.
    import intaris.server as srv

    srv._evaluator = None
    result = client.post(
        "/api/v1/evaluate",
        headers=ADMIN,
        json={
            "session_id": "s",
            "tool": "terminal",
            "args": {"command": "sudo pwd"},
        },
    )
    assert result.json()["decision"] == "deny", result.text


@pytest.mark.parametrize("carrier", ["authorization", "x-api-key", "cognis_session"])
def test_agent_key_cannot_inherit_admin_cookie(client, carrier):
    from intaris.api.auth import _COOKIE_NAME, create_exchange_session
    from intaris.server import _get_db

    cookie = create_exchange_session(_get_db(), user_id="owner", agent_id=None)
    client.cookies.set(_COOKIE_NAME, cookie)
    headers = {"X-Agent-Id": "hermes"}
    if carrier == "cognis_session":
        client.cookies.set(carrier, "agent-secret")
    else:
        headers[carrier] = (
            "Bearer agent-secret" if carrier == "authorization" else "agent-secret"
        )
    result = client.post(
        "/api/v1/decision",
        headers=headers,
        json={"call_id": "x", "decision": "approve"},
    )
    assert result.status_code == 403, result.text


def test_agent_websocket_rejected(client):
    with client.websocket_connect("/api/v1/stream") as ws:
        ws.send_json({"type": "auth", "token": "agent-secret", "user_id": "owner"})
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 4001


@pytest.mark.parametrize(
    "command,expected",
    [
        ("pwd", "read"),
        ("ls -la", "read"),
        ("git status --short", "read"),
        ("rg -n TODO src", "read"),
        ("head -n 20 README.md", "read"),
        ("sudo id", "critical"),
        ("ls; touch /tmp/file", "write"),
        ("cat /tmp/x > /tmp/y", "write"),
        ("ls\ntouch /tmp/file", "write"),
        ("echo $(touch /tmp/file)", "write"),
        (r"find . -exec touch {} \;", "write"),
        ("git diff --output=/tmp/file", "write"),
        ("rg --pre=sh pattern", "write"),
        ("sort -o /tmp/file /tmp/input", "write"),
        ("awk 'BEGIN {exit 1}'", "write"),
    ],
)
def test_terminal_conservative_shell_classification(command, expected):
    from intaris.classifier import classify

    assert (
        classify("terminal", {"command": command}, session_policy=POLICY).value
        == expected
    )


@pytest.mark.parametrize(
    "method,path", [("GET", "/api/v1/config"), ("POST", "/api/v1/decision")]
)
def test_agent_only_deployment_is_not_no_auth(client, method, path):
    import intaris.server as srv

    srv._config.server.api_keys = {}
    result = client.request(method, path, json={})
    assert result.status_code == 401
    with client.websocket_connect("/api/v1/stream") as ws:
        ws.send_json({"type": "auth", "token": "", "user_id": "owner"})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()


def test_role_cannot_be_overridden_or_leak_between_requests(client):
    create(client)
    spoofed = {**AGENT, "X-User-Id": "other", "X-Agent-Id": "admin", "X-Role": "admin"}
    assert client.post("/api/v1/decision", headers=spoofed, json={}).status_code == 403
    # Admin request still works after a restricted request.
    result = client.patch(
        "/api/v1/session/s",
        headers=ADMIN,
        json={"policy": {"maximum_outcome": "approve"}},
    )
    assert result.status_code == 200
    assert evaluate(client, command="sudo id")["decision"] == "deny"


def test_parent_cannot_weaken_agent_policy(client):
    create(client, "parent", headers=ADMIN, policy={"maximum_outcome": "approve"})
    create(
        client,
        "child",
        parent_session_id="parent",
        policy={"maximum_outcome": "approve"},
    )
    assert evaluate(client, session="child", command="sudo id")["decision"] == "deny"
    client.patch(
        "/api/v1/session/parent/status", headers=ADMIN, json={"status": "suspended"}
    ).raise_for_status()
    assert evaluate(client, session="child")["decision"] == "deny"


def test_agent_policy_survives_missing_config_fail_closed(client):
    create(client)
    import intaris.server as srv

    srv._evaluator._agent_policy = None
    result = client.post(
        "/api/v1/evaluate",
        headers=AGENT,
        json={
            "session_id": "s",
            "tool": "terminal",
            "args": {"command": "sudo id"},
        },
    )
    assert result.status_code >= 400


def test_human_approval_retry_still_works(client):
    create(client)
    denied = evaluate(client, command="sudo id")
    client.post(
        "/api/v1/decision",
        headers=ADMIN,
        json={"call_id": denied["call_id"], "decision": "approve"},
    ).raise_for_status()
    assert evaluate(client, command="sudo id")["decision"] == "approve"


def test_prior_judge_approval_cannot_bypass_mandatory_critical(client):
    from intaris.audit import AuditStore
    from intaris.server import _get_db

    create(client)
    denied = evaluate(client, command="sudo id")
    # Prior judge resolution (e.g. from a less restrictive deployment) is not
    # human approval of the current mandatory deny rule.
    AuditStore(_get_db()).resolve_escalation(
        denied["call_id"], "approve", user_id="owner", resolved_by="judge"
    )
    assert evaluate(client, command="sudo id")["decision"] == "deny"


@pytest.mark.parametrize("bearer", ["bearer", "BEARER"])
def test_agent_bearer_scheme_cannot_inherit_cookie(client, bearer):
    from intaris.api.auth import _COOKIE_NAME, create_exchange_session
    from intaris.server import _get_db

    client.cookies.set(
        _COOKIE_NAME, create_exchange_session(_get_db(), user_id="owner", agent_id=None)
    )
    result = client.post(
        "/api/v1/decision", headers={"Authorization": bearer + " agent-secret"}, json={}
    )
    assert result.status_code == 403


def test_judge_uses_server_policy_for_existing_admin_session(client):
    import intaris.server as srv
    from intaris.decision import Decision

    create(
        client,
        headers=ADMIN,
        policy={"judge": {"allowed_decisions": ["approve"], "on_uncertain": "approve"}},
    )
    # An uncertain advisory judge must defer, despite stored agent overrides.
    with (
        patch.object(
            srv._get_evaluator(),
            "_llm_evaluate",
            return_value=Decision("escalate", "high", "Review write", "llm"),
        ),
        patch(
            "intaris.llm.LLMClient.generate",
            return_value=json.dumps(
                {
                    "decision": "defer",
                    "confidence": "low",
                    "reasoning": "Human review needed",
                    "risk": "high",
                }
            ),
        ),
    ):
        result = evaluate(client, command="touch /tmp/output")
    assert result["decision"] == "escalate", result
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=ADMIN).json()
    assert audit["user_decision"] is None
    assert audit["judge_decision"] == "defer"


@pytest.mark.parametrize("tool", ["bash", "terminal"])
@pytest.mark.parametrize(
    "command",
    [
        "cat README.md",
        "ls -la",
        "pwd",
        "git status --short",
        "git cat-file -p HEAD:README.md",
    ],
)
def test_common_shell_reads_do_not_require_inference(client, tool, command):
    create(client)
    response = client.post(
        "/api/v1/evaluate",
        headers=AGENT,
        json={
            "session_id": "s",
            "tool": tool,
            "args": {"command": command},
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "approve"
    assert response.json()["path"] == "fast"


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize(
    "command", ["ls && pwd", "cat README.md | head", "ls; pwd", "ls & pwd"]
)
def test_compounds_require_evaluation(tool, command):
    from intaris.classifier import classify

    assert classify(tool, {"command": command}).value == "write"


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize(
    "command",
    [
        "echo 'hello'>/tmp/out",
        "cat 'input'</tmp/in",
        "date -s tomorrow",
        "hostname changed",
        "tree -o /tmp/out",
        "file -C -m custom.magic",
        "sort --ou=/tmp/out input",
        "uniq -- input -output",
        "fd -Hxtouch",
        "git remote -v add malicious /tmp/repo",
        "git config --get x --edit",
        "git tag -l -d tag",
        "git diff --out=/tmp/out",
    ],
)
def test_shell_side_effect_options_never_fast(tool, command):
    from intaris.classifier import classify

    assert classify(tool, {"command": command}).value == "write"


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize("policy", [None, POLICY], ids=["default", "mandatory"])
@pytest.mark.parametrize(
    "command",
    [
        "find . -{delete,print}",
        "find . -{delete,{print,ls}}",
        "rg --{pre=sh,files}",
        "ls file{1..3}",
        "find . '-{delete,print}'",
    ],
)
def test_brace_syntax_requires_evaluation(tool, policy, command):
    from intaris.classifier import classify

    # shlex does not expand braces. The shell can turn an apparently safe
    # operand into write/exec options; quoted braces are conservative too.
    assert classify(tool, {"command": command}, session_policy=policy).value == "write"


@pytest.mark.parametrize("tool", ["terminal", "bash"])
def test_agent_brace_expansion_reaches_inference(client, tool):
    create(client)
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "reasoning": "Brace expansion adds a destructive find option",
                "decision": "deny",
            }
        ),
    ) as inference:
        result = evaluate(client, tool=tool, command="find . -{delete,print}")

    assert result["decision"] == "deny", result
    assert result["path"] == "llm", result
    inference.assert_called_once()
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == "write"
    assert audit["tool"] == tool


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize("policy", [None, POLICY], ids=["default", "mandatory"])
@pytest.mark.parametrize(
    "command",
    [
        "find . *",
        "find . -??????",
        "find . [-]delete",
        "find . @(-delete)",
        "find . '*'",
        r"find . \*",
    ],
)
def test_glob_syntax_requires_evaluation(tmp_path, tool, policy, command):
    from intaris.classifier import classify

    # Matching filenames can become options after shell expansion. Never
    # execute find: classification must reject the syntax before READ.
    for name in ("-delete", "-print"):
        (tmp_path / name).touch()
    assert (
        classify(
            tool,
            {"command": command},
            session_policy=policy,
            working_directory=str(tmp_path),
        ).value
        == "write"
    )


@pytest.mark.parametrize("tool", ["terminal", "bash"])
def test_agent_pathname_expansion_reaches_inference(client, tmp_path, tool):
    shell_directory = tmp_path / "shell"
    shell_directory.mkdir()
    for name in ("-delete", "-print"):
        (shell_directory / name).touch()
    create(client, details={"working_directory": str(shell_directory)})
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "reasoning": "Pathname expansion adds a destructive find option",
                "decision": "deny",
            }
        ),
    ) as inference:
        result = evaluate(client, tool=tool, command="find . *")

    assert result["decision"] == "deny", result
    assert result["path"] == "llm", result
    inference.assert_called_once()
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == "write"
    assert audit["tool"] == tool


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize("policy", [None, POLICY], ids=["default", "mandatory"])
@pytest.mark.parametrize(
    "option", ["--filters", "--filter", "--filte", "--filt", "--fil", "--fi", "--f"]
)
def test_git_filter_options_require_evaluation(tmp_path, tool, policy, option):
    from intaris.classifier import classify

    # Long-option abbreviations and overlaps vary across Git versions.
    # Check every prefix conservatively without executing configured filters.
    command = f"git cat-file {option} HEAD:assets/model.bin"
    assert (
        classify(
            tool,
            {"command": command},
            session_policy=policy,
            working_directory=str(tmp_path),
        ).value
        == "write"
    )


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize("option", ["--filters", "--filt"])
def test_agent_git_filters_reach_inference(client, tmp_path, tool, option):
    create(client, details={"working_directory": str(tmp_path)})
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "reasoning": "Git filters can execute commands with side effects",
                "decision": "deny",
            }
        ),
    ) as inference:
        result = evaluate(
            client,
            tool=tool,
            command=f"git cat-file {option} HEAD:assets/model.bin",
        )

    assert result["decision"] == "deny", result
    assert result["path"] == "llm", result
    inference.assert_called_once()
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == "write"
    assert audit["tool"] == tool


def test_atomic_lifecycle_update_preserves_concurrent_stop(client):
    from intaris.session import SessionStore

    create(client)
    original = SessionStore.update_status

    def stop_before_update(store, session_id, status, **kwargs):
        if kwargs.get("agent_request"):
            original(store, session_id, "suspended", user_id=kwargs["user_id"])
        return original(store, session_id, status, **kwargs)

    with patch.object(SessionStore, "update_status", stop_before_update):
        response = client.patch(
            "/api/v1/session/s/status", headers=AGENT, json={"status": "active"}
        )
    assert response.status_code == 403
    assert (
        client.get("/api/v1/session/s", headers=ADMIN).json()["status"] == "suspended"
    )


def test_restricted_marker_survives_database_reopen(client):
    import intaris.server as srv
    from intaris.db import Database
    from intaris.session import SessionStore

    create(client)
    db = Database(srv._config.db)
    try:
        assert SessionStore(db).get("s", user_id="owner")["agent_restricted"]
    finally:
        db.close()


def test_agent_can_read_behavior_and_flush_recording(client):
    create(client)
    for path in ("/session/s/summary", "/profile"):
        response = client.get("/api/v1" + path, headers=AGENT)
        assert response.status_code == 200, response.text
    response = client.post("/api/v1/session/s/events/flush", headers=AGENT)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("carrier", ["authorization", "x-api-key", "cognis_session"])
def test_agent_websocket_cannot_use_alternate_admin_auth(client, carrier):
    headers = {}
    if carrier == "cognis_session":
        client.cookies.set(carrier, "agent-secret")
    else:
        headers[carrier] = (
            "Bearer agent-secret" if carrier == "authorization" else "agent-secret"
        )
    with client.websocket_connect("/api/v1/stream", headers=headers) as ws:
        ws.send_json({"type": "auth", "token": "admin-secret", "user_id": "owner"})
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 4001


def test_agent_key_that_looks_like_jwt_stays_restricted(client):
    import intaris.server as srv

    srv._config.server.agent_api_keys["header.payload.signature"] = "owner"
    response = client.post(
        "/api/v1/decision",
        headers={"Authorization": "Bearer header.payload.signature"},
        json={},
    )
    assert response.status_code == 403


def test_conflicting_agent_credentials_rejected(client):
    import intaris.server as srv

    srv._config.server.agent_api_keys["other-secret"] = "other-tenant"
    response = client.get(
        "/api/v1/profile", headers={**AGENT, "X-API-Key": "other-secret"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("classification", ["write", "escalate"])
@pytest.mark.parametrize("resolved_by", ["judge", "user"])
@pytest.mark.parametrize("restricted", [True, False], ids=["restricted", "legacy"])
def test_retry_approval_identity_for_every_classification(
    client, classification, resolved_by, restricted
):
    import intaris.server as srv
    from intaris.audit import AuditStore
    from intaris.decision import Decision

    create(client, "history", headers=ADMIN)
    evaluator = srv._get_evaluator()
    args = {"command": "touch /tmp/output"}
    prior = evaluator.evaluate(
        user_id="owner",
        session_id="history",
        agent_id="operator",
        tool="terminal",
        args=args,
        tool_preferences={"terminal": "escalate"},
    )
    AuditStore(srv._get_db()).resolve_escalation(
        prior["call_id"], "approve", user_id="owner", resolved_by=resolved_by
    )
    create(client, headers=AGENT if restricted else ADMIN)
    with patch.object(
        evaluator,
        "_llm_evaluate",
        return_value=Decision("deny", "high", "Current policy rejects write", "llm"),
    ) as inference:
        result = evaluator.evaluate(
            user_id="owner",
            session_id="s",
            agent_id="hermes",
            tool="terminal",
            args=args,
            tool_preferences=(
                {"terminal": "escalate"} if classification == "escalate" else None
            ),
            restricted_agent=restricted,
        )

    if restricted and resolved_by == "judge":
        assert result["decision"] == (
            "deny" if classification == "write" else "escalate"
        ), result
        if classification == "write":
            inference.assert_called_once()
            assert inference.call_args.kwargs["session"]["policy"] == POLICY
        else:
            inference.assert_not_called()
    else:
        assert result["decision"] == "approve", result
        assert result["path"] == "fast"
        inference.assert_not_called()


@pytest.mark.parametrize("history_session", ["history", "s"])
def test_agent_write_cannot_reuse_old_judge_approval(client, history_session):
    import intaris.server as srv
    from intaris.audit import AuditStore

    create(client, history_session, headers=ADMIN)
    evaluator = srv._get_evaluator()
    prior = evaluator.evaluate(
        user_id="owner",
        session_id=history_session,
        agent_id="operator",
        tool="terminal",
        args={"command": "touch /tmp/output"},
        tool_preferences={"terminal": "escalate"},
    )
    AuditStore(srv._get_db()).resolve_escalation(
        prior["call_id"], "approve", user_id="owner", resolved_by="judge"
    )
    if history_session != "s":
        create(client)
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "reasoning": "Current policy rejects write",
                "decision": "deny",
            }
        ),
    ) as inference:
        result = evaluate(client, command="touch /tmp/output")
    assert result["decision"] == "deny", result
    assert result["path"] == "llm", result
    inference.assert_called_once()


@pytest.mark.parametrize("stopped_status", ["suspended", "terminated"])
@pytest.mark.parametrize(
    "headers", [AGENT, ADMIN], ids=["agent", "admin-on-restricted"]
)
def test_idle_resume_race_returns_inactive_denial(client, stopped_status, headers):
    from intaris.session import SessionStore

    create(client)
    client.patch(
        "/api/v1/session/s/status", headers=ADMIN, json={"status": "idle"}
    ).raise_for_status()
    original = SessionStore.update_status

    def stop_before_resume(store, session_id, status, **kwargs):
        if status == "active" and kwargs.get("agent_request"):
            original(
                store,
                session_id,
                stopped_status,
                user_id=kwargs["user_id"],
                status_reason="Operator stopped session during idle resume",
            )
        return original(store, session_id, status, **kwargs)

    with patch.object(SessionStore, "update_status", stop_before_resume):
        response = client.post(
            "/api/v1/evaluate",
            headers=headers,
            json={"session_id": "s", "tool": "terminal", "args": {"command": "pwd"}},
        )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["decision"] == "deny", result
    assert result["session_status"] == stopped_status
    assert result["status_reason"] == "Operator stopped session during idle resume"
    assert result["outcome_override"] == "hard_stop.session_lifecycle"
    assert result["path"] == "fast"
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["decision"] == "deny"
    assert audit["outcome_override"] == "hard_stop.session_lifecycle"
    session = client.get("/api/v1/session/s", headers=ADMIN).json()
    assert session["status"] == stopped_status
    assert session["status_reason"] == result["status_reason"]


def test_restricted_idle_resume_without_race_stays_fast(client):
    create(client)
    client.patch(
        "/api/v1/session/s/status", headers=ADMIN, json={"status": "idle"}
    ).raise_for_status()
    result = evaluate(client)
    assert result["decision"] == "approve"
    assert result["path"] == "fast"
    assert client.get("/api/v1/session/s", headers=ADMIN).json()["status"] == "active"


def _evaluate_path_read(client, path, headers=AGENT):
    response = client.post(
        "/api/v1/evaluate",
        headers=headers,
        json={
            "session_id": "s",
            "tool": "terminal",
            "args": {"command": f"cat {path}"},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("source", ["llm", "judge"])
@pytest.mark.parametrize("adoption", ["agent", "other-worker", "legacy"])
def test_restricted_adoption_ignores_prior_path_prefix(client, source, adoption):
    import asyncio

    import intaris.server as srv
    from intaris.decision import Decision
    from intaris.judge import resolve_with_side_effects
    from intaris.session import SessionStore

    create(client, headers=ADMIN, details={"working_directory": "/tmp/project"})
    evaluator = srv._get_evaluator()
    with patch.object(
        evaluator,
        "_llm_evaluate",
        return_value=Decision(
            "approve" if source == "llm" else "escalate", "low", "Prior read", "llm"
        ),
    ):
        prior = evaluator.evaluate(
            user_id="owner",
            session_id="s",
            agent_id="operator",
            tool="terminal",
            args={"command": "cat /outside/first.txt"},
        )
    if source == "judge":
        asyncio.run(
            resolve_with_side_effects(
                call_id=prior["call_id"],
                user_id="owner",
                user_decision="approve",
                resolved_by="judge",
                audit_store=evaluator._audit,
                evaluator=evaluator,
            )
        )
    assert evaluator._approved_paths[("owner", "s")]
    if adoption == "other-worker":
        # A different worker has no access to this evaluator's local cache.
        SessionStore(srv._get_db()).restrict_agent_session("s", user_id="owner")
    current_policy = {**POLICY, "deny_policies": ["Do not read outside project"]}
    evaluator._agent_policy = current_policy
    with patch.object(
        evaluator,
        "_llm_evaluate",
        return_value=Decision("deny", "high", "Current policy rejects read", "llm"),
    ) as inference:
        result = _evaluate_path_read(
            client, "/outside/second.txt", AGENT if adoption == "agent" else ADMIN
        )
    if adoption == "legacy":
        assert result["decision"] == "approve", result
        assert result["path"] == "fast"
        inference.assert_not_called()
    else:
        assert result["decision"] == "deny", result
        assert result["path"] == "llm"
        inference.assert_called_once()
        assert inference.call_args.kwargs["session"]["policy"] == current_policy
        audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
        assert audit["classification"] == "write"


@pytest.mark.parametrize("headers", [AGENT, ADMIN], ids=["agent", "admin"])
def test_restricted_llm_read_approval_does_not_train_path_cache(client, headers):
    import intaris.server as srv
    from intaris.decision import Decision

    create(client, details={"working_directory": "/tmp/project"})
    evaluator = srv._get_evaluator()
    with patch.object(
        evaluator,
        "_llm_evaluate",
        side_effect=[
            Decision("approve", "low", "One read approved", "llm"),
            Decision("deny", "high", "Sibling read rejected", "llm"),
        ],
    ) as inference:
        first = _evaluate_path_read(client, "/outside/first.txt", headers)
        second = _evaluate_path_read(client, "/outside/second.txt", headers)
    assert first["decision"] == "approve"
    assert second["decision"] == "deny", second
    assert second["path"] == "llm"
    assert inference.call_count == 2
    assert not evaluator._approved_paths.get(("owner", "s"))


def test_admin_inference_finishing_after_adoption_cannot_train_path_cache(client):
    import intaris.server as srv
    from intaris.decision import Decision
    from intaris.session import SessionStore

    create(client, headers=ADMIN, details={"working_directory": "/tmp/project"})
    evaluator = srv._get_evaluator()

    def adopt_during_inference(**kwargs):
        assert not kwargs["session"]["agent_restricted"]
        # Deterministic interleaving: another worker adopts the session while
        # this unrestricted request is awaiting its model response.
        SessionStore(srv._get_db()).restrict_agent_session("s", user_id="owner")
        return Decision("approve", "low", "Old admin inference completed", "llm")

    with patch.object(evaluator, "_llm_evaluate", side_effect=adopt_during_inference):
        assert (
            _evaluate_path_read(client, "/outside/first.txt", ADMIN)["decision"]
            == "approve"
        )
    assert not evaluator._approved_paths.get(("owner", "s"))
    with patch.object(
        evaluator,
        "_llm_evaluate",
        return_value=Decision("deny", "high", "Restricted read rejected", "llm"),
    ) as inference:
        result = _evaluate_path_read(client, "/outside/second.txt")
    assert result["decision"] == "deny", result
    inference.assert_called_once()


@pytest.mark.parametrize("resolved_by", ["judge", "user"])
def test_restricted_path_approval_reuses_only_exact_human_call(client, resolved_by):
    import asyncio

    import intaris.server as srv
    from intaris.decision import Decision
    from intaris.judge import resolve_with_side_effects

    create(client, details={"working_directory": "/tmp/project"})
    evaluator = srv._get_evaluator()
    with patch.object(
        evaluator,
        "_llm_evaluate",
        return_value=Decision("deny", "high", "Read needs approval", "llm"),
    ):
        prior = _evaluate_path_read(client, "/outside/first.txt")
    if resolved_by == "user":
        client.post(
            "/api/v1/decision",
            headers=ADMIN,
            json={"call_id": prior["call_id"], "decision": "approve"},
        ).raise_for_status()
    else:
        asyncio.run(
            resolve_with_side_effects(
                call_id=prior["call_id"],
                user_id="owner",
                user_decision="approve",
                resolved_by="judge",
                audit_store=evaluator._audit,
                evaluator=evaluator,
            )
        )
    with patch.object(
        evaluator,
        "_llm_evaluate",
        return_value=Decision("deny", "high", "Current read rejected", "llm"),
    ) as inference:
        exact = _evaluate_path_read(client, "/outside/first.txt")
        sibling = _evaluate_path_read(client, "/outside/second.txt")
    assert exact["decision"] == ("approve" if resolved_by == "user" else "deny"), exact
    assert sibling["decision"] == "deny", sibling
    assert sibling["path"] == "llm"
    assert inference.call_count == (1 if resolved_by == "user" else 2)
    assert not evaluator._approved_paths.get(("owner", "s"))


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize(
    "deny_paths", [[], ["/etc/*"]], ids=["boundary", "explicit-deny"]
)
def test_agent_quoted_shell_paths_obey_mandatory_policy(client, tool, deny_paths):
    import intaris.server as srv

    evaluator = srv._get_evaluator()
    evaluator._agent_policy = {**POLICY, "deny_paths": deny_paths}
    create(client, details={"working_directory": "/tmp/project"})
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "reasoning": "Outside-project read requires authorization",
                "decision": "deny",
            }
        ),
    ) as inference:
        result = evaluate(client, tool=tool, command='cat "/etc/passwd"')
    assert result["decision"] == "deny", result
    assert result["path"] == ("critical" if deny_paths else "llm"), result
    assert inference.call_count == (0 if deny_paths else 1)
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == ("critical" if deny_paths else "write")
    assert audit["tool"] == tool
    if not deny_paths:
        context = audit["args_redacted"]["__intaris_context"]["path_policy"]
        assert context["target_paths"] == ["/etc/passwd"]


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize(
    "command", ['grep -nf "/etc/passwd" README.md', 'rg -nf "/etc/passwd" README.md']
)
def test_agent_search_file_flags_enforce_path_denies(client, tool, command):
    import intaris.server as srv

    srv._get_evaluator()._agent_policy = {**POLICY, "deny_paths": ["/etc/*"]}
    create(client, details={"working_directory": "/tmp/project"})
    result = evaluate(client, tool=tool, command=command)
    assert result["decision"] == "deny", result
    assert result["path"] == "critical", result
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == "critical"
    assert audit["tool"] == tool


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize(
    "deny_paths", [[], ["/etc/*"]], ids=["boundary", "explicit-deny"]
)
def test_agent_ripgrep_file_listing_obeys_path_policy(client, tool, deny_paths):
    import intaris.server as srv

    srv._get_evaluator()._agent_policy = {**POLICY, "deny_paths": deny_paths}
    create(client, details={"working_directory": "/tmp/project"})
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "reasoning": "Unapproved directory",
                "decision": "deny",
            }
        ),
    ) as inference:
        result = evaluate(client, tool=tool, command='rg --files "/etc/private"')
    assert result["decision"] == "deny", result
    assert result["path"] == ("critical" if deny_paths else "llm"), result
    assert inference.call_count == (0 if deny_paths else 1)
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == ("critical" if deny_paths else "write")
    assert audit["tool"] == tool


@pytest.mark.parametrize("tool", ["terminal", "bash"])
def test_agent_stat_format_is_not_a_denied_path(client, tool):
    import intaris.server as srv

    srv._get_evaluator()._agent_policy = {**POLICY, "deny_paths": ["/etc/*"]}
    create(client, details={"working_directory": "/tmp/project"})
    result = evaluate(client, tool=tool, command='stat -c "/etc/passwd" README.md')
    assert result["decision"] == "approve", result
    assert result["path"] == "fast", result
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == "read"
    assert audit["tool"] == tool


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize(
    "command,option,target",
    [("grep", "--exclude-from", "README.md"), ("rg", "--ignore-file", ".")],
)
@pytest.mark.parametrize("separator", ["=", " "])
@pytest.mark.parametrize(
    "deny_paths", [[], ["/etc/*"]], ids=["boundary", "explicit-deny"]
)
def test_agent_auxiliary_search_files_obey_policy(
    client, tool, command, option, target, separator, deny_paths
):
    import intaris.server as srv

    srv._get_evaluator()._agent_policy = {**POLICY, "deny_paths": deny_paths}
    create(client, details={"working_directory": "/tmp/project"})
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "reasoning": "Unapproved auxiliary file",
                "decision": "deny",
            }
        ),
    ):
        result = evaluate(
            client,
            tool=tool,
            command=f'{command} {option}{separator}"/etc/passwd" pattern {target}',
        )
    assert result["decision"] == "deny", result
    assert result["path"] == ("critical" if deny_paths else "llm"), result
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == ("critical" if deny_paths else "write")
    assert audit["tool"] == tool


@pytest.mark.parametrize("tool", ["terminal", "bash"])
@pytest.mark.parametrize("command", ["cat ~alex/notes.txt", "cat ~-/notes.txt"])
def test_agent_unresolved_tilde_requires_evaluation(client, tool, command):
    create(client, details={"working_directory": "/tmp/project"})
    with patch(
        "intaris.llm.LLMClient.generate",
        return_value=json.dumps(
            {
                "aligned": False,
                "risk": "high",
                "reasoning": "Unresolved client path",
                "decision": "deny",
            }
        ),
    ):
        result = evaluate(client, tool=tool, command=command)
    assert result["decision"] == "deny", result
    assert result["path"] == "llm", result
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == "write"
    assert audit["tool"] == tool


@pytest.mark.parametrize("tool", ["terminal", "bash"])
def test_agent_stat_cluster_format_is_data(client, tool):
    import intaris.server as srv

    srv._get_evaluator()._agent_policy = {**POLICY, "deny_paths": ["/etc/*"]}
    create(client, details={"working_directory": "/tmp/project"})
    result = evaluate(client, tool=tool, command='stat -Lc "/etc/passwd" README.md')
    assert result["decision"] == "approve", result
    assert result["path"] == "fast", result
    audit = client.get(f"/api/v1/audit/{result['call_id']}", headers=AGENT).json()
    assert audit["classification"] == "read"
    assert audit["tool"] == tool
