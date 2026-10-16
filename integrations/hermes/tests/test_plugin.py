"""Unit tests for the Hermes Intaris plugin."""

from __future__ import annotations

import io
import json
import os
import sys
import types
import urllib.error
from dataclasses import replace
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Stub the Hermes-internal ``tools.registry`` module so the plugin can be
# imported without a full Hermes installation.
# ---------------------------------------------------------------------------

_fake_tools: dict[str, object] = {}


class _FakeToolEntry:
    __slots__ = (
        "name",
        "toolset",
        "schema",
        "handler",
        "check_fn",
        "requires_env",
        "is_async",
        "description",
        "emoji",
    )

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class _FakeRegistry:
    def __init__(self):
        self._tools: dict[str, _FakeToolEntry] = {}

    def register(self, **kw):
        entry = _FakeToolEntry(**kw)
        self._tools[kw["name"]] = entry


_registry = _FakeRegistry()

# Inject the stub into sys.modules BEFORE importing the plugin.
_tools_mod = types.ModuleType("tools")
_registry_mod = types.ModuleType("tools.registry")
_registry_mod.registry = _registry  # type: ignore[attr-defined]
sys.modules["tools"] = _tools_mod
sys.modules["tools.registry"] = _registry_mod

# Now we can import the plugin package.
from hermes_intaris import (  # noqa: E402
    Config,
    ProfileRuntime,
    SessionState,
    _build_agent_summary,
    _build_checkpoint_content,
    _build_policy,
    _get_or_create_state,
    _make_guarded_handler,
    _profile_key,
    _resolve_config,
    register,
)
from hermes_intaris.client import ApiResult, IntarisClient  # noqa: E402

from . import test_waits  # noqa: E402

host = test_waits.host

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset registrations between tests."""
    import hermes_intaris as mod

    mod._profiles.clear()
    mod._retired_sessions.clear()
    mod._registration_locks.clear()
    mod._registered_homes.clear()
    mod._completion_owners.clear()
    mod._retired_owners.clear()
    _registry._tools.clear()
    yield
    mod._profiles.clear()
    mod._retired_sessions.clear()
    mod._registration_locks.clear()
    mod._registered_homes.clear()
    mod._completion_owners.clear()
    mod._retired_owners.clear()


@pytest.fixture
def profile():
    return ProfileRuntime(
        home=_profile_key(),
        cfg=Config(),
        client=IntarisClient("http://test:8060", "key"),
    )


@pytest.fixture
def env_vars(monkeypatch):
    """Set required environment variables."""
    monkeypatch.setenv("INTARIS_URL", "http://test:8060")
    monkeypatch.setenv("INTARIS_API_KEY", "test-key")
    monkeypatch.setenv("INTARIS_USER_ID", "test-user")


@pytest.fixture
def scripted_http(monkeypatch, host):
    """Control only transport and time; keep adapter/client/polling real."""
    clock = types.SimpleNamespace(now=0.0)

    def sleep(seconds):
        clock.now += seconds

    monkeypatch.setattr("time.sleep", sleep)
    monkeypatch.setattr("time.monotonic", lambda: clock.now)
    monkeypatch.setattr(
        "hermes_intaris.waits.Invocation._wait_slice",
        lambda _self, seconds: sleep(seconds),
    )

    def script(*replies):
        responses = []
        for reply in replies:
            if isinstance(reply, Exception):
                responses.append(reply)
                continue
            body = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
            response = io.BytesIO(body)
            response.status = 200
            responses.append(response)
        transport = mock.Mock(side_effect=responses)
        monkeypatch.setattr("urllib.request.urlopen", transport)
        return transport

    return script


@pytest.fixture
def guarded_native(profile):
    """Create a real guard with valid Hermes context and observable execution."""

    profile.cfg = Config(checkpoint_interval=0, escalation_timeout_s=10)
    profile.client = IntarisClient("http://test:8060", "test-key", "test-user")
    state = _get_or_create_state(profile, "task-1")
    state.intaris_session_id = "hm-test-session"
    state.session_created = True
    executed = []

    def original(args, **kwargs):
        executed.append((args, kwargs))
        return json.dumps({"result": "executed"})

    handler = _make_guarded_handler(
        profile, original, "terminal", "terminal-tools", False
    )

    def invoke():
        return json.loads(
            handler({"command": "pwd"}, task_id="task-1", session_id="task-1")
        )

    return invoke, executed, state


INVALID_DECISION_RESPONSES = [
    pytest.param({"decision": "unexpected"}, id="unknown"),
    pytest.param({"decision": "APPROVE"}, id="uppercase"),
    pytest.param({"decision": " approve "}, id="whitespace"),
    pytest.param({"decision": None}, id="null-decision"),
    pytest.param({"decision": False}, id="false-decision"),
    pytest.param({"decision": True}, id="true-decision"),
    pytest.param({"decision": 1}, id="number-decision"),
    pytest.param({"decision": []}, id="array-decision"),
    pytest.param({"decision": {"approve": True}}, id="object-decision"),
    pytest.param({"reasoning": "missing decision"}, id="missing-decision"),
    pytest.param({"decision": "escalate"}, id="missing-escalation-id"),
    pytest.param({}, id="empty-object"),
    pytest.param(None, id="null-response"),
    pytest.param(False, id="false-response"),
    pytest.param(True, id="true-response"),
    pytest.param(1, id="number-response"),
    pytest.param("approve", id="string-response"),
    pytest.param([], id="empty-array"),
    pytest.param([{"decision": "approve"}], id="array-response"),
    pytest.param(b'{"decision":', id="malformed-json"),
    pytest.param(b"", id="empty-body"),
    pytest.param(b"\xff", id="invalid-utf8"),
    pytest.param(
        b'{"decision":"approve","content":[],"metadata":NaN}', id="non-json-nan"
    ),
    pytest.param(
        b'{"decision":"approve","content":[],"metadata":Infinity}',
        id="non-json-infinity",
    ),
    pytest.param(
        b'{"decision":"approve","content":[],"metadata":-Infinity}',
        id="non-json-negative-infinity",
    ),
]


def _evaluation(decision, **fields):
    return {
        "call_id": "call-1",
        "decision": decision,
        "reasoning": "Safety evaluation",
        "risk": "low",
        "path": "llm",
        "latency_ms": 1,
        **fields,
    }


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestConfig:
    def test_defaults(self, monkeypatch):
        # Clear all INTARIS env vars to test true defaults
        for key in list(os.environ):
            if key.startswith("INTARIS_"):
                monkeypatch.delenv(key, raising=False)
        cfg = _resolve_config()
        assert cfg.url == "http://localhost:8060"
        assert cfg.api_key == ""
        assert cfg.fail_open is False
        assert cfg.checkpoint_interval == 25
        assert cfg.recording is False
        assert cfg.mcp_tools is True  # default is True (enabled by default)

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("INTARIS_URL", "http://custom:9090")
        monkeypatch.setenv("INTARIS_API_KEY", "my-key")
        monkeypatch.setenv("INTARIS_FAIL_OPEN", "true")
        monkeypatch.setenv("INTARIS_CHECKPOINT_INTERVAL", "50")
        monkeypatch.setenv("INTARIS_SESSION_RECORDING", "1")
        monkeypatch.setenv("INTARIS_MCP_TOOLS", "true")
        cfg = _resolve_config()
        assert cfg.url == "http://custom:9090"
        assert cfg.api_key == "my-key"
        assert cfg.fail_open is True
        assert cfg.checkpoint_interval == 50
        assert cfg.recording is True
        assert cfg.mcp_tools is True


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_build_policy_defaults(self):
        policy = _build_policy("")
        assert "/tmp/*" in policy["allow_paths"]
        assert "/var/tmp/*" in policy["allow_paths"]

    def test_build_policy_with_paths(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/user")
        policy = _build_policy("~/src, /opt/data")
        paths = policy["allow_paths"]
        assert "/home/user/src/*" in paths
        assert "/opt/data/*" in paths

    def test_build_checkpoint_content(self, profile):

        profile.cfg = Config(checkpoint_interval=25)
        state = SessionState(
            call_count=50,
            approved_count=45,
            denied_count=3,
            escalated_count=2,
            recent_tools=["read_file", "terminal"],
        )
        content = _build_checkpoint_content(profile, state)
        assert "Checkpoint #2" in content
        assert "50 calls" in content
        assert "45 approved" in content
        assert "read_file, terminal" in content

    def test_build_agent_summary(self):
        state = SessionState(
            call_count=10,
            approved_count=8,
            denied_count=1,
            escalated_count=1,
        )
        summary = _build_agent_summary(state)
        assert "10 tool calls" in summary
        assert "8 approved" in summary

    def test_get_or_create_state(self, profile):
        state1 = _get_or_create_state(profile, "task-1")
        state2 = _get_or_create_state(profile, "task-1")
        assert state1 is state2
        assert state1.call_count == 0


# ---------------------------------------------------------------------------
# Client tests
# ---------------------------------------------------------------------------


class TestClient:
    def test_call_api_success(self):
        client = IntarisClient("http://test:8060", "key", "user")
        response_data = json.dumps({"session_id": "s1"}).encode()

        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = response_data
            mock_resp.status = 200
            mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = client.call_api("POST", "/api/v1/intention", {"session_id": "s1"})
            assert result.data == {"session_id": "s1"}
            assert result.status == 200
            assert result.error is None

    def test_call_api_http_error(self):
        import urllib.error

        client = IntarisClient("http://test:8060", "key", "user")

        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            error = urllib.error.HTTPError(
                "http://test:8060/api/v1/intention",
                401,
                "Unauthorized",
                {},
                None,
            )
            error.read = mock.MagicMock(return_value=b'{"detail": "Invalid API key"}')
            mock_urlopen.side_effect = error

            result = client.call_api("POST", "/api/v1/intention", {})
            assert result.status == 401
            assert "Invalid API key" in (result.error or "")

    def test_call_api_network_error(self):
        client = IntarisClient("http://test:8060", "key", "user")

        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = ConnectionError("Connection refused")

            result = client.call_api("POST", "/api/v1/intention", {})
            assert result.status is None
            assert "Connection refused" in (result.error or "")


# ---------------------------------------------------------------------------
# Tool wrapper tests
# ---------------------------------------------------------------------------


class TestToolWrapper:
    def _setup_plugin(self, monkeypatch, profile):
        """Set up the plugin with mocked client."""

        monkeypatch.setenv("INTARIS_URL", "http://test:8060")
        monkeypatch.setenv("INTARIS_API_KEY", "test-key")
        monkeypatch.setenv("INTARIS_MCP_TOOLS", "false")

        profile.cfg = _resolve_config()
        profile.client = IntarisClient("http://test:8060", "test-key")

        # Create a session
        state = _get_or_create_state(profile, "session-1")
        state.intaris_session_id = "hm-test-session"
        return state

    def test_approve_calls_original(self, monkeypatch, profile):
        self._setup_plugin(monkeypatch, profile)
        original = mock.MagicMock(return_value='{"result": "ok"}')

        handler = _make_guarded_handler(
            profile, original, "read_file", "file-tools", False
        )

        with mock.patch.object(IntarisClient, "evaluate") as mock_eval:
            mock_eval.return_value = ApiResult(
                data={
                    "call_id": "c1",
                    "decision": "approve",
                    "reasoning": "",
                    "risk": "low",
                    "path": "fast",
                    "latency_ms": 1,
                },
                status=200,
            )
            result = handler(
                {"path": "/tmp/test.txt"}, session_id="session-1", task_id="task-1"
            )

        assert result == '{"result": "ok"}'
        original.assert_called_once_with(
            {"path": "/tmp/test.txt"}, session_id="session-1", task_id="task-1"
        )

    def test_deny_blocks_execution(self, monkeypatch, profile):
        self._setup_plugin(monkeypatch, profile)
        original = mock.MagicMock(return_value='{"result": "ok"}')

        handler = _make_guarded_handler(
            profile, original, "terminal", "terminal-tools", False
        )

        with mock.patch.object(IntarisClient, "evaluate") as mock_eval:
            mock_eval.return_value = ApiResult(
                data={
                    "call_id": "c2",
                    "decision": "deny",
                    "reasoning": "Dangerous command",
                    "risk": "critical",
                    "path": "critical",
                    "latency_ms": 1,
                },
                status=200,
            )
            result = handler(
                {"command": "rm -rf /"}, session_id="session-1", task_id="task-1"
            )

        parsed = json.loads(result)
        assert "error" in parsed
        assert "DENIED" in parsed["error"]
        assert "Dangerous command" in parsed["error"]
        original.assert_not_called()

    def test_fail_open_on_network_error(self, monkeypatch, profile):

        monkeypatch.setenv("INTARIS_FAIL_OPEN", "true")
        self._setup_plugin(monkeypatch, profile)
        profile.cfg = _resolve_config()  # Re-resolve with fail_open=true
        original = mock.MagicMock(return_value='{"result": "ok"}')

        handler = _make_guarded_handler(
            profile, original, "read_file", "file-tools", False
        )

        with mock.patch.object(IntarisClient, "evaluate") as mock_eval:
            mock_eval.return_value = ApiResult(error="Connection refused")
            result = handler(
                {"path": "/tmp/test.txt"}, session_id="session-1", task_id="task-1"
            )

        assert result == '{"result": "ok"}'
        original.assert_called_once()

    def test_fail_closed_on_network_error(self, monkeypatch, profile):
        self._setup_plugin(monkeypatch, profile)
        original = mock.MagicMock(return_value='{"result": "ok"}')

        handler = _make_guarded_handler(
            profile, original, "terminal", "terminal-tools", False
        )

        with mock.patch.object(IntarisClient, "evaluate") as mock_eval:
            mock_eval.return_value = ApiResult(error="Connection refused")
            result = handler(
                {"command": "ls"}, session_id="session-1", task_id="task-1"
            )

        parsed = json.loads(result)
        assert "error" in parsed
        assert "INTARIS_FAIL_OPEN=false" in parsed["error"]
        original.assert_not_called()

    def test_4xx_always_blocks(self, monkeypatch, profile):
        """4xx errors block even with fail_open=true."""

        monkeypatch.setenv("INTARIS_FAIL_OPEN", "true")
        self._setup_plugin(monkeypatch, profile)
        profile.cfg = _resolve_config()
        original = mock.MagicMock(return_value='{"result": "ok"}')

        handler = _make_guarded_handler(
            profile, original, "terminal", "terminal-tools", False
        )

        with mock.patch.object(IntarisClient, "evaluate") as mock_eval:
            mock_eval.return_value = ApiResult(error="Unauthorized", status=401)
            result = handler(
                {"command": "ls"}, session_id="session-1", task_id="task-1"
            )

        parsed = json.loads(result)
        assert "error" in parsed
        assert "rejected" in parsed["error"].lower()
        original.assert_not_called()

    def test_statistics_tracking(self, monkeypatch, profile):
        state = self._setup_plugin(monkeypatch, profile)
        original = mock.MagicMock(return_value='{"result": "ok"}')

        handler = _make_guarded_handler(
            profile, original, "read_file", "file-tools", False
        )

        with mock.patch.object(IntarisClient, "evaluate") as mock_eval:
            mock_eval.return_value = ApiResult(
                data={
                    "call_id": "c1",
                    "decision": "approve",
                    "reasoning": "",
                    "risk": "low",
                    "path": "fast",
                    "latency_ms": 1,
                },
                status=200,
            )
            handler({"path": "/tmp/test.txt"}, session_id="session-1", task_id="task-1")

        assert state.call_count == 1
        assert state.approved_count == 1
        assert state.recent_tools == ["read_file"]

    def test_no_session_fail_closed(self, monkeypatch, profile):
        """No active session with fail_open=false returns error."""

        monkeypatch.setenv("INTARIS_URL", "http://test:8060")
        monkeypatch.setenv("INTARIS_API_KEY", "test-key")
        monkeypatch.setenv("INTARIS_MCP_TOOLS", "false")
        profile.cfg = _resolve_config()
        profile.client = IntarisClient("http://test:8060", "test-key")

        original = mock.MagicMock(return_value='{"result": "ok"}')
        handler = _make_guarded_handler(
            profile, original, "terminal", "terminal-tools", False
        )

        result = handler({"command": "ls"}, session_id="session-1", task_id="task-1")
        parsed = json.loads(result)
        assert "error" in parsed
        assert "No active Intaris session" in parsed["error"]
        original.assert_not_called()


# ---------------------------------------------------------------------------
# Decision protocol tests
# ---------------------------------------------------------------------------


class TestDecisionProtocol:
    def test_non_json_constant_names_are_allowed_in_strings(
        self, guarded_native, scripted_http
    ):
        invoke, executed, _ = guarded_native
        scripted_http(_evaluation("approve", reasoning="NaN Infinity -Infinity"))

        assert invoke() == {"result": "executed"}
        assert len(executed) == 1

    @pytest.mark.parametrize("fail_open", [False, True])
    @pytest.mark.parametrize("reactivated", [False, True])
    @pytest.mark.parametrize("body", INVALID_DECISION_RESPONSES)
    def test_invalid_evaluation_never_executes(
        self, profile, guarded_native, scripted_http, body, fail_open, reactivated
    ):

        invoke, executed, state = guarded_native
        profile.cfg = replace(profile.cfg, fail_open=fail_open)
        prefix = []
        if reactivated:
            prefix = [
                _evaluation("deny", session_status="suspended"),
                {"session_id": "hm-test-session", "status": "active"},
            ]
        transport = scripted_http(*prefix, body)

        result = invoke()

        assert executed == []
        assert "invalid" in result["error"].lower()
        assert "response" in result["error"].lower()
        assert state.pending_tool_results == []
        assert transport.call_count == len(prefix) + 1

    @pytest.mark.parametrize("reactivated", [False, True])
    @pytest.mark.parametrize("decision,expected_calls", [("approve", 1), ("deny", 0)])
    def test_recognized_decision_controls_execution(
        self, guarded_native, scripted_http, decision, expected_calls, reactivated
    ):
        invoke, executed, state = guarded_native
        prefix = []
        if reactivated:
            prefix = [
                _evaluation("deny", session_status="suspended"),
                {"session_id": "hm-test-session", "status": "active"},
            ]
        transport = scripted_http(*prefix, _evaluation(decision))

        result = invoke()

        assert len(executed) == expected_calls
        if expected_calls:
            assert result == {"result": "executed"}
            assert executed == [
                ({"command": "pwd"}, {"task_id": "task-1", "session_id": "task-1"})
            ]
            assert state.pending_tool_results[0]["call_id"] == "call-1"
        else:
            assert "DENIED" in result["error"]
        assert transport.call_count == len(prefix) + 1
        request = transport.call_args.args[0]
        assert json.loads(request.data)["session_id"] == "hm-test-session"

    @pytest.mark.parametrize("reactivated", [False, True])
    @pytest.mark.parametrize("resolution,expected_calls", [("approve", 1), ("deny", 0)])
    def test_escalation_waits_for_explicit_resolution(
        self, guarded_native, scripted_http, resolution, expected_calls, reactivated
    ):
        invoke, executed, state = guarded_native
        prefix = []
        if reactivated:
            prefix = [
                _evaluation("deny", session_status="suspended"),
                {"session_id": "hm-test-session", "status": "active"},
            ]
        transport = scripted_http(
            *prefix,
            _evaluation("escalate"),
            {"call_id": "call-1", "user_decision": None},
            {"call_id": "call-1", "user_decision": resolution},
        )
        # No native execution is allowed before the audit returns approval.
        respond = transport.side_effect

        def respond_before_execution(*args, **kwargs):
            assert executed == []
            return next(respond)

        transport.side_effect = respond_before_execution

        result = invoke()

        assert len(executed) == expected_calls
        assert transport.call_count == len(prefix) + 3
        if expected_calls:
            assert result == {"result": "executed"}
            assert state.pending_tool_results[0]["call_id"] == "call-1"
        else:
            assert "DENIED by user" in result["error"]

    @pytest.mark.parametrize("reactivated", [False, True])
    @pytest.mark.parametrize(
        "body",
        [
            {"user_decision": "unexpected"},
            {"user_decision": False},
            {"user_decision": True},
            {"user_decision": []},
            {"user_decision": {"approve": True}},
            {},
            [],
            None,
            b'{"user_decision":',
            b'{"user_decision":"approve","metadata":NaN}',
            b'{"user_decision":"approve","metadata":Infinity}',
            b'{"user_decision":"approve","metadata":-Infinity}',
        ],
    )
    def test_invalid_escalation_resolution_blocks(
        self, profile, guarded_native, scripted_http, body, reactivated
    ):

        invoke, executed, state = guarded_native
        profile.cfg = replace(profile.cfg, fail_open=True)
        prefix = []
        if reactivated:
            prefix = [
                _evaluation("deny", session_status="suspended"),
                {"session_id": "hm-test-session", "status": "active"},
            ]
        transport = scripted_http(*prefix, _evaluation("escalate"), body)

        result = invoke()

        assert executed == []
        assert "invalid" in result["error"].lower()
        assert "response" in result["error"].lower()
        assert state.pending_tool_results == []
        assert transport.call_count == len(prefix) + 2

    @pytest.mark.parametrize("call_id", [None, "", False, [], {}])
    def test_escalation_requires_valid_call_id(
        self, guarded_native, scripted_http, call_id
    ):
        invoke, executed, _ = guarded_native
        transport = scripted_http(_evaluation("escalate", call_id=call_id))

        result = invoke()

        assert executed == []
        assert "invalid" in result["error"].lower()
        assert transport.call_count == 1

    @pytest.mark.parametrize("reactivated", [False, True])
    @pytest.mark.parametrize("fail_open", [False, True])
    @pytest.mark.parametrize("status", [None, 401, 403, 404, 429, 503])
    def test_availability_fail_open_does_not_override_http_rejections(
        self, profile, guarded_native, scripted_http, fail_open, status, reactivated
    ):

        invoke, executed, _ = guarded_native
        profile.cfg = replace(profile.cfg, fail_open=fail_open)
        error = (
            urllib.error.URLError("unreachable")
            if status is None
            else urllib.error.HTTPError(
                "http://test:8060/api/v1/evaluate",
                status,
                "failure",
                {},
                io.BytesIO(b'{"decision":"approve"}'),
            )
        )
        prefix = []
        if reactivated:
            prefix = [
                _evaluation("deny", session_status="suspended"),
                {"session_id": "hm-test-session", "status": "active"},
            ]
        transport = scripted_http(*prefix, error)

        result = invoke()

        # Preserve the existing stricter reactivation path: fresh approval is
        # required after a known suspension, even during an availability fault.
        allowed = not reactivated and fail_open and status in (None, 503)
        assert len(executed) == int(allowed)
        assert ("result" if allowed else "error") in result
        assert transport.call_count == len(prefix) + 1

    @pytest.mark.parametrize("body", [None, [], False, "approve", b"not json", b"\xff"])
    def test_client_does_not_retry_invalid_protocol_responses(
        self, scripted_http, body
    ):
        transport = scripted_http(body, _evaluation("approve"))
        client = IntarisClient("http://test:8060", "key", "user")

        result = client.call_api_with_retry("POST", "/api/v1/mcp/call", {})

        assert result.data is None
        assert result.status == 200
        assert "invalid" in result.error.lower()
        assert transport.call_count == 1


class TestMCPDecisionProtocol:
    def _invoke(self, profile, scripted_http, body):
        import hermes_intaris as mod

        transport = scripted_http(
            {
                "tools": [
                    {
                        "server": "test",
                        "name": "tool",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
            body,
        )
        ctx = mock.Mock()
        mod._register_mcp_tools(profile, ctx)
        handler = ctx.register_tool.call_args.kwargs["handler"]
        result = json.loads(handler({}, task_id="task-1", session_id="task-1"))
        # The server may already have executed the MCP call. Do not retry an
        # invalid reply or present it as a successful result.
        assert transport.call_count == 2
        request = transport.call_args.args[0]
        assert json.loads(request.data)["session_id"] == "hm-test-session"
        return result

    @pytest.mark.parametrize("fail_open", [False, True])
    @pytest.mark.parametrize("body", INVALID_DECISION_RESPONSES)
    def test_invalid_response_is_reported_as_error(
        self, profile, guarded_native, scripted_http, body, fail_open
    ):

        profile.cfg = replace(profile.cfg, fail_open=fail_open)
        result = self._invoke(profile, scripted_http, body)

        assert "invalid" in result["error"].lower()
        assert "response" in result["error"].lower()
        assert "result" not in result

    @pytest.mark.parametrize("decision", ["approve", "deny", "escalate"])
    def test_recognized_response(
        self, profile, guarded_native, scripted_http, decision
    ):
        result = self._invoke(
            profile,
            scripted_http,
            {
                **_evaluation(decision),
                "content": [{"type": "text", "text": "server result"}],
                "isError": False,
            },
        )

        if decision == "approve":
            assert result == {"result": "server result"}
        else:
            assert ("DENIED" if decision == "deny" else "ESCALATED") in result["error"]

    @pytest.mark.parametrize(
        "fields",
        [
            {},
            {"content": None},
            {"content": "text"},
            {"content": {}},
            {"content": [None]},
            {"content": ["text"]},
            {"content": [{"text": None}]},
            {"content": [{}]},
            {"content": [{"type": "text"}]},
            {"content": [{"type": 1, "text": "value"}]},
            {"content": [{"text": "value"}]},
            {"content": [], "isError": "false"},
        ],
    )
    def test_malformed_approved_content_is_reported_as_error(
        self, profile, guarded_native, scripted_http, fields
    ):
        result = self._invoke(
            profile, scripted_http, {**_evaluation("approve"), **fields}
        )

        assert "invalid" in result["error"].lower()
        assert "response" in result["error"].lower()


# ---------------------------------------------------------------------------
# Hook tests
# ---------------------------------------------------------------------------


class TestHooks:
    def test_on_session_start_creates_session(self, monkeypatch, profile):
        import hermes_intaris as mod

        monkeypatch.setenv("INTARIS_URL", "http://test:8060")
        monkeypatch.setenv("INTARIS_API_KEY", "test-key")
        monkeypatch.setenv("INTARIS_MCP_TOOLS", "false")
        profile.cfg = _resolve_config()
        profile.client = IntarisClient("http://test:8060", "test-key")

        with mock.patch.object(IntarisClient, "create_intention") as mock_create:
            mock_create.return_value = ApiResult(
                data={"session_id": "hm-123"}, status=200
            )
            _on_session_start = mod._on_session_start
            _on_session_start(
                profile, session_id="task-1", model="gpt-5", platform="cli"
            )

        state = profile.sessions.get("task-1")
        assert state is not None
        assert state.intaris_session_id is not None
        assert state.intaris_session_id.startswith("hm-")

    def test_on_session_end_signals_completion(self, monkeypatch, profile):
        import hermes_intaris as mod

        monkeypatch.setenv("INTARIS_URL", "http://test:8060")
        monkeypatch.setenv("INTARIS_API_KEY", "test-key")
        monkeypatch.setenv("INTARIS_MCP_TOOLS", "false")
        profile.cfg = _resolve_config()
        profile.client = IntarisClient("http://test:8060", "test-key")

        state = _get_or_create_state(profile, "task-1")
        state.intaris_session_id = "hm-test"
        state.call_count = 5
        state.approved_count = 4
        state.denied_count = 1

        with (
            mock.patch.object(IntarisClient, "update_status") as mock_status,
            mock.patch.object(IntarisClient, "submit_agent_summary") as mock_summary,
        ):
            mock_status.return_value = ApiResult(data={}, status=200)
            mock_summary.return_value = ApiResult(data={}, status=200)

            mod._on_session_end(profile, session_id="task-1", completed=True)

        mock_status.assert_called_once_with("hm-test", "completed")
        mock_summary.assert_called_once()
        summary_text = mock_summary.call_args[0][1]
        assert "5 tool calls" in summary_text

        # Session should be removed
        assert "task-1" not in profile.sessions

    def test_pre_llm_call_forwards_reasoning(self, monkeypatch, profile):
        import hermes_intaris as mod

        monkeypatch.setenv("INTARIS_URL", "http://test:8060")
        monkeypatch.setenv("INTARIS_API_KEY", "test-key")
        monkeypatch.setenv("INTARIS_MCP_TOOLS", "false")
        monkeypatch.setenv("INTARIS_SESSION_RECORDING", "false")
        profile.cfg = _resolve_config()
        profile.client = IntarisClient("http://test:8060", "test-key")

        state = _get_or_create_state(profile, "task-1")
        state.intaris_session_id = "hm-test"

        with mock.patch.object(IntarisClient, "submit_reasoning") as mock_reason:
            mock_reason.return_value = ApiResult(data={}, status=200)

            mod._on_pre_llm_call(
                profile,
                session_id="task-1",
                user_message="Fix the bug in main.py",
            )

        mock_reason.assert_called_once()
        content = mock_reason.call_args[0][1]
        assert "Fix the bug in main.py" in content
        assert state.intention_pending is True


# ---------------------------------------------------------------------------
# Register tests
# ---------------------------------------------------------------------------


class TestRegister:
    def test_register_wraps_tools(self, monkeypatch):
        """register() should wrap all existing tools in the registry."""
        monkeypatch.setenv("INTARIS_URL", "http://test:8060")
        monkeypatch.setenv("INTARIS_API_KEY", "test-key")
        monkeypatch.setenv("INTARIS_MCP_TOOLS", "false")

        # Pre-populate the fake registry with a tool
        original_handler = mock.MagicMock(return_value='{"ok": true}')
        _registry.register(
            name="test_tool",
            toolset="test",
            schema={"name": "test_tool", "parameters": {}},
            handler=original_handler,
            check_fn=None,
            requires_env=[],
            is_async=False,
            description="A test tool",
            emoji="",
        )

        # Create a mock plugin context
        ctx = mock.MagicMock(spec=["register_tool", "register_hook"])

        with mock.patch.object(IntarisClient, "list_mcp_tools", return_value=[]):
            register(ctx)

        # The tool should have been re-registered with a different handler
        entry = _registry._tools.get("test_tool")
        assert entry is not None
        assert entry.handler is not original_handler  # Wrapped

        # Hooks should be registered
        assert ctx.register_hook.call_count == 6
        hook_names = [call[0][0] for call in ctx.register_hook.call_args_list]
        assert "on_session_start" in hook_names
        assert "on_session_end" in hook_names
        assert "pre_llm_call" in hook_names
        assert "pre_tool_call" in hook_names
        assert "post_tool_call" in hook_names
        assert "post_llm_call" in hook_names
