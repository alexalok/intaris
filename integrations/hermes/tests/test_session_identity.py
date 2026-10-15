"""Invocation identity regressions using the real adapter and HTTP client."""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request

import hermes_intaris as plugin
import pytest
from hermes_intaris.client import IntarisClient


class _Transport:
    """Capture serialized HTTP requests without contacting an Intaris server."""

    def __init__(self) -> None:
        self.requests = []
        self.sessions = {}
        self.denied_sessions = set()
        self.barrier = None
        self.lock = threading.Lock()

    def __call__(self, request: Request, *, timeout: float) -> BytesIO:
        path = urlparse(request.full_url).path
        body = json.loads(request.data) if request.data else None
        with self.lock:
            self.requests.append((path, body))
            call_id = f"audit-{len(self.requests)}"
        if path == "/api/v1/intention":
            self.sessions[body["details"]["session_key"]] = body["session_id"]
            response = {"session_id": body["session_id"]}
        elif path == "/api/v1/mcp/tools":
            response = {"tools": [{"server": "files", "name": "read_file"}]}
        elif path in ("/api/v1/evaluate", "/api/v1/mcp/call"):
            if self.barrier:
                self.barrier.wait(timeout=5)
            denied = body["session_id"] in self.denied_sessions
            response = {
                "call_id": call_id,
                "decision": "deny" if denied else "approve",
                "reasoning": "Session policy denies this tool" if denied else "Allowed",
                "risk": "low",
                "path": "fast",
                "latency_ms": 1,
                "content": [{"type": "text", "text": "ok"}],
                "isError": False,
            }
        else:
            response = {"ok": True}
        stream = BytesIO(json.dumps(response).encode())
        stream.status = 200
        return stream


@pytest.fixture(params=["native", "mcp"])
def invocation(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[SimpleNamespace]:
    """Create sessions via lifecycle hooks, then expose either invocation path."""
    plugin._sessions.clear()
    monkeypatch.setattr(
        plugin, "_cfg", plugin.Config(mcp_tools=False, checkpoint_interval=0)
    )
    monkeypatch.setattr(
        plugin, "_client", IntarisClient("http://intaris.test", "test-key")
    )
    monkeypatch.setattr(plugin, "_mcp_tool_cache", None)
    monkeypatch.setattr(plugin, "_mcp_tool_cache_at", 0.0)
    transport = _Transport()
    monkeypatch.setattr("urllib.request.urlopen", transport)
    plugin._on_session_start(session_id="A")
    plugin._on_session_start(session_id="B")
    executions = []

    def original(args: dict[str, Any], **kwargs: Any) -> str:
        executions.append((args, kwargs))
        return json.dumps({"result": "ok"})

    if request.param == "native":
        handler = plugin._make_guarded_handler(original, "read_file", "files", False)
        endpoint = "/api/v1/evaluate"
        args_key = "args"
    else:
        registered = {}

        def register_tool(**kwargs: Any) -> None:
            registered[kwargs["name"]] = kwargs["handler"]

        plugin._register_mcp_tools(SimpleNamespace(register_tool=register_tool))
        handler = registered["files_read_file"]
        endpoint = "/api/v1/mcp/call"
        args_key = "arguments"

    transport.requests.clear()
    yield SimpleNamespace(
        kind=request.param,
        handler=handler,
        transport=transport,
        executions=executions,
        endpoint=endpoint,
        args_key=args_key,
    )
    plugin._sessions.clear()


def test_originating_session_overrides_insertion_order_and_task_id(
    invocation: SimpleNamespace,
) -> None:
    """An A call must not inherit B's policy, even when its task_id equals B."""
    args = {"path": "/tmp/a", "session_id": "B"}
    kwargs = {"session_id": "A", "task_id": "B", "user_task": "read A's file"}

    result = invocation.handler(args, **kwargs)

    assert json.loads(result) == {"result": "ok"}
    assert invocation.transport.requests == [
        (
            invocation.endpoint,
            {
                "session_id": invocation.transport.sessions["A"],
                "tool": "read_file",
                invocation.args_key: args,
                **({"server": "files"} if invocation.kind == "mcp" else {}),
            },
        )
    ]
    if invocation.kind == "native":
        assert invocation.executions == [(args, kwargs)]
        assert plugin._sessions["A"].call_count == 1
        assert plugin._sessions["B"].call_count == 0


def test_revisiting_session_keeps_its_identity(invocation: SimpleNamespace) -> None:
    for session_id in ("A", "B", "A"):
        plugin._on_pre_llm_call(session_id=session_id, user_message="Continue")
        assert json.loads(
            invocation.handler(
                {"path": "/tmp/file"}, session_id=session_id, task_id="shared-task"
            )
        ) == {"result": "ok"}

    calls = [
        body
        for path, body in invocation.transport.requests
        if path == invocation.endpoint
    ]
    assert [body["session_id"] for body in calls] == [
        invocation.transport.sessions["A"],
        invocation.transport.sessions["B"],
        invocation.transport.sessions["A"],
    ]
    assert list(plugin._sessions) == ["A", "B"]


@pytest.mark.parametrize(
    ("a_idle", "b_idle", "origin"),
    [(True, False, "A"), (False, True, "B"), (True, True, "A"), (True, True, "B")],
)
def test_idle_flags_cannot_select_another_session(
    invocation: SimpleNamespace, a_idle: bool, b_idle: bool, origin: str
) -> None:
    plugin._sessions["A"].is_idle = a_idle
    plugin._sessions["B"].is_idle = b_idle

    result = invocation.handler({}, session_id=origin, task_id="worker")

    assert json.loads(result) == {"result": "ok"}
    assert (
        invocation.transport.requests[0][1]["session_id"]
        == invocation.transport.sessions[origin]
    )


@pytest.mark.parametrize("fail_open", [False, True])
@pytest.mark.parametrize(
    "identity",
    [
        {},
        {"task_id": "A"},
        {"session_id": None, "task_id": "B"},
        {"session_id": ""},
        {"session_id": "   "},
        {"session_id": " A "},
        {"session_id": 1},
        {"session_id": {"session_id": "A"}},
        {"session_id": ["A", "B"]},
        {"session_id": "unknown", "task_id": "A"},
    ],
)
def test_unresolved_identity_blocks_without_side_effects(
    invocation: SimpleNamespace, fail_open: bool, identity: dict[str, Any]
) -> None:
    plugin._cfg.fail_open = fail_open

    result = invocation.handler({"session_id": "A", "path": "/tmp/file"}, **identity)

    assert "error" in json.loads(result)
    assert invocation.transport.requests == []
    assert invocation.executions == []
    assert all(state.call_count == 0 for state in plugin._sessions.values())


@pytest.mark.parametrize("state_case", ["single", "empty", "unbound", "completed"])
def test_missing_binding_never_borrows_remaining_session(
    invocation: SimpleNamespace, state_case: str
) -> None:
    plugin._cfg.fail_open = True
    if state_case == "empty":
        plugin._sessions.clear()
    elif state_case == "unbound":
        plugin._sessions["A"].intaris_session_id = None
    elif state_case == "completed":
        plugin._on_session_end(session_id="A")
    else:
        plugin._sessions.pop("A")
    invocation.transport.requests.clear()

    result = invocation.handler({}, session_id="A", task_id="B")

    assert "error" in json.loads(result)
    assert invocation.transport.requests == []
    assert invocation.executions == []


def test_deny_from_originating_session_cannot_use_other_sessions_approval(
    invocation: SimpleNamespace,
) -> None:
    invocation.transport.denied_sessions.add(invocation.transport.sessions["A"])

    result = invocation.handler({}, session_id="A", task_id="B")

    assert "DENIED" in json.loads(result)["error"]
    assert (
        invocation.transport.requests[0][1]["session_id"]
        == invocation.transport.sessions["A"]
    )
    assert invocation.executions == []


@pytest.mark.parametrize("caller", ["workers", "async"])
def test_concurrent_invocations_keep_explicit_identity(
    invocation: SimpleNamespace, caller: str
) -> None:
    invocation.transport.barrier = threading.Barrier(2)

    def call(session_id: str) -> str:
        return invocation.handler(
            {"path": session_id}, session_id=session_id, task_id="shared-task"
        )

    if caller == "workers":
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(call, ("A", "B")))
    else:

        async def run() -> list[str]:
            return await asyncio.gather(
                asyncio.to_thread(call, "A"), asyncio.to_thread(call, "B")
            )

        results = asyncio.run(run())

    assert [json.loads(result) for result in results] == [{"result": "ok"}] * 2
    assert {
        body[invocation.args_key]["path"]: body["session_id"]
        for path, body in invocation.transport.requests
        if path == invocation.endpoint
    } == invocation.transport.sessions
    if invocation.kind == "native":
        assert {
            args["path"]: kwargs["session_id"] for args, kwargs in invocation.executions
        } == {"A": "A", "B": "B"}


def test_tool_recordings_use_session_id_and_preserve_audit_correlation(
    invocation: SimpleNamespace,
) -> None:
    plugin._cfg.recording = True
    args = {"path": "/tmp/file"}
    identity = {"session_id": "A", "task_id": "B", "tool_call_id": "hermes-call"}
    plugin._on_pre_tool_call(tool_name="read_file", args=args, **identity)
    result = invocation.handler(args, session_id="A", task_id="B")
    plugin._on_post_tool_call(
        tool_name="read_file", args=args, result=result, **identity
    )
    plugin._flush_recording_buffer("A")
    plugin._flush_recording_buffer("B")

    records = [
        (path, body)
        for path, body in invocation.transport.requests
        if path.endswith("/events")
    ]
    assert len(records) == 1
    path, events = records[0]
    assert path == f"/api/v1/session/{invocation.transport.sessions['A']}/events"
    assert [event["type"] for event in events] == ["tool_call", "tool_result"]
    assert all(event["data"]["session_key"] == "A" for event in events)
    assert events[0]["data"]["call_id"] == "hermes-call"
    assert events[1]["data"]["output"] == result
    if invocation.kind == "native":
        assert events[1]["data"]["call_id"] == "audit-1"
        assert plugin._sessions["A"].pending_tool_results == []


def test_recording_hooks_never_fall_back_to_task_id(
    invocation: SimpleNamespace,
) -> None:
    plugin._cfg.recording = True
    plugin._on_pre_tool_call(tool_name="read_file", args={}, task_id="B")
    plugin._on_post_tool_call(tool_name="read_file", args={}, result="ok", task_id="B")
    plugin._flush_recording_buffer("A")
    plugin._flush_recording_buffer("B")

    assert invocation.transport.requests == []
