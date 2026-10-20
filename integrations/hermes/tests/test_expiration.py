"""Native approval retirement through real wrappers, polls and urllib requests."""

from __future__ import annotations

import asyncio
import io
import json
import threading
import types
import urllib.error
from contextlib import contextmanager
from dataclasses import replace
from urllib.parse import urlsplit

import hermes_intaris as plugin
import pytest
from hermes_intaris.client import IntarisClient

from . import test_waits

host = test_waits.host
adapter = test_waits.adapter
invocation = test_waits.invocation


class Transport:
    """Control only HTTP, retaining the adapter's actual dispatch/cancel paths."""

    def __init__(self, *, block="poll", evaluation="escalate", poll=None):
        self.block = block
        self.evaluation = evaluation
        self.evaluation_fields = {}
        self.poll = {"user_decision": "approve"} if poll is None else poll
        self.entered = threading.Event()
        self.release = threading.Event()
        self.exited = threading.Event()
        self.expire_entered = threading.Event()
        self.expire_release = threading.Event()
        self.expire_release.set()
        self.requests = []
        self.condition = threading.Condition()
        self.expire_errors = []
        self.mcp_decision = "escalate"

    @property
    def expirations(self):
        return [r for r in self.requests if r["path"].endswith("/expire")]

    @property
    def evaluations(self):
        return [r for r in self.requests if r["path"] == "/api/v1/evaluate"]

    def wait_expirations(self, count=1):
        with self.condition:
            return self.condition.wait_for(lambda: len(self.expirations) >= count, 2)

    def __call__(self, req, timeout):
        path = urlsplit(req.full_url).path
        body = json.loads(req.data) if req.data else None
        with self.condition:
            self.requests.append(
                dict(
                    path=path,
                    body=body,
                    url=req.full_url,
                    method=req.method,
                    headers=dict(req.header_items()),
                    timeout=timeout,
                    thread=threading.get_ident(),
                )
            )
            self.condition.notify_all()
        if path.endswith("/expire"):
            self.expire_entered.set()
            assert self.expire_release.wait(5), "cleanup transport not released"
            if self.expire_errors:
                error = self.expire_errors.pop(0)
                if isinstance(error, int):
                    raise urllib.error.HTTPError(
                        req.full_url, error, "failure", {}, io.BytesIO(b"{}")
                    )
                if isinstance(error, Exception):
                    raise error
                if isinstance(error, bytes):
                    return self.response(error)
            return self.response(
                {
                    "call_id": path.split("/")[-2],
                    "session_id": body["session_id"],
                    "expired_at": "2026-10-18T10:00:00Z",
                    "expiration_reason": body["reason"],
                }
            )
        if path == "/api/v1/evaluate":
            number = len(self.evaluations)
            point = "evaluate" if number == 1 else "reevaluate"
            if self.evaluation == "suspended" and number == 1:
                data = {
                    "decision": "deny",
                    "session_status": "suspended",
                    "call_id": "denied",
                }
            else:
                decision = (
                    "escalate" if self.evaluation == "suspended" else self.evaluation
                )
                data = {"decision": decision, "call_id": f"c{number}"}
                data.update(self.evaluation_fields)
        elif path.startswith("/api/v1/audit/"):
            point, data = "poll", self.poll
        elif path == "/api/v1/mcp/tools":
            point, data = "tools", {"tools": [{"server": "files", "name": "write"}]}
        elif path == "/api/v1/mcp/call":
            point, data = (
                "mcp",
                {
                    "decision": self.mcp_decision,
                    "call_id": "mcp-c1",
                    "content": [{"type": "text", "text": "executed"}],
                },
            )
        else:
            point, data = "other", {"status": "active"}
        if point == self.block:
            self.entered.set()
            assert self.release.wait(5), "evaluation/poll transport not released"
        self.exited.set()
        if isinstance(data, int):
            raise urllib.error.HTTPError(
                req.full_url, data, "failure", {}, io.BytesIO(b"{}")
            )
        if isinstance(data, Exception):
            raise data
        return self.response(data)

    @staticmethod
    def response(data):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        response = io.BytesIO(body)
        response.status = 200
        return response


def drain_cleanup():
    """Keep detached cleanup inside each test's HTTP boundary."""
    for thread in threading.enumerate():
        if thread.name == "intaris-expire":
            thread.join(5)
            assert not thread.is_alive(), "expiration cleanup leaked"


@pytest.fixture
def boundary(monkeypatch):
    transport = Transport()
    monkeypatch.setattr("urllib.request.urlopen", transport)
    yield transport
    transport.release.set()
    transport.expire_release.set()
    drain_cleanup()


def assert_retired(transport, reason, call_id="c1", session_id="intaris-A"):
    assert transport.wait_expirations(), "undispatched escalation was not retired"
    drain_cleanup()
    assert len(transport.expirations) == 1
    req = transport.expirations[0]
    assert req["method"] == "POST"
    assert req["path"] == f"/api/v1/audit/{call_id}/expire"
    assert req["body"] == {"session_id": session_id, "reason": reason}
    assert req["timeout"] <= 2
    return req


def test_timeout_reports_expiration_without_waiting_for_cleanup(
    adapter, host, monkeypatch, boundary
):
    adapter.profile.cfg = replace(adapter.profile.cfg, escalation_timeout_s=0.1)
    boundary.expire_release.clear()
    with invocation(adapter, boundary, monkeypatch) as run:
        assert run.done.wait(1), "HTTP cleanup must not park Hermes worker"
        assert "TIMEOUT" in json.loads(run.result[0])["error"]
        assert boundary.expire_entered.wait(1), "timeout left pending approval behind"
        assert not adapter.calls
        assert not any(host.pending.values())
        assert boundary.expirations[0]["thread"] != run.thread.ident
        boundary.expire_release.set()
    assert_retired(boundary, "timeout")
    assert len(boundary.evaluations) == 1
    assert not adapter.calls, "late approval must never dispatch an expired invocation"


@pytest.mark.parametrize("stop", ["interrupt", "session_end"])
def test_cancelled_wait_reports_original_session(
    adapter, host, monkeypatch, boundary, stop
):
    with invocation(adapter, boundary, monkeypatch) as run:
        other = plugin._get_or_create_state(adapter.profile, "session-B")
        other.intaris_session_id = "intaris-B"
        if stop == "interrupt":
            host.interrupted.add(run.thread.ident)
        else:
            plugin._on_session_end(adapter.profile, "session-A", completed=False)
        assert run.done.wait(1)
        assert "CANCELLED" in json.loads(run.result[0])["error"]
        assert_retired(boundary, "cancelled")
    assert not adapter.calls
    assert len(boundary.evaluations) == 1


def test_active_approval_dispatches_once_without_expiration(
    adapter, host, monkeypatch, boundary
):
    with invocation(adapter, boundary, monkeypatch) as run:
        assert host.pending["gateway-A"] == 1
        assert not run.done.is_set()
        assert not boundary.expirations
        boundary.release.set()
        assert run.done.wait(1)
        assert json.loads(run.result[0]) == {"result": "executed"}
    drain_cleanup()
    assert len(adapter.calls) == 1
    assert not boundary.expirations
    assert len(boundary.evaluations) == 1


@pytest.mark.parametrize("decision", ["approve", "deny", None])
def test_already_expired_audit_is_distinct_from_denial(adapter, boundary, decision):
    adapter.profile.cfg = replace(adapter.profile.cfg, escalation_timeout_s=0.1)
    boundary.block = "never"
    boundary.poll = {
        "user_decision": decision,
        "expired_at": "2026-10-18T10:00:00Z",
        "expiration_reason": "timeout",
    }
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "EXPIRED" in result["error"]
    assert "DENIED" not in result["error"]
    assert not adapter.calls
    drain_cleanup()
    assert not boundary.expirations


@pytest.mark.parametrize(
    "poll",
    [
        b"{",
        {},
        {"user_decision": "unexpected"},
        {"user_decision": "approve", "expired_at": False},
        403,
    ],
)
def test_failed_or_malformed_poll_retires_known_escalation(adapter, boundary, poll):
    boundary.block, boundary.poll = "never", poll
    adapter.profile.cfg = replace(
        adapter.profile.cfg, escalation_timeout_s=0.2, fail_open=True
    )
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "error" in result
    assert not adapter.calls
    assert_retired(boundary, "abandoned")


def test_source_changed_after_approval_retires_undispatched_call(
    adapter, host, monkeypatch, boundary
):
    source = types.SimpleNamespace(
        name="synthetic",
        handler=lambda *_a, **_kw: adapter.calls.append("executed"),
        toolset="test",
        is_async=False,
    )
    current = [source]
    registry = types.SimpleNamespace(get_entry=lambda *a, **kw: current[0])
    adapter.handler = plugin._make_dispatch_entry(
        adapter.profile, registry, source, "test"
    ).handler
    with invocation(adapter, boundary, monkeypatch) as run:
        current[0] = object()
        boundary.release.set()
        assert run.done.wait(1)
        assert "registration changed" in json.loads(run.result[0])["error"]
    assert not adapter.calls
    assert_retired(boundary, "abandoned")


def test_cancel_after_approved_poll_before_dispatch_retires_approval(
    adapter, host, monkeypatch, boundary
):
    boundary.block = "never"
    queue_result = plugin._queue_pending_tool_result

    def cancel(*args):
        pending = queue_result(*args)
        host.interrupted.add(threading.get_ident())
        return pending

    monkeypatch.setattr(plugin, "_queue_pending_tool_result", cancel)
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "CANCELLED" in result["error"]
    assert not adapter.calls
    assert not adapter.state.pending_tool_results
    assert_retired(boundary, "cancelled")


@pytest.mark.parametrize(
    "decision,requires_expiration,retire",
    [
        ("approve", None, False),
        ("deny", None, False),
        ("escalate", None, True),
        ("approve", True, True),
        ("approve", "true", False),
        ("deny", True, False),
    ],
)
def test_late_evaluate_only_retires_known_escalation_with_captured_client(
    adapter, host, monkeypatch, boundary, decision, requires_expiration, retire
):
    boundary.block, boundary.evaluation = "evaluate", decision
    if requires_expiration is not None:
        boundary.evaluation_fields["requires_expiration"] = requires_expiration
    original_client = IntarisClient(
        "http://original.test", "original-key", "original-user", "original-agent"
    )
    adapter.profile.client = original_client
    with invocation(adapter, boundary, monkeypatch) as run:
        host.interrupted.add(run.thread.ident)
        assert run.done.wait(1)
        assert not boundary.expirations, "no call_id known until evaluate completes"
        adapter.state.intaris_session_id = "replacement-session"
        adapter.profile.client = IntarisClient("http://replacement.test", "other-key")
        boundary.release.set()
        assert boundary.exited.wait(1)
        if retire:
            req = assert_retired(boundary, "cancelled")
            assert req["url"].startswith("http://original.test/")
            assert req["headers"]["Authorization"] == "Bearer original-key"
            assert req["headers"]["X-user-id"] == "original-user"
            assert req["headers"]["X-agent-id"] == "original-agent"
    drain_cleanup()
    assert not adapter.calls
    assert len(boundary.evaluations) == 1
    if not retire:
        assert not boundary.expirations


def test_late_reevaluation_after_timeout_retires_second_call(
    adapter, monkeypatch, boundary
):
    boundary.block, boundary.evaluation = "reevaluate", "suspended"
    adapter.profile.cfg = replace(adapter.profile.cfg, escalation_timeout_s=0.1)
    with invocation(adapter, boundary, monkeypatch) as run:
        assert run.done.wait(1)
        assert "TIMEOUT" in json.loads(run.result[0])["error"]
        boundary.release.set()
        assert_retired(boundary, "timeout", call_id="c2")
    assert not adapter.calls
    assert len(boundary.evaluations) == 2


@pytest.mark.parametrize(
    "decision,poll", [("deny", "approve"), ("escalate", "deny"), ("approve", "approve")]
)
def test_denials_and_direct_approvals_are_not_retired(
    adapter, boundary, decision, poll
):
    boundary.block, boundary.evaluation = "never", decision
    boundary.poll = {"user_decision": poll}
    adapter.handler({}, session_id="session-A")
    drain_cleanup()
    assert len(adapter.calls) == (decision == "approve")
    assert not boundary.expirations


@pytest.mark.parametrize(
    "error", [404, OSError("offline"), b"not json", b"{}", b'{"expired_at":null}']
)
def test_cleanup_failure_never_retries_execution_and_is_logged(
    adapter, monkeypatch, boundary, caplog, error
):
    adapter.profile.cfg = replace(
        adapter.profile.cfg, escalation_timeout_s=0.1, fail_open=True
    )
    boundary.expire_errors = [error] * 5
    with invocation(adapter, boundary, monkeypatch) as run:
        assert run.done.wait(1)
        assert "TIMEOUT" in json.loads(run.result[0])["error"]
        assert boundary.wait_expirations()
        drain_cleanup()
    assert not adapter.calls
    assert len(boundary.evaluations) == 1
    assert 1 <= len(boundary.expirations) <= 3
    if error == 404:
        assert len(boundary.expirations) == 1
        assert "compatib" in caplog.text.lower() or "unsupported" in caplog.text.lower()
    assert "expir" in caplog.text.lower()


def test_transient_cleanup_failure_retries_same_expiration(
    adapter, monkeypatch, boundary
):
    adapter.profile.cfg = replace(adapter.profile.cfg, escalation_timeout_s=0.1)
    boundary.expire_errors = [503, OSError("offline")]
    with invocation(adapter, boundary, monkeypatch) as run:
        assert run.done.wait(1)
        assert boundary.wait_expirations(3)
        drain_cleanup()
    assert len(boundary.expirations) == 3
    assert all(
        req["body"] == {"session_id": "intaris-A", "reason": "timeout"}
        for req in boundary.expirations
    )
    assert len(boundary.evaluations) == 1
    assert not adapter.calls


def test_mcp_escalation_stays_available_for_retry_and_session_end(adapter, boundary):
    boundary.block = "never"
    registered = {}
    plugin._register_mcp_tools(
        adapter.profile,
        types.SimpleNamespace(
            register_tool=lambda **kw: registered.update({kw["name"]: kw["handler"]})
        ),
    )
    handler = registered["files_write"]
    result = json.loads(handler({}, session_id="session-A"))
    assert "ESCALATED" in result["error"]
    assert "retry" in result["error"]
    drain_cleanup()
    assert not boundary.expirations
    boundary.mcp_decision = "approve"
    assert json.loads(handler({}, session_id="session-A")) == {"result": "executed"}
    boundary.mcp_decision = "escalate"
    handler({}, session_id="session-A")
    plugin._on_session_end(adapter.profile, "session-A", completed=False)
    drain_cleanup()
    assert not boundary.expirations
    assert not boundary.evaluations
    assert not any(
        req["path"].startswith("/api/v1/audit/") for req in boundary.requests
    )


@pytest.mark.parametrize("terminal", ["deny", "expired"])
def test_terminal_audit_observed_before_cancellation_is_not_retired(
    adapter, host, monkeypatch, boundary, terminal
):
    from hermes_intaris.waits import Invocation

    boundary.block = "never"
    boundary.poll = {"user_decision": "deny"}
    if terminal == "expired":
        boundary.poll.update(
            expired_at="2026-10-18T10:00:00Z", expiration_reason="timeout"
        )
    wait = Invocation.human_wait

    @contextmanager
    def cancel_on_exit(inv, label):
        with wait(inv, label) as heartbeat:
            yield heartbeat
            host.interrupted.add(threading.get_ident())

    monkeypatch.setattr(Invocation, "human_wait", cancel_on_exit)
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "error" in result
    assert not adapter.calls
    drain_cleanup()
    assert not boundary.expirations, "observed denial/expiration is already terminal"


def test_evaluation_ready_at_cancellation_handoff_is_retired_once(
    adapter, monkeypatch, boundary
):
    boundary.block = "never"

    def request(req, timeout):
        response = boundary(req, timeout)
        if urlsplit(req.full_url).path == "/api/v1/evaluate":
            read = response.read

            def read_and_cancel():
                body = read()
                adapter.state._ended.set()
                return body

            response.read = read_and_cancel
        return response

    monkeypatch.setattr("urllib.request.urlopen", request)
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "CANCELLED" in result["error"]
    assert_retired(boundary, "cancelled")
    assert not adapter.calls


def test_cleanup_queues_parallel_batch_without_parking_invocations(
    adapter, host, monkeypatch, boundary, caplog
):
    boundary.block = "never"
    boundary.poll = b"invalid json"
    boundary.expire_release.clear()
    result = []
    done = threading.Event()

    def run():
        try:
            for _ in range(12):
                result.append(adapter.handler({}, session_id="session-A"))
        finally:
            done.set()

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        assert done.wait(1), "cleanup capacity must not block Hermes admission"
        assert len(result) == 12
        assert all("error" in json.loads(value) for value in result)
        assert "capacity" not in caplog.text.lower()
        assert len(boundary.expirations) <= 4
        assert not adapter.calls
    finally:
        boundary.expire_release.set()
        worker.join(2)
        drain_cleanup()
    assert len(boundary.expirations) == 12, (
        "normal parallel batches must not lose retirement reports"
    )
    assert {req["path"] for req in boundary.expirations} == {
        f"/api/v1/audit/c{i}/expire" for i in range(1, 13)
    }


def test_dispatched_handler_failure_is_not_reported_as_abandoned(adapter, boundary):
    boundary.block = "never"

    def original(*args, **kwargs):
        adapter.calls.append("started")
        raise RuntimeError("handler failed after starting")

    adapter.handler = plugin._make_guarded_handler(
        adapter.profile, original, "synthetic", "test", False
    )
    with pytest.raises(RuntimeError, match="handler failed"):
        adapter.handler({}, session_id="session-A")
    drain_cleanup()
    assert adapter.calls == ["started"]
    assert not boundary.expirations


@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.parametrize("callable_object", [False, True])
@pytest.mark.parametrize("inline_approval", [False, True])
def test_async_dispatch_rechecks_lifetime_before_entering_handler(
    adapter, boundary, cancel, callable_object, inline_approval
):
    boundary.block = "never"
    if inline_approval:
        boundary.evaluation = "approve"
        boundary.evaluation_fields["requires_expiration"] = True

    async def original(*args, **kwargs):
        adapter.calls.append("entered")
        return '{"result": "executed"}'

    if callable_object:

        class AsyncTool:
            async def __call__(self, *args, **kwargs):
                return await original(*args, **kwargs)

        target = AsyncTool()
    else:
        target = original
    handler = plugin._make_guarded_handler(
        adapter.profile, target, "synthetic", "test", True
    )
    # The public async wrapper awaits this synchronous guard's returned lifetime.
    # Control that exact handoff without replacing evaluation, polling or dispatch.
    pending = handler.__wrapped__({}, session_id="session-A")
    assert not adapter.calls
    if cancel:
        adapter.state._ended.set()
    result = json.loads(asyncio.run(pending))
    if cancel:
        assert "CANCELLED" in result["error"]
        assert not adapter.calls
        assert_retired(boundary, "cancelled")
        assert not adapter.state.pending_tool_results
    else:
        assert result == {"result": "executed"}
        assert adapter.calls == ["entered"]
        drain_cleanup()
        assert not boundary.expirations


def test_async_cancellation_after_handler_entry_keeps_native_semantics(
    adapter, boundary
):
    boundary.block = "never"

    async def run():
        entered = asyncio.Event()

        async def original(*args, **kwargs):
            adapter.calls.append("entered")
            entered.set()
            await asyncio.Event().wait()

        handler = plugin._make_guarded_handler(
            adapter.profile, original, "synthetic", "test", True
        )
        task = asyncio.create_task(handler({}, session_id="session-A"))
        await asyncio.wait_for(entered.wait(), timeout=1)
        adapter.state._ended.set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    drain_cleanup()
    assert adapter.calls == ["entered"]
    assert not boundary.expirations


@pytest.mark.parametrize("inline_approval", [False, True])
def test_async_task_cancel_requested_during_approval_prevents_body_entry(
    adapter, boundary, monkeypatch, inline_approval
):
    boundary.block = "never"
    if inline_approval:
        boundary.evaluation = "approve"
        boundary.evaluation_fields["requires_expiration"] = True

    async def original(*args, **kwargs):
        adapter.calls.append("entered")
        return '{"result": "executed"}'

    async def run():
        loop = asyncio.get_running_loop()
        task = None

        def request(req, timeout):
            response = boundary(req, timeout)
            if (inline_approval and req.full_url.endswith("/evaluate")) or (
                not inline_approval
                and req.method == "GET"
                and "/audit/" in req.full_url
            ):
                loop.call_soon_threadsafe(task.cancel)
            return response

        monkeypatch.setattr("urllib.request.urlopen", request)
        handler = plugin._make_guarded_handler(
            adapter.profile, original, "synthetic", "test", True
        )
        task = asyncio.create_task(handler({}, session_id="session-A"))
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert not adapter.calls
    assert_retired(boundary, "cancelled")


@pytest.mark.parametrize("call_id", [None, "", " "])
def test_inline_approval_without_retirement_id_blocks_dispatch(
    adapter, boundary, call_id
):
    boundary.block, boundary.evaluation = "never", "approve"
    boundary.evaluation_fields = {"requires_expiration": True, "call_id": call_id}
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "Invalid" in result["error"]
    assert not adapter.calls
    assert not boundary.expirations
