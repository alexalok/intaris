"""Exercise the real adapter with controlled Hermes and HTTP boundaries."""

from __future__ import annotations

import concurrent.futures
import contextvars
import json
import sys
import threading
import time
import types
from contextlib import contextmanager
from urllib.parse import urlsplit

import hermes_intaris as plugin
import pytest
from hermes_intaris.client import IntarisClient


@pytest.fixture
def host(monkeypatch):
    """Model the host's public, thread-scoped interrupt and wait contracts."""
    if "tools" not in sys.modules:
        monkeypatch.setitem(sys.modules, "tools", types.ModuleType("tools"))
    session_key = contextvars.ContextVar("test_approval_key", default="gateway-A")
    interrupted = set()
    pending = {}
    completed = {}
    started = {}
    lock = threading.Lock()
    runtime = types.SimpleNamespace(
        interrupted=interrupted,
        pending=pending,
        completed=completed,
        session_key=session_key,
        ceiling=360.0,
    )

    @contextmanager
    def window(key=None):
        key = key if key is not None else session_key.get()
        with lock:
            if not pending.get(key):
                started[key] = time.monotonic()
            pending[key] = pending.get(key, 0) + 1
        try:
            yield
        finally:
            with lock:
                pending[key] -= 1
                if not pending[key]:
                    completed[key] = (
                        completed.get(key, 0) + time.monotonic() - started[key]
                    )

    modules = {
        "tools.interrupt": {
            "is_interrupted": lambda: threading.get_ident() in interrupted
        },
        "tools.approval_context": {"get_current_session_key": session_key.get},
        "tools.approval_human_wait": {
            "human_wait_window": window,
            "human_wait_ceiling": lambda: runtime.ceiling,
            "HUMAN_WAIT_MARGIN_S": 60.0,
            "activity_heartbeat": lambda label: lambda: None,
        },
    }
    for name, attrs in modules.items():
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, module)
    return runtime


class Transport:
    """Only the urllib boundary is replaced; client, wrapper and pollers are real."""

    def __init__(
        self, mode="escalate", block="poll", decision="approve", redecision="approve"
    ):
        self.mode = mode
        self.block = block
        self.decision = decision
        self.redecision = redecision
        self.entered = threading.Event()
        self.release = threading.Event()
        self.exited = threading.Event()
        self.evaluations = 0

    @contextmanager
    def __call__(self, req, timeout):
        path = urlsplit(req.full_url).path
        if path == "/api/v1/evaluate":
            self.evaluations += 1
            point = "evaluate" if self.evaluations == 1 else "reevaluate"
            data = {"decision": self.redecision, "call_id": "c2"}
            if self.evaluations == 1:
                data = {"decision": self.mode, "call_id": "c1"}
                if self.mode == "suspended":
                    data.update(decision="deny", session_status="suspended")
        elif path.startswith("/api/v1/audit/"):
            point = "repoll" if self.mode == "suspended" else "poll"
            data = {"user_decision": self.decision}
        elif req.method == "GET" and path.startswith("/api/v1/session/"):
            point = "poll"
            data = {"status": "active" if self.decision == "approve" else "terminated"}
        elif path == "/api/v1/checkpoint":
            point, data = "checkpoint", {}
        elif req.method == "PATCH" and path.startswith("/api/v1/session/"):
            point, data = "update", {}
        else:
            point, data = "other", {}
        if point == self.block:
            self.entered.set()
            assert self.release.wait(8), "test did not release transport"
        try:
            yield types.SimpleNamespace(
                status=200, read=lambda: json.dumps(data).encode()
            )
        finally:
            if point == self.block:
                self.exited.set()


@pytest.fixture
def adapter(monkeypatch, host):
    plugin._sessions.clear()
    monkeypatch.setattr(
        plugin, "_cfg", plugin.Config(checkpoint_interval=0, mcp_tools=False)
    )
    monkeypatch.setattr(
        plugin, "_client", IntarisClient("http://intaris.test", "test-key")
    )
    state = plugin._get_or_create_state("session-A")
    state.intaris_session_id = "intaris-A"
    calls = []

    def original(args, **kwargs):
        calls.append((args, kwargs))
        return '{"result": "executed"}'

    handler = plugin._make_guarded_handler(original, "synthetic", "test", False)
    # Accelerate only the adapter's backoff, never sleeps in other code.
    monkeypatch.setattr(
        plugin,
        "time",
        types.SimpleNamespace(
            monotonic=time.monotonic,
            sleep=lambda seconds: None,
        ),
    )
    yield types.SimpleNamespace(handler=handler, calls=calls, state=state)
    plugin._sessions.clear()


@contextmanager
def invocation(adapter, transport, monkeypatch, session_id="session-A"):
    monkeypatch.setattr("urllib.request.urlopen", transport)
    result = []
    done = threading.Event()

    def run():
        try:
            result.append(
                adapter.handler({}, session_id=session_id, task_id="worker-task")
            )
        finally:
            done.set()

    thread = threading.Thread(
        target=contextvars.copy_context().run, args=(run,), daemon=True
    )
    thread.start()
    try:
        assert transport.entered.wait(4), "adapter did not reach controlled transport"
        yield types.SimpleNamespace(thread=thread, done=done, result=result)
    finally:
        transport.release.set()
        thread.join(6)
        assert not thread.is_alive(), "adapter worker leaked"


@pytest.mark.parametrize(
    "mode,block",
    [
        ("escalate", "poll"),
        ("suspended", "poll"),
        ("suspended", "reevaluate"),
        ("approve", "evaluate"),
    ],
)
def test_interrupt_during_transport_prevents_late_dispatch(
    adapter, host, monkeypatch, mode, block
):
    transport = Transport(mode, block)
    with invocation(adapter, transport, monkeypatch) as run:
        host.interrupted.add(run.thread.ident)
        assert run.done.wait(1), "interruption must release worker before HTTP returns"
        assert not adapter.calls
        assert "CANCELLED" in json.loads(run.result[0])["error"]
        assert not any(host.pending.values())
    assert not adapter.calls, "late HTTP approval must never execute original handler"


@pytest.mark.parametrize("mode", ["escalate", "suspended"])
def test_human_wait_registered_and_closed_on_approval(adapter, host, monkeypatch, mode):
    transport = Transport(mode)
    with invocation(adapter, transport, monkeypatch) as run:
        assert host.pending.get("gateway-A") == 1
        assert not run.done.is_set()
        transport.release.set()
        assert run.done.wait(1)
    assert len(adapter.calls) == 1
    assert host.pending["gateway-A"] == 0
    assert host.completed["gateway-A"] > 0


@pytest.mark.parametrize("mode", ["escalate", "suspended"])
def test_session_end_cancels_wait_before_completion_http(
    adapter, host, monkeypatch, mode
):
    transport = Transport(mode)
    with invocation(adapter, transport, monkeypatch) as run:
        # Another session becomes newest after this invocation started.
        other = plugin._get_or_create_state("session-B")
        other.intaris_session_id = "intaris-B"
        plugin._on_session_end("session-B")
        assert not run.done.is_set()
        plugin._on_session_end("session-A", completed=False)
        assert run.done.wait(1)
        assert "CANCELLED" in json.loads(run.result[0])["error"]
    assert not adapter.calls
    assert not any(host.pending.values())


@pytest.mark.parametrize("mode", ["escalate", "suspended"])
def test_timeout_while_transport_pending_fails_closed(adapter, host, monkeypatch, mode):
    plugin._cfg.escalation_timeout_s = 0.2
    transport = Transport(mode)
    with invocation(adapter, transport, monkeypatch) as run:
        assert run.done.wait(1), "adapter timeout must include pending HTTP"
        assert "TIMEOUT" in json.loads(run.result[0])["error"]
        assert not any(host.pending.values())
    assert not adapter.calls


@pytest.mark.parametrize("mode", ["escalate", "suspended"])
def test_denial_cleans_up_without_dispatch(adapter, host, monkeypatch, mode):
    transport = Transport(mode, decision="deny")
    with invocation(adapter, transport, monkeypatch) as run:
        transport.release.set()
        assert run.done.wait(1)
        assert "error" in json.loads(run.result[0])
    assert not adapter.calls
    assert not any(host.pending.values())


def test_interrupt_is_scoped_to_worker_and_session(adapter, host, monkeypatch):
    first, second = Transport(), Transport()
    with invocation(adapter, first, monkeypatch) as a:
        state_b = plugin._get_or_create_state("session-B")
        state_b.intaris_session_id = "intaris-B"
        token = host.session_key.set("gateway-B")
        try:
            with invocation(adapter, second, monkeypatch, "session-B") as b:
                host.interrupted.add(a.thread.ident)
                assert a.done.wait(1)
                assert not b.done.is_set()
                assert host.pending["gateway-A"] == 0
                assert host.pending["gateway-B"] == 1
                second.release.set()
                assert b.done.wait(1)
        finally:
            host.session_key.reset(token)
    assert [kwargs["session_id"] for _, kwargs in adapter.calls] == ["session-B"]


def test_unlimited_adapter_setting_still_honors_host_ceiling(
    adapter, host, monkeypatch
):
    host.ceiling = 60.2  # Host approvals.timeout=0.2 plus its 60s safety margin.
    with invocation(adapter, Transport(), monkeypatch) as run:
        assert run.done.wait(1)
        assert "TIMEOUT" in json.loads(run.result[0])["error"]
    assert not adapter.calls
    assert not any(host.pending.values())


@pytest.mark.parametrize("missing", ["tools.interrupt", "tools.approval_human_wait"])
def test_missing_host_support_returns_retry_without_waiting(
    adapter, monkeypatch, missing
):
    monkeypatch.setitem(sys.modules, missing, None)
    transport = Transport(block="never")
    monkeypatch.setattr("urllib.request.urlopen", transport)
    plugin._cfg.fail_open = True
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "Cannot safely wait" in result["error"]
    assert "retry" in result["error"]
    assert not adapter.calls


@pytest.mark.parametrize("mode", ["approve", "escalate", "suspended"])
def test_cancellation_rechecked_at_dispatch(adapter, host, monkeypatch, mode):
    transport = Transport(mode, block="never")
    monkeypatch.setattr("urllib.request.urlopen", transport)

    # Trigger after the real correlation is queued, before handler dispatch.
    queue_result = plugin._queue_pending_tool_result
    unrelated = {"tool": "other", "args": "{}", "call_id": "other-call"}
    adapter.state.pending_tool_results.append(unrelated)

    def cancel(*args):
        pending = queue_result(*args)
        host.interrupted.add(threading.get_ident())
        return pending

    monkeypatch.setattr(plugin, "_queue_pending_tool_result", cancel)
    plugin._cfg.fail_open = True
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "CANCELLED" in result["error"]
    assert not adapter.calls
    assert adapter.state.pending_tool_results == [unrelated]

    # A later identical invocation must record its own audit ID.
    host.interrupted.remove(threading.get_ident())
    monkeypatch.setattr(plugin, "_queue_pending_tool_result", queue_result)
    plugin._cfg.recording = True
    result = adapter.handler({}, session_id="session-A")
    plugin._on_post_tool_call(
        tool_name="synthetic", args={}, result=result, session_id="session-A"
    )
    assert len(adapter.calls) == 1
    assert adapter.state.recording_buffer[-1]["data"]["call_id"] == "c2"
    assert adapter.state.pending_tool_results == [unrelated]


def test_transport_failure_does_not_override_cancellation_with_fail_open(
    adapter, host, monkeypatch
):
    def failing(req, timeout):
        adapter.state._ended.set()
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", failing)
    plugin._cfg.fail_open = True
    result = json.loads(adapter.handler({}, session_id="session-A"))
    assert "CANCELLED" in result["error"]
    assert not adapter.calls


def test_resume_does_not_revive_cancelled_wait(adapter, host, monkeypatch):
    with invocation(adapter, Transport(), monkeypatch) as run:
        plugin._on_session_end("session-A", completed=False)
        plugin._on_pre_llm_call(session_id="session-A", user_message="continue")
        assert run.done.wait(1)
        assert "CANCELLED" in json.loads(run.result[0])["error"]
    assert not adapter.calls
    assert not adapter.state._ended.is_set()


def test_reactivation_then_escalation_still_honors_interruption(
    adapter, host, monkeypatch
):
    transport = Transport("suspended", block="repoll", redecision="escalate")
    with invocation(adapter, transport, monkeypatch) as run:
        assert host.pending["gateway-A"] == 1
        host.interrupted.add(run.thread.ident)
        assert run.done.wait(1)
        assert "CANCELLED" in json.loads(run.result[0])["error"]
        assert not any(host.pending.values())
    assert not adapter.calls


@pytest.mark.parametrize("block", ["checkpoint", "update"])
def test_interrupt_during_other_predispatch_http_does_not_park_worker(
    adapter, host, monkeypatch, block
):
    plugin._cfg.checkpoint_interval = 1 if block == "checkpoint" else 0
    adapter.state.call_count = 2  # Triggers the existing intention update path.
    with invocation(adapter, Transport("approve", block=block), monkeypatch) as run:
        host.interrupted.add(run.thread.ident)
        assert run.done.wait(1), "all pre-dispatch transport must remain cancellable"
    assert not adapter.calls


def test_approval_budget_spans_reactivation_and_reevaluation(
    adapter, host, monkeypatch
):
    import hermes_intaris.waits as waits

    clock = types.SimpleNamespace(now=0.0)
    monkeypatch.setattr(
        waits, "time", types.SimpleNamespace(monotonic=lambda: clock.now)
    )
    plugin._cfg.escalation_timeout_s = 10
    with invocation(
        adapter, Transport("suspended", block="reevaluate"), monkeypatch
    ) as run:
        assert host.pending["gateway-A"] == 0, "re-evaluation is not a human wait"
        clock.now = 11
        assert run.done.wait(1)
        assert "TIMEOUT" in json.loads(run.result[0])["error"]
    assert not adapter.calls


def test_session_eviction_cancels_pending_wait(adapter, host, monkeypatch):
    monkeypatch.setattr(plugin, "MAX_SESSIONS", 1)
    with invocation(adapter, Transport(), monkeypatch) as run:
        plugin._get_or_create_state("session-B")
        assert run.done.wait(1), "eviction must not orphan a session lifetime"
        assert "CANCELLED" in json.loads(run.result[0])["error"]
    assert not adapter.calls


def test_interrupt_during_poll_backoff_releases_accounting(adapter, host, monkeypatch):
    from hermes_intaris.waits import Invocation

    sleeping = threading.Event()
    original_sleep = Invocation.sleep

    def sleep(inv, seconds):
        sleeping.set()
        original_sleep(inv, seconds)

    monkeypatch.setattr(Invocation, "sleep", sleep)
    transport = Transport(decision=None)
    with invocation(adapter, transport, monkeypatch) as run:
        transport.release.set()
        assert sleeping.wait(1)
        host.interrupted.add(run.thread.ident)
        assert run.done.wait(1)
        assert "CANCELLED" in json.loads(run.result[0])["error"]
    assert not adapter.calls
    assert not any(host.pending.values())


def test_exception_unwinds_human_wait_accounting(adapter, host, monkeypatch):
    class TransportStopped(BaseException):
        pass

    transport = Transport(block="never")

    def request(req, timeout):
        if "/audit/" in req.full_url:
            raise TransportStopped("test transport stopped")
        return transport(req, timeout)

    monkeypatch.setattr("urllib.request.urlopen", request)
    with pytest.raises(TransportStopped):
        adapter.handler({}, session_id="session-A")
    assert not adapter.calls
    assert not any(host.pending.values())


@pytest.fixture
def runtime(host, monkeypatch):
    from .hermes_runtime import load_runtime

    return load_runtime(monkeypatch)


@contextmanager
def host_worker(adapter, transport, runtime, monkeypatch):
    from .hermes_runtime import agent_stub

    monkeypatch.setattr("urllib.request.urlopen", transport)
    agent = agent_stub()
    gate = runtime._ConcurrentToolAuthorizationGate(session_key="gateway-A")

    def run():
        with runtime._registered_tool_worker(agent):
            return adapter.handler({}, session_id="session-A")

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(contextvars.copy_context().run, run)
    try:
        assert transport.entered.wait(4)
        yield agent, gate, future
    finally:
        transport.release.set()
        future.result(timeout=4)
        pool.shutdown()


@pytest.mark.parametrize("path", ["sequential", "parallel"])
@pytest.mark.parametrize("mode", ["escalate", "suspended"])
def test_real_host_excludes_human_wait_from_tool_budget(
    adapter, runtime, monkeypatch, path, mode
):
    from .hermes_runtime import await_host

    transport = Transport(mode)
    with host_worker(adapter, transport, runtime, monkeypatch) as (agent, gate, future):
        runtime.clock.now = 100  # Ordinary tool budget is only 10s.
        # Release the answer ONLY when host reaches its wait-for-result branch.
        # Without human accounting it returns timeout before reaching this point.
        if path == "sequential":
            original_result = future.result

            def result(timeout=None):
                transport.release.set()
                return original_result(timeout)

            monkeypatch.setattr(future, "result", result)
        else:
            original_wait = concurrent.futures.wait

            def wait(*args, **kwargs):
                transport.release.set()
                return original_wait(*args, **kwargs)

            monkeypatch.setattr(concurrent.futures, "wait", wait)
        assert await_host(runtime, path, agent, future, gate, deadline=10)
    assert len(adapter.calls) == 1
    assert runtime.human.human_wait_seconds("gateway-A") == 100
    assert runtime.human.human_wait_seconds("gateway-B") == 0
    assert runtime.human._human_wait_states["gateway-A"].pending == 0
    assert not agent._tool_worker_threads
    assert not runtime.interrupt._interrupted_threads


@pytest.mark.parametrize("path", ["sequential", "parallel"])
@pytest.mark.parametrize(
    "mode,block",
    [
        ("escalate", "poll"),
        ("suspended", "poll"),
        ("approve", "evaluate"),
    ],
)
def test_real_host_abandonment_then_late_approval_never_dispatches(
    adapter,
    runtime,
    monkeypatch,
    path,
    mode,
    block,
):
    from .hermes_runtime import await_host

    transport = Transport(mode, block)
    with host_worker(adapter, transport, runtime, monkeypatch) as (agent, gate, future):
        runtime.clock.now = 1000  # Past even the host's bounded wait exclusion.
        assert not await_host(runtime, path, agent, future, gate, deadline=10)
        assert "CANCELLED" in json.loads(future.result(timeout=1))["error"]
        assert not adapter.calls
        assert all(
            state.pending == 0 for state in runtime.human._human_wait_states.values()
        )
        transport.release.set()
        assert transport.exited.wait(1)
    assert not adapter.calls
    assert not agent._tool_worker_threads
    assert not runtime.interrupt._interrupted_threads


@pytest.mark.parametrize("path", ["sequential", "parallel"])
def test_staggered_waiters_share_host_window_budget(
    adapter, runtime, monkeypatch, path
):
    import hermes_intaris.waits as waits

    from .hermes_runtime import await_host

    monkeypatch.setattr(waits, "time", runtime.clock)
    first, second = Transport(), Transport()
    with host_worker(adapter, first, runtime, monkeypatch) as (_, gate, a):
        runtime.clock.now = 150
        with host_worker(adapter, second, runtime, monkeypatch) as (agent, _, b):
            assert runtime.human._human_wait_states["gateway-A"].pending == 2
            runtime.clock.now = 250
            first.release.set()
            assert json.loads(a.result(timeout=1)) == {"result": "executed"}
            assert runtime.human._human_wait_states["gateway-A"].pending == 1
            runtime.clock.now = 301
            # Second waiter gets the remaining shared allowance, not a new 300s.
            assert "TIMEOUT" in json.loads(b.result(timeout=1))["error"]
            # Host's 30s active-tool budget has not been consumed by the wait.
            assert await_host(runtime, path, agent, b, gate, deadline=30)
    assert len(adapter.calls) == 1
    assert runtime.human._human_wait_states["gateway-A"].pending == 0
