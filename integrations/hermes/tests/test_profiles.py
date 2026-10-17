"""Profile isolation at the Hermes and HTTP boundaries.

Set HERMES_SOURCE to a Hermes checkout to exercise its real ContextVar API
and ToolRegistry. The default doubles implement those same scoped contracts.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import importlib
import inspect
import io
import json
import os
import sys
import threading
import types
from concurrent.futures import ThreadPoolExecutor
from functools import partial, wraps
from pathlib import Path

import hermes_intaris as plugin
import pytest


class ScopedRegistry:
    def __init__(self, home):
        self.home = home
        self._lock = threading.RLock()
        self._tools = {}
        self.scoped = {}

    def register(self, *, name, scope=None, override=False, **kwargs):
        target = self._tools if scope is None else self.scoped.setdefault(scope, {})
        target[name] = types.SimpleNamespace(name=name, **kwargs)

    def get_all_entries(self):
        return list({**self._tools, **self.scoped.get(str(self.home()), {})}.values())

    def get_entry(self, name, scope=None):
        return {**self._tools, **self.scoped.get(scope or str(self.home()), {})}.get(
            name
        )

    def snapshot_registration(self, name, scope=None):
        return self.scoped.get(scope, {}).get(name)

    def dispatch(self, name, args, **kwargs):
        entry = self.get_entry(name)
        parameters = inspect.signature(entry.handler).parameters
        if not any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()
        ):
            kwargs = {k: v for k, v in kwargs.items() if k in parameters}
        result = entry.handler(args, **kwargs)
        return asyncio.run(result) if entry.is_async else result

    def restore_registration(self, name, current, previous, scope=None):
        target = self._tools if scope is None else self.scoped[scope]
        if target.get(name) is current:
            if previous is None:
                target.pop(name)
            else:
                target[name] = previous


class Handle:
    def __init__(self, release):
        self.release = release
        self.active = True

    def dispose(self):
        if self.active:
            self.active = False
            self.release()


class ToolHandle(Handle):
    """Model Hermes leases that skip retired predecessor generations."""

    def __init__(self, registry, home, name, previous, current):
        self.previous, self.current = previous, current
        leases = getattr(registry, "test_leases", [])
        registry.test_leases = leases
        self.predecessor = next(
            (handle for handle in reversed(leases) if handle.current is previous), None
        )
        leases.append(self)

        def release():
            entry, predecessor = self.previous, self.predecessor
            while predecessor is not None and not predecessor.active:
                entry, predecessor = predecessor.previous, predecessor.predecessor
            registry.restore_registration(name, current, entry, scope=home)

        super().__init__(release)


class Context:
    """Only the supported PluginContext calls used by this adapter."""

    def __init__(self, registry, home, settings=None):
        self.registry = registry
        self.home = str(home)
        self.settings = settings or {}
        self.hooks = {}
        self.middleware = {}
        self.unload = []

    def has_capability(self, name):
        return name == "tools.override"

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_tool(self, **kwargs):
        name = kwargs["name"]
        previous = self.registry.snapshot_registration(name, scope=self.home)
        defaults = dict(check_fn=None, requires_env=[], is_async=False, emoji="")
        self.registry.register(**(defaults | kwargs), scope=self.home)
        current = self.registry.snapshot_registration(name, scope=self.home)
        return ToolHandle(self.registry, self.home, name, previous, current)

    def register_hook(self, name, handler):
        self.hooks.setdefault(name, []).append(handler)
        return Handle(lambda: self.hooks[name].remove(handler))

    def register_middleware(self, name, handler):
        self.middleware.setdefault(name, []).append(handler)
        return Handle(lambda: self.middleware[name].remove(handler))

    def execute(self, name, args, **kwargs):
        """Model Hermes' fail-open execution chain, including single-use next_call."""
        callbacks = list(self.middleware.get("tool_execution", []))

        def run(index, payload):
            if index == len(callbacks):
                return self.registry.dispatch(name, payload, **kwargs)
            called = False

            def next_call(next_args):
                nonlocal called
                assert not called, "downstream dispatched twice"
                called = True
                return run(index + 1, next_args)

            try:
                return callbacks[index](
                    tool_name=name, args=payload, next_call=next_call, **kwargs
                )
            except Exception:
                if called:
                    raise
                return next_call(payload)

        return run(0, args)

    def on_unload(self, handler):
        self.unload.append(handler)

    def emit(self, name, **kwargs):
        for handler in self.hooks[name]:
            handler(**kwargs)


class Timer:
    instances = []

    def __init__(self, interval, function, args=None, kwargs=None):
        self.interval = interval
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.cancelled = False
        self.instances.append(self)

    def start(self):
        pass

    def cancel(self):
        self.cancelled = True

    def fire(self):
        # Deliberately permit a late callback even after cancel(), like a real race.
        self.function(*self.args, **self.kwargs)


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    for key in list(os.environ):
        if key.startswith("INTARIS_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("INTARIS_MCP_TOOLS", "false")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "unregistered"))

    source = os.environ.get("HERMES_SOURCE")
    if source:
        monkeypatch.syspath_prepend(source)
        # test_plugin.py installs legacy stubs at collection time.
        monkeypatch.delitem(sys.modules, "tools", raising=False)
        monkeypatch.delitem(sys.modules, "tools.registry", raising=False)
        constants = importlib.import_module("hermes_constants")
        registry_module = importlib.import_module("tools.registry")
        registry = registry_module.ToolRegistry()
        monkeypatch.setattr(registry_module, "registry", registry)
        secrets = importlib.import_module("agent.secret_scope")
        thread_context = importlib.import_module("tools.thread_context")
        # Prompt callbacks are unrelated to ownership; avoid importing terminal/vault tools.
        monkeypatch.setattr(thread_context, "_callback_api", lambda: ())
        worker = thread_context.propagate_context_to_thread
    else:
        home_var = contextvars.ContextVar("test_hermes_home", default=None)
        constants = types.ModuleType("hermes_constants")
        constants.get_hermes_home = lambda: Path(
            home_var.get() or os.environ["HERMES_HOME"]
        )
        constants.set_hermes_home_override = home_var.set
        constants.reset_hermes_home_override = home_var.reset
        monkeypatch.setitem(sys.modules, "hermes_constants", constants)
        registry = ScopedRegistry(constants.get_hermes_home)
        registry_module = types.ModuleType("tools.registry")
        registry_module.registry = registry
        monkeypatch.setitem(sys.modules, "tools.registry", registry_module)
        secret_var = contextvars.ContextVar("test_hermes_secrets", default=None)
        secrets = types.ModuleType("agent.secret_scope")
        secrets.set_secret_scope = lambda values, **kw: secret_var.set(values)
        secrets.reset_secret_scope = secret_var.reset
        secrets.get_secret = lambda name, default=None: (
            secret_var.get().get(name, default)
            if secret_var.get() is not None
            else os.environ.get(name, default)
        )
        monkeypatch.setitem(sys.modules, "agent.secret_scope", secrets)

        def worker(fn):
            return partial(contextvars.copy_context().run, fn)

    secret_values = {}

    @contextlib.contextmanager
    def profile(name):
        home = (tmp_path / name).resolve()
        token = constants.set_hermes_home_override(home)
        secret_token = secrets.set_secret_scope(
            secret_values.get(name), profile_home=str(home)
        )
        try:
            yield home
        finally:
            secrets.reset_secret_scope(secret_token)
            constants.reset_hermes_home_override(token)

    # Clean either the baseline's shared state or the isolated implementation.
    if hasattr(plugin, "_profiles"):
        plugin._profiles.clear()
        plugin._retired_sessions.clear()
        plugin._registration_locks.clear()
        plugin._registered_homes.clear()
        plugin._completion_owners.clear()
        plugin._retired_owners.clear()
    if hasattr(plugin, "_sessions"):
        plugin._sessions.clear()
        plugin._mcp_tool_cache = None
    Timer.instances = []
    monkeypatch.setattr(plugin.threading, "Timer", Timer)
    requests = []
    request_lock = threading.Lock()
    mcp_tools = {}
    evaluate_hook = []
    request_hook = []

    def urlopen(req, **kwargs):
        payload = json.loads(req.data) if req.data else None
        record = dict(url=req.full_url, headers=dict(req.header_items()), body=payload)
        with request_lock:
            requests.append(record)
        if request_hook:
            request_hook[0](req)
        if req.full_url.endswith("/evaluate"):
            if evaluate_hook:
                evaluate_hook[0]()
            result = dict(
                decision="approve", call_id="call-1", risk="low", latency_ms=1
            )
        elif req.full_url.endswith("/mcp/tools"):
            result = {"tools": mcp_tools.get(req.host, [])}
        elif req.full_url.endswith("/mcp/call"):
            result = {
                "decision": "approve",
                "content": [{"type": "text", "text": req.host}],
            }
        else:
            result = {"ok": True}
        response = io.BytesIO(json.dumps(result).encode())
        response.status = 200
        return response

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    registry.register(
        name="read_file",
        toolset="files",
        schema={"name": "read_file", "parameters": {}},
        handler=lambda args, **kw: json.dumps({"result": args["path"]}),
        check_fn=None,
        requires_env=[],
        is_async=False,
        description="Read",
        emoji="",
    )

    def register(name, settings=None, env=True):
        with profile(name) as home:
            if env:
                monkeypatch.setenv("INTARIS_URL", f"https://{name}.invalid")
                monkeypatch.setenv("INTARIS_API_KEY", f"key-{name}")
                monkeypatch.setenv("INTARIS_USER_ID", name)
            ctx = Context(registry, home, settings)
            plugin.register(ctx)
            return ctx

    def guarded_entry(name):
        """Capture the adapter's invocation-local entry for focused guard tests.

        Production registry entries now remain provider-owned. Tests of captured
        admissions/composed handlers use the same transient factory as dispatch.
        """
        source_entry = registry.get_entry(name)
        coordinator = getattr(registry, "_intaris_dispatch_coordinator", None)
        if coordinator is None or source_entry is None:
            return source_entry
        owner = coordinator.current_owner(str(constants.get_hermes_home().resolve()))
        return (
            owner.make_entry(source_entry, owner.profile.home)
            if owner
            else source_entry
        )

    yield types.SimpleNamespace(
        guarded_entry=guarded_entry,
        profile=profile,
        registry=registry,
        register=register,
        requests=requests,
        tools=mcp_tools,
        evaluate_hook=evaluate_hook,
        secrets=secret_values,
        worker=worker,
        request_hook=request_hook,
    )
    if hasattr(plugin, "_profiles"):
        plugin._profiles.clear()
        plugin._retired_sessions.clear()
        plugin._registration_locks.clear()
        plugin._registered_homes.clear()
        plugin._completion_owners.clear()
        plugin._retired_owners.clear()


def requests_for(runtime, suffix):
    return [r for r in runtime.requests if r["url"].endswith(suffix)]


@pytest.mark.parametrize("order", [("a", "b"), ("b", "a")])
def test_existing_wrapper_and_same_session_id_keep_profile_client(runtime, order):
    contexts, handlers = {}, {}
    for name in order:
        contexts[name] = runtime.register(name)
        with runtime.profile(name):
            contexts[name].emit("on_session_start", session_id="same-id")
            handlers[name] = runtime.guarded_entry("read_file").handler

    for name in ("a", "b"):
        with runtime.profile(name):
            assert (
                json.loads(handlers[name]({"path": name}, session_id="same-id"))[
                    "result"
                ]
                == name
            )
    created = requests_for(runtime, "/intention")
    evaluated = requests_for(runtime, "/evaluate")
    assert len(created) == 2
    assert created[0]["body"]["session_id"] != created[1]["body"]["session_id"]
    sessions = {r["headers"]["X-user-id"]: r["body"]["session_id"] for r in created}
    assert [
        (r["url"], r["headers"]["Authorization"], r["body"]["session_id"])
        for r in evaluated
    ] == [
        ("https://a.invalid/api/v1/evaluate", "Bearer key-a", sessions["a"]),
        ("https://b.invalid/api/v1/evaluate", "Bearer key-b", sessions["b"]),
    ]


def test_concurrent_worker_contexts_keep_client_and_sessions(runtime):
    for name in ("a", "b"):
        ctx = runtime.register(name)
        with runtime.profile(name):
            ctx.emit("on_session_start", session_id="same-id")
    barrier = threading.Barrier(2)
    runtime.evaluate_hook.append(lambda: barrier.wait(timeout=5))

    def invoke():
        return runtime.guarded_entry("read_file").handler(
            {"path": "ok"}, session_id="same-id"
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = []
        for name in ("a", "b"):
            with runtime.profile(name):
                futures.append(pool.submit(runtime.worker(invoke)))
        assert all(json.loads(f.result(timeout=10))["result"] == "ok" for f in futures)
    evaluated = requests_for(runtime, "/evaluate")
    assert sorted(r["headers"]["X-user-id"] for r in evaluated) == ["a", "b"]
    assert len({r["body"]["session_id"] for r in evaluated}) == 2


def test_settings_override_env_per_profile_without_mutating_environment(
    runtime, monkeypatch
):
    monkeypatch.setenv("INTARIS_URL", "https://env.invalid")
    monkeypatch.setenv("INTARIS_API_KEY", "env-key")
    monkeypatch.setenv("INTARIS_ALLOW_PATHS", "/env")
    for name in ("a", "b"):
        runtime.secrets[name] = {"INTARIS_API_KEY": f"key-{name}"}
        ctx = runtime.register(
            name,
            dict(
                url=f"https://{name}.invalid",
                user_id=name,
                agent_id=f"agent-{name}",
                allow_paths=f"/{name}",
                mcp_tools=False,
            ),
            env=False,
        )
        with runtime.profile(name):
            ctx.emit("on_session_start", session_id="same-id")
    assert os.environ["INTARIS_URL"] == "https://env.invalid"
    created = requests_for(runtime, "/intention")
    assert [r["url"] for r in created] == [
        "https://a.invalid/api/v1/intention",
        "https://b.invalid/api/v1/intention",
    ]
    for r, name in zip(created, ("a", "b")):
        assert r["headers"]["Authorization"] == f"Bearer key-{name}"
        assert r["headers"]["X-user-id"] == name
        assert r["headers"]["X-agent-id"] == f"agent-{name}"
        assert f"/{name}/*" in r["body"]["policy"]["allow_paths"]
        assert "/env/*" not in r["body"]["policy"]["allow_paths"]


def test_mcp_exposure_cache_and_captured_handler_are_profile_owned(
    runtime, monkeypatch
):
    monkeypatch.setenv("INTARIS_MCP_TOOLS", "true")
    runtime.tools["a.invalid"] = [
        {"server": "private", "name": "a", "description": "A private tool"}
    ]
    runtime.tools["b.invalid"] = [
        {"server": "private", "name": "b", "description": "B private tool"}
    ]
    a = runtime.register("a")
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same-id")
        handler = runtime.guarded_entry("private_a").handler
    b = runtime.register("b")
    with runtime.profile("b"):
        b.emit("on_session_start", session_id="same-id")
        assert runtime.registry.get_entry("private_a") is None
        assert runtime.registry.get_entry("private_b") is not None
    with runtime.profile("a"):
        assert runtime.registry.get_entry("private_b") is None
        assert json.loads(handler({}, session_id="same-id"))["result"] == "a.invalid"
    call = requests_for(runtime, "/mcp/call")[-1]
    assert call["headers"]["Authorization"] == "Bearer key-a"


def test_recording_callbacks_and_hooks_keep_originating_client(runtime, monkeypatch):
    monkeypatch.setenv("INTARIS_SESSION_RECORDING", "true")
    a = runtime.register("a")
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same-id")
        a.emit("post_llm_call", session_id="same-id", assistant_response="private A")
    timer_a = Timer.instances[0]
    monkeypatch.setenv("INTARIS_SESSION_RECORDING", "false")
    b = runtime.register("b")
    with runtime.profile("b"):
        b.emit("on_session_start", session_id="same-id")
        b.emit("post_llm_call", session_id="same-id", assistant_response="private B")
        timer_a.fire()
        # A manager's late hook must also retain A even outside its turn context.
        a.emit("on_session_end", session_id="same-id")
    events = requests_for(runtime, "/events")
    assert len(events) == 1
    assert events[0]["url"].startswith("https://a.invalid/")
    assert "private A" in json.dumps(events[0]["body"])
    assert "private B" not in json.dumps(events[0]["body"])
    assert requests_for(runtime, "/status")[-1]["url"].startswith("https://a.invalid/")


def test_repeat_registration_does_not_stack_guards_hooks_or_timers(
    runtime, monkeypatch
):
    monkeypatch.setenv("INTARIS_SESSION_RECORDING", "true")
    ctx = runtime.register("a")
    with runtime.profile("a"):
        plugin.register(ctx)
        ctx.emit("on_session_start", session_id="same-id")
        runtime.guarded_entry("read_file").handler({"path": "ok"}, session_id="same-id")
    assert len(requests_for(runtime, "/evaluate")) == 1
    assert all(len(handlers) == 1 for handlers in ctx.hooks.values())
    assert len(Timer.instances) == 1


def test_unload_stops_timer_even_when_late_callback_runs(runtime, monkeypatch):
    monkeypatch.setenv("INTARIS_SESSION_RECORDING", "true")
    ctx = runtime.register("a")
    timer = Timer.instances[0]
    assert ctx.unload
    for callback in ctx.unload:
        callback()
    assert timer.cancelled
    timer.fire()
    assert len(Timer.instances) == 1


def test_session_updates_retain_originating_working_directory(
    runtime, monkeypatch, tmp_path
):
    work_a = tmp_path / "work-a"
    work_b = tmp_path / "work-b"
    work_a.mkdir()
    work_b.mkdir()
    monkeypatch.chdir(work_a)
    a = runtime.register("a")
    with runtime.profile("a"):
        a.emit(
            "on_session_start", session_id="same-id", platform="cli", model="model-a"
        )
    monkeypatch.chdir(work_b)
    b = runtime.register("b")
    with runtime.profile("b"):
        b.emit("on_session_start", session_id="same-id")
    with runtime.profile("a"):
        for _ in range(3):
            runtime.guarded_entry("read_file").handler(
                {"path": "ok"}, session_id="same-id"
            )
        a.emit("on_session_end", session_id="same-id")
    updates = [
        r
        for r in runtime.requests
        if r["url"].startswith("https://a.invalid/")
        and r["body"]
        and "intention" in r["body"]
    ]
    assert len(updates) == 2
    assert all(
        r["body"]["details"]["working_directory"] == str(work_a) for r in updates
    )
    assert updates[1]["body"]["details"]["model"] == "model-a"
    summaries = requests_for(runtime, "/agent-summary")
    assert str(work_a) in json.dumps(summaries[-1]["body"])


def test_profile_defaults_and_explicit_empty_false_zero_settings(runtime, monkeypatch):
    monkeypatch.setenv("INTARIS_USER_ID", "env-user")
    monkeypatch.setenv("INTARIS_AGENT_ID", "env-agent")
    monkeypatch.setenv("INTARIS_FAIL_OPEN", "true")
    monkeypatch.setenv("INTARIS_CHECKPOINT_INTERVAL", "1")
    monkeypatch.setenv("INTARIS_SESSION_RECORDING", "true")
    monkeypatch.setenv("INTARIS_ESCALATION_TIMEOUT", "12")
    monkeypatch.setenv("INTARIS_RECORDING_FLUSH_SIZE", "9")
    monkeypatch.setenv("INTARIS_RECORDING_FLUSH_INTERVAL", "7")
    monkeypatch.setenv("INTARIS_MCP_TOOLS_CACHE_TTL_S", "20")
    a = runtime.register("a", env=False)
    b = runtime.register(
        "b",
        dict(
            user_id="",
            agent_id="",
            api_key="",
            fail_open=False,
            checkpoint_interval=0,
            session_recording=False,
            escalation_timeout=0,
            recording_flush_size=2,
            recording_flush_interval=3,
            mcp_tools_cache_ttl_s=40,
        ),
        env=False,
    )
    ca, cb = plugin._resolve_config(a), plugin._resolve_config(b)
    assert (
        ca.user_id,
        ca.agent_id,
        ca.fail_open,
        ca.checkpoint_interval,
        ca.recording,
    ) == ("env-user", "env-agent", True, 1, True)
    assert (
        cb.user_id,
        cb.agent_id,
        cb.api_key,
        cb.fail_open,
        cb.checkpoint_interval,
        cb.recording,
    ) == ("", "", "", False, 0, False)
    assert (
        ca.escalation_timeout_s,
        ca.recording_flush_size,
        ca.recording_flush_interval_s,
        ca.mcp_tools_cache_ttl_s,
    ) == (12, 9, 7, 20)
    assert (
        cb.escalation_timeout_s,
        cb.recording_flush_size,
        cb.recording_flush_interval_s,
        cb.mcp_tools_cache_ttl_s,
    ) == (0, 2, 3, 40)
    assert [timer.interval for timer in Timer.instances] == [7]
    # Fail-open remains an availability policy; both calls need valid identity.
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same-id")
    with runtime.profile("b"):
        b.emit("on_session_start", session_id="same-id")

    def unavailable(req):
        if req.full_url.endswith("/evaluate"):
            raise OSError("synthetic evaluation outage")

    runtime.request_hook.append(unavailable)
    with runtime.profile("a"):
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "ok"}, session_id="same-id"
            )
        ) == {"result": "ok"}
    with runtime.profile("b"):
        assert "error" in json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "ok"}, session_id="same-id"
            )
        )


def test_disabled_mcp_profile_never_fetches_or_exposes_other_profiles_tools(runtime):
    runtime.tools["a.invalid"] = [{"server": "private", "name": "tool"}]
    a = runtime.register("a", {"mcp_tools": True})
    b = runtime.register("b", {"mcp_tools": False})
    with runtime.profile("b"):
        b.emit("on_session_start", session_id="same-id")
        assert runtime.registry.get_entry("private_tool") is None
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same-id")
        assert runtime.registry.get_entry("private_tool") is not None
    assert [r["url"] for r in requests_for(runtime, "/mcp/tools")] == [
        "https://a.invalid/api/v1/mcp/tools"
    ]


def test_mcp_cache_ttl_is_scoped_to_profile(runtime):
    runtime.register("a", {"mcp_tools": True, "mcp_tools_cache_ttl_s": -1})
    b = runtime.register("b", {"mcp_tools": True, "mcp_tools_cache_ttl_s": 3600})
    with runtime.profile("b"):
        b.emit("on_session_start", session_id="b")
    assert [r["url"] for r in requests_for(runtime, "/mcp/tools")] == [
        "https://a.invalid/api/v1/mcp/tools",
        "https://b.invalid/api/v1/mcp/tools",
    ]


def test_captured_handler_refuses_foreign_profile_even_with_fail_open(runtime):
    a = runtime.register("a", {"fail_open": True, "mcp_tools": True})
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same-id")
        handler = runtime.guarded_entry("read_file").handler
    runtime.register("b")
    with runtime.profile("b"):
        assert "error" in json.loads(
            handler({"path": "must-not-run"}, session_id="same-id")
        )
    assert not requests_for(runtime, "/evaluate")


def test_profile_secret_scope_overrides_process_environment(runtime, monkeypatch):
    monkeypatch.setenv("INTARIS_URL", "https://foreign.invalid")
    monkeypatch.setenv("INTARIS_API_KEY", "foreign-key")
    for name in ("a", "b"):
        runtime.secrets[name] = {
            "INTARIS_URL": f"https://{name}.invalid",
            "INTARIS_API_KEY": f"key-{name}",
            "INTARIS_USER_ID": name,
            "INTARIS_AGENT_ID": f"agent-{name}",
            "INTARIS_ALLOW_PATHS": f"/{name}",
            "INTARIS_MCP_TOOLS": "false",
        }
        ctx = runtime.register(name, env=False)
        with runtime.profile(name):
            ctx.emit("on_session_start", session_id="same-id")
            runtime.guarded_entry("read_file").handler(
                {"path": "ok"}, session_id="same-id"
            )
    evaluated = requests_for(runtime, "/evaluate")
    assert [r["url"] for r in evaluated] == [
        "https://a.invalid/api/v1/evaluate",
        "https://b.invalid/api/v1/evaluate",
    ]
    assert [r["headers"]["Authorization"] for r in evaluated] == [
        "Bearer key-a",
        "Bearer key-b",
    ]


@pytest.mark.parametrize("unload_first", [False, True])
@pytest.mark.parametrize("fail_open", [False, True])
def test_reload_keeps_active_session_without_start_replay(
    runtime, unload_first, fail_open
):
    old = runtime.register("a", {"fail_open": fail_open})
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id", model="original-model")
        runtime.guarded_entry("read_file").handler(
            {"path": "before"}, session_id="same-id"
        )
        old.emit(
            "post_llm_call", session_id="same-id", assistant_response="prior context"
        )
    other = runtime.register("b")
    with runtime.profile("b"):
        other.emit("on_session_start", session_id="same-id")
    with runtime.profile("a"):
        if unload_first:
            for callback in old.unload:
                callback()
        new = runtime.register("a", {"fail_open": fail_open, "checkpoint_interval": 2})
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "after"}, session_id="same-id"
            )
        ) == {"result": "after"}
        new.emit("pre_llm_call", session_id="same-id", user_message="Continue")
        new.emit("on_session_end", session_id="same-id")
    created = requests_for(runtime, "/intention")
    assert len(created) == 2  # One per profile, none from reload or the LLM hook.
    sid = created[0]["body"]["session_id"]
    assert [r["body"]["session_id"] for r in requests_for(runtime, "/evaluate")] == [
        sid,
        sid,
    ]
    assert requests_for(runtime, "/reasoning")[-1]["body"] == {
        "session_id": sid,
        "content": "User message: Continue",
        "context": "prior context",
    }
    assert requests_for(runtime, "/checkpoint")[-1]["body"]["session_id"] == sid
    assert requests_for(runtime, "/agent-summary")[-1]["url"].endswith(
        f"/{sid}/agent-summary"
    )


def test_reloading_profile_retires_old_callbacks_and_mcp_exposure(runtime):
    runtime.tools["a.invalid"] = [{"server": "old", "name": "tool"}]
    old = runtime.register("a", {"mcp_tools": True, "session_recording": True})
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        old.emit(
            "post_llm_call", session_id="same-id", assistant_response="before reload"
        )
        handler = runtime.guarded_entry("read_file").handler
        timer = Timer.instances[-1]
        new = runtime.register(
            "a",
            {
                "mcp_tools": False,
                "session_recording": False,
                "url": "https://new.invalid",
            },
        )
        assert runtime.registry.get_entry("old_tool") is None
        new.emit("on_session_start", session_id="same-id")
        runtime.guarded_entry("read_file").handler({"path": "ok"}, session_id="same-id")
        assert "error" in json.loads(
            handler({"path": "must-not-run"}, session_id="same-id")
        )
        timer.fire()
    assert timer.cancelled
    assert len(Timer.instances) == 1
    assert requests_for(runtime, "/events")[0]["url"].startswith("https://a.invalid/")
    assert [r["url"] for r in requests_for(runtime, "/evaluate")] == [
        "https://new.invalid/api/v1/evaluate"
    ]


@pytest.mark.parametrize("changed", ["url", "user_id", "agent_id", "api_key", "policy"])
def test_reload_identity_change_requires_fresh_start(runtime, monkeypatch, changed):
    settings = {
        "url": "https://a.invalid",
        "user_id": "a",
        "fail_open": True,
        "mcp_tools": True,
    }
    for host in ("a.invalid", "changed.invalid"):
        runtime.tools[host] = [{"server": "shared", "name": "tool"}]
    old = runtime.register("a", settings)
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        old.emit("post_llm_call", session_id="same-id", assistant_response="private")
        if changed == "api_key":
            runtime.secrets["a"] = {"INTARIS_API_KEY": "changed-key"}
        elif changed == "policy":
            monkeypatch.setenv("TMPDIR", "/different-temp-root")
        else:
            settings[changed] = "https://changed.invalid" if changed == "url" else "b"
        new = runtime.register("a", settings)
        count = len(runtime.requests)
        new.emit("pre_llm_call", session_id="same-id", user_message="Continue")
        assert "error" in json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "blocked"}, session_id="same-id"
            )
        )
        assert "error" in json.loads(
            runtime.guarded_entry("shared_tool").handler({}, session_id="same-id")
        )
        assert len(runtime.requests) == count
        # Another reload cannot bypass the requirement for a genuine start.
        new = runtime.register("a", settings)
        assert "error" in json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "still blocked"}, session_id="same-id"
            )
        )
        new.emit("on_session_start", session_id="fresh-session")
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "fresh"}, session_id="fresh-session"
            )
        ) == {"result": "fresh"}
    created = requests_for(runtime, "/intention")
    assert len(created) == 2
    assert (
        requests_for(runtime, "/evaluate")[-1]["body"]["session_id"]
        == (created[-1]["body"]["session_id"])
    )
    assert created[0]["body"]["session_id"] != created[1]["body"]["session_id"]


@pytest.mark.parametrize("changed", ["url", "user_id", "agent_id", "api_key", "policy"])
@pytest.mark.parametrize("fail_open", [False, True])
@pytest.mark.parametrize("reload_again", ["none", "compatible", "failed_replacement"])
def test_reload_requires_fresh_start_for_each_session(
    runtime, monkeypatch, changed, fail_open, reload_again
):
    settings = {
        "url": "https://a.invalid",
        "user_id": "a",
        "fail_open": fail_open,
        "mcp_tools": True,
    }
    for host in ("a.invalid", "changed.invalid"):
        runtime.tools[host] = [{"server": "shared", "name": "tool"}]
    old = runtime.register("a", settings)
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="first")
        old.emit("on_session_start", session_id="stale")
        if changed == "api_key":
            runtime.secrets["a"] = {"INTARIS_API_KEY": "changed-key"}
        elif changed == "policy":
            monkeypatch.setenv("TMPDIR", "/different-temp-root")
        else:
            settings[changed] = "https://changed.invalid" if changed == "url" else "b"
        current = runtime.register("a", settings)
        current.emit("on_session_start", session_id="first")
        if reload_again == "failed_replacement":

            def fail_registration(*args):
                raise RuntimeError("synthetic replacement failure")

            with monkeypatch.context() as failure:
                failure.setattr(plugin, "_register_profile", fail_registration)
                with pytest.raises(RuntimeError, match="synthetic replacement failure"):
                    runtime.register("a", settings)
        if reload_again != "none":
            current = runtime.register("a", settings)
        handler = runtime.guarded_entry("read_file").handler
        mcp_handler = runtime.guarded_entry("shared_tool").handler
        assert json.loads(handler({"path": "fresh"}, session_id="first")) == {
            "result": "fresh"
        }
        before = len(runtime.requests)
        current.emit("pre_llm_call", session_id="stale", user_message="Continue")
        native_result = json.loads(handler({"path": "blocked"}, session_id="stale"))
        mcp_result = json.loads(mcp_handler({}, session_id="stale"))
        assert "error" in native_result, (
            "one fresh session must not unlock stale native calls"
        )
        assert "error" in mcp_result, (
            "one fresh session must not unlock stale MCP calls"
        )
        assert len(runtime.requests) == before, (
            "stale session must not bootstrap or send reasoning"
        )
        current.emit("on_session_start", session_id="stale")
        assert json.loads(handler({"path": "now fresh"}, session_id="stale")) == {
            "result": "now fresh"
        }
        assert json.loads(mcp_handler({}, session_id="stale"))["result"] in (
            "a.invalid",
            "changed.invalid",
        )
    assert len(requests_for(runtime, "/intention")) == 4
    assert len(requests_for(runtime, "/evaluate")) == 2
    assert len(requests_for(runtime, "/mcp/call")) == 1


def test_evicted_reload_state_requires_fresh_start(runtime, monkeypatch):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 1)
    for name in ("a", "b"):
        ctx = runtime.register(name, {"fail_open": True})
        with runtime.profile(name):
            ctx.emit("on_session_start", session_id="same-id")
        for callback in ctx.unload:
            callback()
    with runtime.profile("a"):
        ctx = runtime.register("a", {"fail_open": True})
        before = len(runtime.requests)
        ctx.emit("pre_llm_call", session_id="same-id", user_message="Continue")
        assert "error" in json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "blocked"}, session_id="same-id"
            )
        )
        assert len(runtime.requests) == before
        ctx.emit("on_session_start", session_id="fresh-id")
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "fresh"}, session_id="fresh-id"
            )
        ) == {"result": "fresh"}


def test_reload_keeps_state_updated_by_inflight_evaluation(runtime):
    old = runtime.register("a")
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        old_handler = runtime.guarded_entry("read_file").handler
    entered, release = threading.Event(), threading.Event()
    results = []

    def hold_evaluation():
        entered.set()
        assert release.wait(5)

    def invoke():
        with runtime.profile("a"):
            results.append(
                json.loads(old_handler({"path": "in flight"}, session_id="same-id"))
            )

    runtime.evaluate_hook.append(hold_evaluation)
    thread = threading.Thread(target=invoke)
    thread.start()
    try:
        assert entered.wait(5)
        with runtime.profile("a"):
            new = runtime.register("a")
            for callback in old.unload:
                callback()  # Stale cleanup must not retire the new owner.
    finally:
        runtime.evaluate_hook.clear()
        release.set()
        thread.join(5)
    assert results == [{"result": "in flight"}]
    with runtime.profile("a"):
        runtime.guarded_entry("read_file").handler(
            {"path": "after"}, session_id="same-id"
        )
        new.emit("on_session_end", session_id="same-id")
    assert len(requests_for(runtime, "/intention")) == 1
    assert (
        "2 tool calls (2 approved"
        in requests_for(runtime, "/agent-summary")[-1]["body"]["summary"]
    )


@pytest.mark.parametrize("same_identity", [True, False])
@pytest.mark.parametrize("stop_at", ["quiescing", "replaced", "captured"])
@pytest.mark.parametrize("completed", [True, False])
def test_session_end_cancels_admitted_call_across_reload(
    runtime, monkeypatch, same_identity, stop_at, completed
):
    old = runtime.register("a")
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        handler = runtime.guarded_entry("read_file").handler
        captured_end = old.hooks["on_session_end"][0]
    entered, release, done = threading.Event(), threading.Event(), threading.Event()
    results = []

    def hold_evaluation():
        entered.set()
        assert release.wait(5)

    def invoke():
        try:
            with runtime.profile("a"):
                results.append(
                    json.loads(handler({"path": "must not run"}, session_id="same-id"))
                )
        finally:
            done.set()

    register = plugin._register_profile

    def replace(*args):
        if stop_at == "quiescing" and args[0].predecessor is not None:
            # The predecessor is not ready; replacement hooks do not exist yet.
            old.emit("on_session_end", session_id="same-id", completed=completed)
        return register(*args)

    monkeypatch.setattr(plugin, "_register_profile", replace)
    runtime.evaluate_hook.append(hold_evaluation)
    thread = threading.Thread(target=invoke)
    thread.start()
    try:
        assert entered.wait(5)
        # Equal session IDs in another home must not cancel this invocation.
        other = runtime.register("b")
        with runtime.profile("b"):
            other.emit("on_session_start", session_id="same-id")
            other.emit("on_session_end", session_id="same-id")
        assert not done.is_set()
        with runtime.profile("a"):
            new = runtime.register("a", {} if same_identity else {"agent_id": "new"})
            if stop_at == "replaced":
                # Changed identity has no SessionState for the predecessor.
                new.emit("on_session_end", session_id="same-id", completed=completed)
            elif stop_at == "captured":
                captured_end(session_id="same-id", completed=completed)
        cancelled_before_http_return = done.wait(1)
    finally:
        runtime.evaluate_hook.clear()
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert cancelled_before_http_return, "session end must release the admitted worker"
    assert len(results) == 1 and "CANCELLED" in results[0].get("error", "")
    assert "result" not in results[0], "late HTTP approval must not execute the tool"
    assert not plugin._active_invocations


@pytest.mark.parametrize("is_async", [False, True])
@pytest.mark.parametrize("same_identity", [True, False])
def test_reload_preserves_later_plugin_wrapper(runtime, is_async, same_identity):
    calls, validations, captured_contexts = [], [], []

    def original(args, *, session_id=""):
        calls.append((args, session_id))
        return json.dumps({"result": args["path"]})

    async def async_original(args, *, session_id=""):
        return original(args, session_id=session_id)

    with runtime.profile("a") as home:
        runtime.registry.register(
            name="decorated_tool",
            toolset="test",
            schema={"name": "decorated_tool"},
            handler=async_original if is_async else original,
            is_async=is_async,
            check_fn=None,
            requires_env=[],
            description="Wrapped tool",
            emoji="",
        )
        ctx = runtime.register("a")
        ctx.emit("on_session_start", session_id="same-id")
        predecessor = runtime.guarded_entry("decorated_tool").handler

        @wraps(predecessor)
        def validate(args, **kwargs):
            validations.append(args["path"])
            if args["path"] == "blocked":
                return json.dumps({"error": "other plugin policy"})
            if args["path"] == "retarget":
                kwargs["session_id"] = "other-session"
            if args["path"] == "foreign":
                with runtime.profile("b"):
                    return predecessor({"path": "transformed"}, **kwargs)
            captured_contexts.append(contextvars.copy_context())
            return predecessor({"path": "transformed"}, **kwargs)

        @wraps(predecessor)
        async def async_validate(args, **kwargs):
            validations.append(args["path"])
            if args["path"] == "blocked":
                return json.dumps({"error": "other plugin policy"})
            if args["path"] == "retarget":
                kwargs["session_id"] = "other-session"
            if args["path"] == "foreign":
                with runtime.profile("b"):
                    return await predecessor({"path": "transformed"}, **kwargs)
            captured_contexts.append(contextvars.copy_context())
            return await predecessor({"path": "transformed"}, **kwargs)

        later = Context(runtime.registry, home)
        later.register_tool(
            name="decorated_tool",
            toolset="test",
            schema={"name": "decorated_tool"},
            handler=async_validate if is_async else validate,
            is_async=is_async,
            description="Other plugin",
            override=True,
        )
        for generation in range(2):
            ctx = runtime.register(
                "a", {} if same_identity else {"agent_id": f"generation-{generation}"}
            )
            if not same_identity:
                ctx.emit("on_session_start", session_id="same-id")
            ctx.emit("on_session_start", session_id="other-session")
            handler = runtime.guarded_entry("decorated_tool").handler
            for path in ("blocked", "retarget", "foreign", "allowed"):
                value = handler({"path": path}, session_id="same-id", task_id="worker")
                result = json.loads(asyncio.run(value) if is_async else value)
                if path in ("retarget", "foreign"):
                    assert "originating home/session" in result.get("error", "")
                else:
                    assert result == (
                        {"error": "other plugin policy"}
                        if path == "blocked"
                        else {"result": "transformed"}
                    )
                assert plugin._guard_replacements.get() is None
        if is_async:
            late = captured_contexts[-1].run(
                asyncio.run, predecessor({"path": "late"}, session_id="same-id")
            )
        else:
            late = captured_contexts[-1].run(
                predecessor, {"path": "late"}, session_id="same-id"
            )
        assert "CANCELLED" in json.loads(late).get("error", "")
        stale = predecessor({"path": "stale"}, session_id="same-id")
        assert "error" in json.loads(asyncio.run(stale) if is_async else stale)
    assert validations == ["blocked", "retarget", "foreign", "allowed"] * 2
    assert calls == [({"path": "transformed"}, "same-id")] * 2
    evaluations = [
        r
        for r in requests_for(runtime, "/evaluate")
        if r["body"]["tool"] == "decorated_tool"
    ]
    assert len(evaluations) == 2, "only inner guard evaluates each allowed call once"
    assert all(r["body"]["args"] == {"path": "transformed"} for r in evaluations)
    if not same_identity:
        assert [r["headers"]["X-agent-id"] for r in evaluations] == [
            "generation-0",
            "generation-1",
        ]
    assert not plugin._active_invocations


@pytest.mark.parametrize("outer_async,inner_async", [(True, False), (False, True)])
@pytest.mark.parametrize("same_identity", [True, False])
def test_reload_preserves_mixed_wrapper_calling_convention(
    runtime, outer_async, inner_async, same_identity
):
    calls, validations = [], []

    def original(args, *, session_id=""):
        calls.append((args, session_id))
        return json.dumps({"result": args["path"]})

    async def async_original(args, *, session_id=""):
        return original(args, session_id=session_id)

    with runtime.profile("a") as home:
        runtime.registry.register(
            name="mixed_tool",
            toolset="test",
            schema={"name": "mixed_tool"},
            handler=async_original if inner_async else original,
            is_async=inner_async,
            check_fn=None,
            requires_env=[],
            description="Mixed tool",
            emoji="",
        )
        current = runtime.register("a")
        current.emit("on_session_start", session_id="same-id")
        predecessor = runtime.guarded_entry("mixed_tool").handler

        @wraps(predecessor)
        def validate(args, **kwargs):
            validations.append(args["path"])
            result = asyncio.run(predecessor({"path": "transformed"}, **kwargs))
            # The external plugin consumes the predecessor's concrete result.
            return json.dumps(json.loads(result) | {"validated": True})

        @wraps(predecessor)
        async def async_validate(args, **kwargs):
            validations.append(args["path"])
            result = await asyncio.to_thread(
                predecessor, {"path": "transformed"}, **kwargs
            )
            return json.dumps(json.loads(result) | {"validated": True})

        later = Context(runtime.registry, home)
        later.register_tool(
            name="mixed_tool",
            toolset="test",
            schema={"name": "mixed_tool"},
            handler=async_validate if outer_async else validate,
            is_async=outer_async,
            description="Mixed external wrapper",
            override=True,
        )
        for generation in range(3):
            if generation:
                current = runtime.register(
                    "a",
                    {} if same_identity else {"agent_id": f"generation-{generation}"},
                )
                if not same_identity:
                    current.emit("on_session_start", session_id="same-id")
            entry = runtime.guarded_entry("mixed_tool")
            value = entry.handler({"path": "allowed"}, session_id="same-id")
            result = asyncio.run(value) if entry.is_async else value
            assert json.loads(result) == {"result": "transformed", "validated": True}
            assert plugin._guard_replacements.get() is None
            assert not plugin._active_invocations

    assert validations == ["allowed"] * 3
    assert calls == [({"path": "transformed"}, "same-id")] * 3
    evaluations = [
        r
        for r in requests_for(runtime, "/evaluate")
        if r["body"]["tool"] == "mixed_tool"
    ]
    assert len(evaluations) == 3, "evaluate exactly once before and after each reload"
    assert all(r["body"]["args"] == {"path": "transformed"} for r in evaluations)
    if not same_identity:
        assert [r["headers"].get("X-agent-id", "") for r in evaluations] == [
            "",
            "generation-1",
            "generation-2",
        ]


@pytest.mark.parametrize(
    "is_async,inner_async", [(False, False), (True, True), (True, False), (False, True)]
)
@pytest.mark.parametrize("completed", [False, True])
@pytest.mark.parametrize("change_identity", [False, True])
def test_composed_wrapper_cannot_resume_cancelled_invocation(
    runtime, is_async, inner_async, completed, change_identity
):
    entered, release = threading.Event(), threading.Event()
    calls, results = [], []

    def original(args, **kwargs):
        calls.append(args)
        return json.dumps({"result": "RAW_EXECUTED"})

    async def async_original(args, **kwargs):
        return original(args, **kwargs)

    with runtime.profile("a") as home:
        runtime.registry.register(
            name="paused_tool",
            toolset="test",
            schema={"name": "paused_tool"},
            handler=async_original if inner_async else original,
            is_async=inner_async,
            check_fn=None,
            requires_env=[],
            description="Paused tool",
            emoji="",
        )
        old = runtime.register("a")
        old.emit("on_session_start", session_id="same-id")
        predecessor = runtime.guarded_entry("paused_tool").handler

        @wraps(predecessor)
        def pause(args, **kwargs):
            entered.set()
            assert release.wait(5)
            result = predecessor({"path": "transformed"}, **kwargs)
            return asyncio.run(result) if inner_async else result

        @wraps(predecessor)
        async def async_pause(args, **kwargs):
            entered.set()
            assert release.wait(5)
            if inner_async:
                return await predecessor({"path": "transformed"}, **kwargs)
            result = await asyncio.to_thread(
                predecessor, {"path": "transformed"}, **kwargs
            )
            return json.dumps(json.loads(result))

        later = Context(runtime.registry, home)
        later.register_tool(
            name="paused_tool",
            toolset="test",
            schema={"name": "paused_tool"},
            handler=async_pause if is_async else pause,
            is_async=is_async,
            description="Paused external wrapper",
            override=True,
        )
        current = runtime.register("a")
        handler = runtime.guarded_entry("paused_tool").handler

    def invoke():
        with runtime.profile("a"):
            result = handler({"path": "original"}, session_id="same-id")
            results.append(json.loads(asyncio.run(result) if is_async else result))

    thread = threading.Thread(target=invoke)
    thread.start()
    try:
        assert entered.wait(5)
        with plugin._invocations_lock:
            admissions_while_paused = len(
                plugin._active_invocations.get((str(home), "same-id"), {})
            )
        with runtime.profile("a"):
            if change_identity:
                current = runtime.register("a", {"agent_id": "replacement"})
            current.emit("on_session_end", session_id="same-id", completed=completed)
            if completed or change_identity:
                current.emit("on_session_start", session_id="same-id")
            else:
                current.emit(
                    "pre_llm_call", session_id="same-id", user_message="Resume"
                )
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert admissions_while_paused == 1, "async composition must retain outer admission"
    assert len(results) == 1 and "CANCELLED" in results[0].get("error", "")
    assert not requests_for(runtime, "/evaluate"), "cancel before resumed evaluation"
    assert not calls, "resuming a session must not revive the abandoned invocation"
    assert not plugin._active_invocations


@pytest.mark.parametrize("same_identity", [True, False])
def test_reload_observes_admitted_session_start_completion(runtime, same_identity):
    old = runtime.register("a")
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="old-session")
    starting = runtime.register("a", {"user_id": "b", "fail_open": True})
    entered, release = threading.Event(), threading.Event()
    failures = []

    def hold_creation(req):
        if req.full_url.endswith("/intention"):
            entered.set()
            assert release.wait(5)

    def start():
        try:
            with runtime.profile("a"):
                starting.emit("on_session_start", session_id="fresh-session")
        except Exception as exc:
            failures.append(exc)

    runtime.request_hook.append(hold_creation)
    thread = threading.Thread(target=start)
    thread.start()
    try:
        assert entered.wait(5)
        new = runtime.register(
            "a", {"user_id": "b" if same_identity else "c", "fail_open": True}
        )
    finally:
        runtime.request_hook.clear()
        release.set()
        thread.join(5)
    assert not failures
    with runtime.profile("a"):
        result = json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "after start"}, session_id="fresh-session"
            )
        )
        new.emit("pre_llm_call", session_id="fresh-session", user_message="Continue")
    if same_identity:
        assert result == {"result": "after start"}
        assert (
            requests_for(runtime, "/evaluate")[-1]["body"]["session_id"]
            == (requests_for(runtime, "/intention")[-1]["body"]["session_id"])
        )
        assert len(requests_for(runtime, "/reasoning")) == 1
    else:
        assert "error" in result
        assert not requests_for(runtime, "/evaluate")
        assert not requests_for(runtime, "/reasoning")


@pytest.mark.parametrize("fail_open", [False, True])
@pytest.mark.parametrize(
    "failure", ["abandoned", "invalid_setting", "legacy_rejection", "hook_failure"]
)
def test_failed_first_load_allows_later_llm_bootstrap(
    runtime, monkeypatch, failure, fail_open
):
    if failure == "abandoned":
        with runtime.profile("a") as home:
            abandoned = Context(runtime.registry, home)
            abandoned._load_abandoned = True
            plugin.register(abandoned)
    elif failure == "invalid_setting":
        with pytest.raises(
            ValueError, match="Intaris setting user_id must be a string"
        ):
            runtime.register("a", {"user_id": {"invalid": True}})
    elif failure == "legacy_rejection":
        monkeypatch.setattr(runtime.registry, "get_all_entries", None)
        other = runtime.register("b")
        with pytest.raises(RuntimeError, match="profile-scoped tool registry"):
            runtime.register("a")
        for callback in other.unload:
            callback()
    else:
        original = Context.register_hook

        def fail_registration(*args, **kwargs):
            raise RuntimeError("synthetic first-load failure")

        monkeypatch.setattr(Context, "register_hook", fail_registration)
        with pytest.raises(RuntimeError, match="synthetic first-load failure"):
            runtime.register("a", {"user_id": "failed-load"})
        monkeypatch.setattr(Context, "register_hook", original)

    with runtime.profile("a"):
        ctx = runtime.register("a", {"fail_open": fail_open})
        # Reload after a failed first attempt does not replay session-start.
        ctx.emit("pre_llm_call", session_id="already-running", user_message="Continue")
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "checked"}, session_id="already-running"
            )
        ) == {"result": "checked"}
    created = requests_for(runtime, "/intention")
    assert len(created) == 1
    sid = created[0]["body"]["session_id"]
    assert requests_for(runtime, "/reasoning")[-1]["body"]["session_id"] == sid
    assert requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == sid


@pytest.mark.parametrize(
    "changed", [None, "url", "user_id", "agent_id", "api_key", "policy"]
)
@pytest.mark.parametrize("unload_first", [False, True])
def test_failed_reload_keeps_session_for_retry(
    runtime, monkeypatch, changed, unload_first
):
    old = runtime.register("a")
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        if unload_first:
            for callback in old.unload:
                callback()
        original = Context.register_hook

        def fail_registration(*args, **kwargs):
            raise RuntimeError("synthetic hook registration failure")

        settings = {"fail_open": True}
        with monkeypatch.context() as change:
            if changed == "api_key":
                runtime.secrets["a"] = {"INTARIS_API_KEY": "changed-key"}
            elif changed == "policy":
                change.setenv("TMPDIR", "/changed-temp-root")
            elif changed is not None:
                settings[changed] = (
                    "https://changed.invalid" if changed == "url" else "changed"
                )
            monkeypatch.setattr(Context, "register_hook", fail_registration)
            with pytest.raises(
                RuntimeError, match="synthetic hook registration failure"
            ):
                runtime.register("a", settings)
        runtime.secrets.pop("a", None)
        monkeypatch.setattr(Context, "register_hook", original)
        runtime.register("a")
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "after retry"}, session_id="same-id"
            )
        ) == {"result": "after retry"}
    assert len(requests_for(runtime, "/intention")) == 1
    assert (
        requests_for(runtime, "/evaluate")[-1]["body"]["session_id"]
        == (requests_for(runtime, "/intention")[0]["body"]["session_id"])
    )


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("fail_registration", [False, True])
@pytest.mark.parametrize("pause_phase", ["before", "after"])
def test_reload_never_exposes_unguarded_native_tool(
    runtime, monkeypatch, legacy, fail_registration, pause_phase
):
    if legacy:
        monkeypatch.setattr(runtime.registry, "get_all_entries", None)
    old = runtime.register("a")
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
    entered, release = threading.Event(), threading.Event()
    failures, replacements = [], []
    register = plugin._register_profile

    def paused_register(*args):
        if pause_phase == "after":
            register(*args)
        entered.set()
        assert release.wait(5)
        if pause_phase == "before":
            register(*args)
        if fail_registration:
            raise RuntimeError("synthetic replacement failure")

    def load():
        try:
            replacements.append(runtime.register("a"))
        except Exception as exc:
            failures.append(exc)

    monkeypatch.setattr(plugin, "_register_profile", paused_register)
    thread = threading.Thread(target=load)
    thread.start()
    try:
        assert entered.wait(5)
        with runtime.profile("a"):
            before = len(requests_for(runtime, "/evaluate"))
            result = json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "during"}, session_id="same-id"
                )
            )
            assert "error" in result
            assert len(requests_for(runtime, "/evaluate")) == before
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert len(failures) == int(fail_registration)
    with runtime.profile("a"):
        before = len(requests_for(runtime, "/evaluate"))
        result = json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "after"}, session_id="same-id"
            )
        )
        assert "error" in result or len(requests_for(runtime, "/evaluate")) > before
        if fail_registration:
            monkeypatch.setattr(plugin, "_register_profile", register)
            replacements.append(runtime.register("a"))
            assert json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "retry"}, session_id="same-id"
                )
            ) == {"result": "retry"}
        # Final explicit unload must still release every guard generation.
        for ctx in [old, *replacements]:
            for callback in ctx.unload:
                callback()
        assert not getattr(
            runtime.guarded_entry("read_file").handler,
            "_intaris_original_handler",
            None,
        )


def test_rejected_middleware_replacement_keeps_old_guard_blocking(runtime, monkeypatch):
    old = runtime.register("a", {"fail_open": True})
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        monkeypatch.setattr(
            Context, "register_middleware", lambda *args, **kwargs: None
        )
        with pytest.raises(
            RuntimeError, match="did not register Intaris execution middleware"
        ):
            runtime.register("a", {"fail_open": True})
        assert "error" in json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "blocked"}, session_id="same-id"
            )
        )
    assert not requests_for(runtime, "/evaluate")


def test_unload_recording_uses_one_total_http_timeout_budget(runtime, monkeypatch):
    old = runtime.register("a", {"session_recording": True})
    with runtime.profile("a"):
        for index in range(3):
            old.emit("on_session_start", session_id=f"session-{index}")
            old.emit(
                "post_llm_call",
                session_id=f"session-{index}",
                assistant_response=f"recording-{index}",
            )
    clock, timeouts = [0.0], []

    def timeout(req, *, timeout):
        assert req.full_url.endswith("/events")
        timeouts.append(timeout)
        clock[0] += min(3.0, timeout)
        raise TimeoutError("synthetic recording timeout")

    with monkeypatch.context() as slow:
        slow.setattr(plugin.time, "monotonic", lambda: clock[0])
        slow.setattr("urllib.request.urlopen", timeout)
        for callback in old.unload:
            callback()
    assert clock[0] <= 5.0
    assert timeouts == [5.0, 2.0]
    with runtime.profile("a"):
        assert not getattr(
            runtime.guarded_entry("read_file").handler,
            "_intaris_original_handler",
            None,
        )
        new = runtime.register("a", {"session_recording": True})
        Timer.instances[-1].fire()
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "after"}, session_id="session-2"
            )
        ) == {"result": "after"}
        new.emit("on_session_end", session_id="session-2")
    events = requests_for(runtime, "/events")
    assert len(events) == 1
    assert "recording-2" in json.dumps(events[0]["body"])


def test_reload_waits_for_external_unload_flush_and_cleanup(runtime):
    old = runtime.register("a", {"session_recording": True})
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        old.emit("post_llm_call", session_id="same-id", assistant_response="before")
    entered, release, loaded = threading.Event(), threading.Event(), threading.Event()
    contexts, failures = [], []

    def hold_flush(req):
        if req.full_url.endswith("/events"):
            entered.set()
            assert release.wait(5)

    def unload():
        try:
            for callback in old.unload:
                callback()
        except Exception as exc:
            failures.append(exc)

    def reload():
        try:
            contexts.append(runtime.register("a", {"session_recording": True}))
            loaded.set()
        except Exception as exc:
            failures.append(exc)

    runtime.request_hook.append(hold_flush)
    closing, loading = threading.Thread(target=unload), threading.Thread(target=reload)
    closing.start()
    try:
        assert entered.wait(5)
        loading.start()
        assert not loaded.wait(0.05)
        runtime.register("b")  # Unrelated profiles must not wait for A's flush.
    finally:
        runtime.request_hook.clear()
        release.set()
        closing.join(5)
        if loading.ident:
            loading.join(5)
    assert not failures
    assert loaded.is_set()
    with runtime.profile("a"):
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "after"}, session_id="same-id"
            )
        ) == {"result": "after"}
        for callback in contexts[0].unload:
            callback()
        assert not getattr(
            runtime.guarded_entry("read_file").handler,
            "_intaris_original_handler",
            None,
        )
    assert len(requests_for(runtime, "/intention")) == 1
    assert len(requests_for(runtime, "/events")) == 1


def test_real_hermes_managers_settings_hooks_registry_and_unload(runtime, monkeypatch):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip(
            "Set HERMES_SOURCE to test the real Hermes PluginContext/PluginManager"
        )
    from hermes_cli import config, plugins
    from hermes_constants import get_hermes_home

    configs = {}

    def load_config():
        return configs[str(get_hermes_home())]

    monkeypatch.setattr(plugins, "load_config_readonly", load_config)
    monkeypatch.setattr(config, "load_config", load_config)
    contexts, managers = {}, {}
    for name in ("a", "b"):
        runtime.secrets[name] = {"INTARIS_API_KEY": f"key-{name}"}
        with runtime.profile(name) as home:
            configs[str(home)] = {
                "plugins": {
                    "entries": {
                        "intaris": {
                            "allow_tool_override": True,
                            "settings": {
                                "url": f"https://{name}.invalid",
                                "user_id": name,
                                "session_recording": True,
                                "mcp_tools": True,
                            },
                        }
                    }
                }
            }
            runtime.tools[f"{name}.invalid"] = [{"server": name, "name": "tool"}]
            manifest = plugins.PluginManifest(
                name="intaris", source="entrypoint", path="hermes_intaris"
            )
            manager = plugins.PluginManager(scope_key=str(home))
            manager._track_tool_override_policy(manifest, "hermes_intaris")
            ctx = plugins.PluginContext(manifest, manager)
            plugin.register(ctx)
            plugin.register(ctx)
            assert len(manager._hooks["on_session_start"]) == 1
            manager.invoke_hook("on_session_start", session_id="same-id")
            contexts[name], managers[name] = ctx, manager
            # Overlapping replacement uses the real Hermes lease coordinator.
            for _ in range(2):
                plugin.register(plugins.PluginContext(manifest, manager))
                assert len(manager._hooks["on_session_start"]) == 1
    with runtime.profile("a"):
        runtime.guarded_entry("read_file").handler({"path": "ok"}, session_id="same-id")
        assert runtime.registry.get_entry("b_tool") is None
    # Host unload can be requested from another profile, but releases only A.
    with runtime.profile("b"):
        managers["a"].unload()
        runtime.guarded_entry("read_file").handler({"path": "ok"}, session_id="same-id")
        assert runtime.registry.get_entry("b_tool") is not None
    with runtime.profile("a"):
        assert runtime.registry.get_entry("a_tool") is None
        assert not getattr(
            runtime.guarded_entry("read_file").handler,
            "_intaris_original_handler",
            None,
        )
    assert [r["headers"]["X-user-id"] for r in requests_for(runtime, "/evaluate")] == [
        "a",
        "b",
    ]
    assert Timer.instances[0].cancelled
    # Force rediscovery unloads before re-registering, without replaying session start.
    with runtime.profile("a"):
        manager = managers["a"]
        manifest = contexts["a"].manifest
        manager._track_tool_override_policy(manifest, "hermes_intaris")
        plugin.register(plugins.PluginContext(manifest, manager))
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "after reload"}, session_id="same-id"
            )
        ) == {"result": "after reload"}
        assert (
            requests_for(runtime, "/evaluate")[-1]["body"]["session_id"]
            == (requests_for(runtime, "/intention")[0]["body"]["session_id"])
        )
        assert len(requests_for(runtime, "/intention")) == 2
        manager.unload()
    with runtime.profile("b"):
        managers["b"].unload()


@pytest.mark.parametrize("public_restore", [False, True])
def test_legacy_unload_restores_original_tool(runtime, monkeypatch, public_restore):
    monkeypatch.setattr(runtime.registry, "get_all_entries", None)
    if not public_restore:
        monkeypatch.setattr(runtime.registry, "restore_registration", None)
    original = runtime.registry._tools["read_file"]
    ctx = runtime.register("a")
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="same-id")
        for _ in range(2):
            previous = ctx
            ctx = runtime.register("a")
            for callback in previous.unload:
                callback()
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "guarded"}, session_id="same-id"
            )
        ) == {"result": "guarded"}
        for callback in ctx.unload:
            callback()
            callback()  # Host cleanup may be repeated after a failed reload.
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "restored"}, session_id="same-id"
            )
        ) == {"result": "restored"}
    assert runtime.registry._tools["read_file"] is original
    assert len(requests_for(runtime, "/evaluate")) == 1


@pytest.mark.parametrize("public_restore", [False, True])
def test_legacy_unload_keeps_later_registration(runtime, monkeypatch, public_restore):
    monkeypatch.setattr(runtime.registry, "get_all_entries", None)
    if not public_restore:
        monkeypatch.setattr(runtime.registry, "restore_registration", None)
    ctx = runtime.register("a")
    runtime.registry.register(
        name="read_file",
        toolset="files",
        schema={"name": "read_file", "parameters": {}},
        handler=lambda args, **kw: json.dumps({"result": "later plugin"}),
    )
    later = runtime.registry._tools["read_file"]
    for callback in ctx.unload:
        callback()
    assert runtime.registry._tools["read_file"] is later
    assert json.loads(later.handler({})) == {"result": "later plugin"}


def test_legacy_registry_refuses_second_profile_without_redirecting_first(
    runtime, monkeypatch
):
    monkeypatch.setattr(runtime.registry, "get_all_entries", None)
    a = runtime.register("a")
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same-id")
    with pytest.raises(RuntimeError, match="profile-scoped tool registry"):
        runtime.register("b")
    with runtime.profile("a"):
        assert (
            json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "ok"}, session_id="same-id"
                )
            )["result"]
            == "ok"
        )
    assert [r["headers"]["X-user-id"] for r in requests_for(runtime, "/evaluate")] == [
        "a"
    ]


def test_legacy_public_enumerator_does_not_imply_profile_scope(runtime, monkeypatch):
    original_register = runtime.registry.register

    def legacy_register(
        name,
        toolset,
        schema,
        handler,
        check_fn=None,
        requires_env=None,
        is_async=False,
        description="",
        emoji="",
    ):
        original_register(
            name=name,
            toolset=toolset,
            schema=schema,
            handler=handler,
            check_fn=check_fn,
            requires_env=requires_env,
            is_async=is_async,
            description=description,
            emoji=emoji,
        )

    monkeypatch.setattr(runtime.registry, "register", legacy_register)
    a = runtime.register("a")
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same-id")
        assert (
            json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "ok"}, session_id="same-id"
                )
            )["result"]
            == "ok"
        )
    with pytest.raises(RuntimeError, match="profile-scoped tool registry"):
        runtime.register("b")


def test_secret_scope_failure_never_falls_back_to_process_credentials(
    runtime, monkeypatch
):
    monkeypatch.setenv("INTARIS_API_KEY", "foreign-key")

    def missing_scope(*args):
        raise RuntimeError("missing profile secret scope")

    monkeypatch.setattr(sys.modules["agent.secret_scope"], "get_secret", missing_scope)
    with pytest.raises(RuntimeError, match="missing profile secret scope"):
        runtime.register("a", env=False)
    assert runtime.requests == []
    assert not plugin._profiles


def test_same_mcp_name_has_profile_specific_schema_and_credentials(runtime):
    for name in ("a", "b"):
        runtime.tools[f"{name}.invalid"] = [
            {
                "server": "shared",
                "name": "tool",
                "description": name,
                "inputSchema": {
                    "type": "object",
                    "properties": {name: {"type": "string"}},
                },
            }
        ]
        ctx = runtime.register(name, {"mcp_tools": True})
        with runtime.profile(name):
            ctx.emit("on_session_start", session_id="same-id")
    for name in ("a", "b"):
        with runtime.profile(name):
            tool = runtime.registry.get_entry("shared_tool")
            assert set(tool.schema["parameters"]["properties"]) == {name}
            assert (
                json.loads(tool.handler({name: "input"}, session_id="same-id"))[
                    "result"
                ]
                == f"{name}.invalid"
            )
    assert [
        r["headers"]["Authorization"] for r in requests_for(runtime, "/mcp/call")
    ] == ["Bearer key-a", "Bearer key-b"]


def test_slow_profile_registration_does_not_block_another_home(runtime):
    entered, release, loaded_b = threading.Event(), threading.Event(), threading.Event()
    failures = []

    def hold_a(req):
        if req.full_url == "https://a.invalid/api/v1/mcp/tools":
            entered.set()
            assert release.wait(5)

    runtime.request_hook.append(hold_a)

    def load(name):
        try:
            runtime.register(
                name,
                {"url": f"https://{name}.invalid", "mcp_tools": name == "a"},
                env=False,
            )
            if name == "b":
                loaded_b.set()
        except Exception as exc:
            failures.append(exc)

    a, b = (
        threading.Thread(target=load, args=("a",)),
        threading.Thread(target=load, args=("b",)),
    )
    a.start()
    try:
        assert entered.wait(5)
        b.start()
        assert loaded_b.wait(1), "Profile B blocked on A's MCP request"
    finally:
        release.set()
        a.join(5)
        if b.ident:
            b.join(5)
    assert not failures


@pytest.mark.parametrize("is_async", [False, True])
def test_scoped_tool_dispatch_preserves_execution_and_context_signature(
    runtime, monkeypatch, is_async
):
    executions = []

    def narrow(args, *, session_id=""):
        executions.append((args, session_id))
        return json.dumps({"result": "executed"})

    async def async_narrow(args, *, session_id=""):
        await asyncio.sleep(0)
        return narrow(args, session_id=session_id)

    # Keep real registry dispatch; isolate the bridge's heavyweight tool imports.
    bridge = types.ModuleType("model_tools")
    bridge._run_async = asyncio.run
    bridge._sanitize_tool_error = str
    monkeypatch.setitem(sys.modules, "model_tools", bridge)
    with runtime.profile("a") as home:
        runtime.registry.register(
            name="scoped_tool",
            toolset="other-plugin",
            schema={"name": "scoped_tool", "parameters": {}},
            handler=async_narrow if is_async else narrow,
            scope=str(home),
            check_fn=None,
            requires_env=[],
            is_async=is_async,
            description="Scoped tool",
            emoji="",
        )
        ctx = runtime.register("a")
        ctx.emit("on_session_start", session_id="session-a")
        result = runtime.registry.dispatch(
            "scoped_tool",
            {"input": "value"},
            task_id="task-a",
            session_id="session-a",
            user_task="context",
        )
        if inspect.isawaitable(result):
            result.close()
            pytest.fail("Async handler was returned without being awaited")
    assert json.loads(result) == {"result": "executed"}
    assert executions == [({"input": "value"}, "session-a")]
    assert len(requests_for(runtime, "/evaluate")) == 1


def test_unload_does_not_strand_event_from_running_recording_hook(runtime, monkeypatch):
    ctx = runtime.register("a", {"session_recording": True})
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="session-a")
    entered, release = threading.Event(), threading.Event()
    record = plugin._record_event
    failures = []

    def paused_record(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return record(*args, **kwargs)

    def produce():
        try:
            ctx.emit(
                "post_llm_call",
                session_id="session-a",
                assistant_response="accepted event",
            )
        except Exception as exc:
            failures.append(exc)

    monkeypatch.setattr(plugin, "_record_event", paused_record)
    thread = threading.Thread(target=produce)
    thread.start()
    try:
        assert entered.wait(5)
        for unload in ctx.unload:
            unload()
    finally:
        release.set()
        thread.join(5)
    assert not failures
    assert len(requests_for(runtime, "/events")) == 1
    assert "accepted event" in json.dumps(requests_for(runtime, "/events")[0]["body"])
    assert Timer.instances[0].cancelled


def test_unload_during_discovery_disposes_late_tools_and_timer(runtime):
    entered, release = threading.Event(), threading.Event()
    runtime.tools["a.invalid"] = [{"server": "late", "name": "tool"}]
    failures = []
    with runtime.profile("a") as home:
        ctx = Context(
            runtime.registry,
            home,
            {
                "url": "https://a.invalid",
                "mcp_tools": True,
                "session_recording": True,
            },
        )

    def hold_request(req):
        if req.full_url.endswith("/mcp/tools"):
            entered.set()
            assert release.wait(5)

    runtime.request_hook.append(hold_request)

    def load():
        try:
            with runtime.profile("a"):
                plugin.register(ctx)
        except Exception as exc:
            failures.append(exc)

    thread = threading.Thread(target=load)
    thread.start()
    try:
        assert entered.wait(5)
        assert ctx.unload
        ctx._load_abandoned = True  # Hermes refuses late registrations on timeout.
        for unload in ctx.unload:
            unload()
    finally:
        release.set()
        thread.join(5)
    assert not failures
    assert not plugin._profiles
    assert not Timer.instances
    with runtime.profile("a"):
        assert runtime.registry.get_entry("late_tool") is None
        assert not getattr(
            runtime.guarded_entry("read_file").handler,
            "_intaris_original_handler",
            None,
        )
        recovered = runtime.register("a", {"url": "https://recovered.invalid"})
        recovered.emit(
            "pre_llm_call", session_id="already-running", user_message="Continue"
        )
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "recovered"}, session_id="already-running"
            )
        ) == {"result": "recovered"}
    assert len(requests_for(runtime, "/evaluate")) == 1


@pytest.mark.parametrize("delivery", ["replacement", "captured"])
@pytest.mark.parametrize("completed", [False, True])
@pytest.mark.parametrize("unload_first", [False, True])
def test_changed_reload_finishes_predecessor_with_original_owner(
    runtime, delivery, completed, unload_first
):
    old = runtime.register("a", {"session_recording": True})
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        captured_end = old.hooks["on_session_end"][0]
        old.emit(
            "post_llm_call", session_id="same-id", assistant_response="old private text"
        )
        runtime.guarded_entry("read_file").handler(
            {"path": "old"}, session_id="same-id"
        )
        original_id = requests_for(runtime, "/intention")[-1]["body"]["session_id"]
        if unload_first:
            for callback in old.unload:
                callback()
        runtime.secrets["a"] = {"INTARIS_API_KEY": "new-key"}
        new = runtime.register(
            "a",
            {
                "url": "https://new.invalid",
                "user_id": "new-user",
                "agent_id": "new-agent",
            },
        )
    other = runtime.register("b")
    with runtime.profile("b"):
        other.emit("on_session_start", session_id="same-id")
    with runtime.profile("a"):
        selected = (
            captured_end if delivery == "captured" else new.hooks["on_session_end"][0]
        )
        selected(session_id="same-id", completed=completed)
        # Duplicate deliveries through either generation must be idempotent.
        new.emit("on_session_end", session_id="same-id", completed=completed)
        captured_end(session_id="same-id", completed=completed)
    statuses = requests_for(runtime, "/status")
    assert len(statuses) == 1, "predecessor lifecycle must be delivered exactly once"
    assert (
        statuses[0]["url"] == f"https://a.invalid/api/v1/session/{original_id}/status"
    )
    assert statuses[0]["body"] == {"status": "completed" if completed else "idle"}
    assert statuses[0]["headers"]["Authorization"] == "Bearer key-a"
    assert statuses[0]["headers"]["X-user-id"] == "a"
    summaries = requests_for(runtime, "/agent-summary")
    assert len(summaries) == int(completed)
    if not completed:
        with runtime.profile("a"):
            new.emit("on_session_end", session_id="same-id", completed=True)
            captured_end(session_id="same-id", completed=True)
        summaries = requests_for(runtime, "/agent-summary")
        assert [r["body"]["status"] for r in requests_for(runtime, "/status")] == [
            "idle",
            "completed",
        ]
    assert len(summaries) == 1
    assert (
        summaries[0]["url"]
        == f"https://a.invalid/api/v1/session/{original_id}/agent-summary"
    )
    assert summaries[0]["headers"]["Authorization"] == "Bearer key-a"
    assert "1 tool calls (1 approved" in summaries[0]["body"]["summary"]
    events = requests_for(runtime, "/events")
    assert len(events) == 1
    assert events[0]["url"] == f"https://a.invalid/api/v1/session/{original_id}/events"
    assert "old private text" in json.dumps(events[0]["body"])


@pytest.mark.parametrize("completed", [False, True])
def test_changed_reload_end_flushes_predecessor_recording_left_by_budget(
    runtime, monkeypatch, completed
):
    old = runtime.register("a", {"session_recording": True})
    with runtime.profile("a"):
        for index in range(3):
            old.emit("on_session_start", session_id=f"session-{index}")
            old.emit(
                "post_llm_call",
                session_id=f"session-{index}",
                assistant_response=f"old-{index}",
            )
        original_id = requests_for(runtime, "/intention")[-1]["body"]["session_id"]
    clock = [0.0]

    def timeout(req, *, timeout):
        assert req.full_url.endswith("/events")
        clock[0] += min(3.0, timeout)
        raise TimeoutError("synthetic recording timeout")

    with monkeypatch.context() as slow:
        slow.setattr(plugin.time, "monotonic", lambda: clock[0])
        slow.setattr("urllib.request.urlopen", timeout)
        for callback in old.unload:
            callback()
    assert clock[0] <= 5.0
    with runtime.profile("a"):
        runtime.register(
            "a", {"url": "https://middle.invalid", "user_id": "middle-user"}
        )
        new = runtime.register(
            "a", {"url": "https://new.invalid", "user_id": "new-user"}
        )
        new.emit("on_session_end", session_id="session-2", completed=completed)
        new.emit("on_session_end", session_id="session-2", completed=completed)
    events = requests_for(runtime, "/events")
    assert len(events) == 1, "end must flush predecessor buffer not attempted at unload"
    assert events[0]["url"] == f"https://a.invalid/api/v1/session/{original_id}/events"
    assert events[0]["headers"]["Authorization"] == "Bearer key-a"
    assert "old-2" in json.dumps(events[0]["body"])
    assert len(requests_for(runtime, "/agent-summary")) == int(completed)


@pytest.mark.parametrize("compatible", [False, True])
def test_completion_owner_deduplicates_concurrent_generation_hooks(runtime, compatible):
    old = runtime.register("a", {"session_recording": True})
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        old.emit("post_llm_call", session_id="same-id", assistant_response="one event")
        captured_end = old.hooks["on_session_end"][0]
        sid = requests_for(runtime, "/intention")[-1]["body"]["session_id"]
        new = runtime.register(
            "a", {} if compatible else {"url": "https://new.invalid"}
        )
    entered, release = threading.Event(), threading.Event()
    gate = threading.Barrier(3)

    def hold_status(req):
        if req.full_url.endswith(f"/{sid}/status"):
            entered.set()
            assert release.wait(5)

    def end(callback):
        gate.wait(5)
        callback(session_id="same-id")

    runtime.request_hook.append(hold_status)
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [
            workers.submit(end, callback)
            for callback in (captured_end, new.hooks["on_session_end"][0])
        ]
        try:
            gate.wait(5)
            assert entered.wait(5)
            # Another home must remain usable while this owner's HTTP is blocked.
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="same-id")
                assert json.loads(
                    runtime.guarded_entry("read_file").handler(
                        {"path": "other"}, session_id="same-id"
                    )
                ) == {"result": "other"}
        finally:
            release.set()
        for future in futures:
            future.result(5)
    assert len(requests_for(runtime, "/status")) == 1
    assert len(requests_for(runtime, "/agent-summary")) == 1
    assert len(requests_for(runtime, "/events")) == 1


@pytest.mark.parametrize("compatible", [False, True])
def test_completion_owner_settles_end_during_creation_without_deleting_reused_id(
    runtime, compatible
):
    old = runtime.register("a")
    entered, release = threading.Event(), threading.Event()
    first = [True]
    failures = []

    def hold_creation(req):
        if req.full_url.endswith("/intention") and first[0]:
            first[0] = False
            entered.set()
            assert release.wait(5)

    def start():
        try:
            with runtime.profile("a"):
                old.emit("on_session_start", session_id="same-id")
        except BaseException as exc:
            failures.append(exc)

    runtime.request_hook.append(hold_creation)
    thread = threading.Thread(target=start)
    thread.start()
    try:
        assert entered.wait(5)
        with runtime.profile("a") as home:
            original_state = plugin._profiles[str(home)].sessions["same-id"]
            current = runtime.register("a", {} if compatible else {"agent_id": "new"})
            current.emit("on_session_end", session_id="same-id")
            assert original_state._ended.is_set()
            current.emit("on_session_start", session_id="same-id")
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not failures
    created = requests_for(runtime, "/intention")
    assert len(created) == 2, "fresh SID reuse must create a distinct Intaris session"
    original_id, new_id = [r["body"]["session_id"] for r in created]
    assert original_id != new_id
    statuses = requests_for(runtime, "/status")
    assert len(statuses) == 1 and statuses[0]["url"].endswith(f"/{original_id}/status")
    assert statuses[0]["body"] == {"status": "completed"}
    assert len(requests_for(runtime, "/agent-summary")) == 1
    assert original_state._ended.is_set() and not original_state.start_confirmed
    with runtime.profile("a"):
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "new lifetime"}, session_id="same-id"
            )
        ) == {"result": "new lifetime"}
    assert requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == new_id


def test_completion_owner_preserves_new_state_during_blocked_final_flush(runtime):
    ctx = runtime.register("a", {"session_recording": True})
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="same-id")
        ctx.emit("post_llm_call", session_id="same-id", assistant_response="old event")
    entered, release = threading.Event(), threading.Event()
    failures = []

    def hold_flush(req):
        if req.full_url.endswith("/events") and not entered.is_set():
            entered.set()
            assert release.wait(5)

    def end():
        try:
            ctx.emit("on_session_end", session_id="same-id")
        except BaseException as exc:
            failures.append(exc)

    runtime.request_hook.append(hold_flush)
    thread = threading.Thread(target=end)
    thread.start()
    try:
        assert entered.wait(5)
        with runtime.profile("a"):
            ctx.emit("on_session_start", session_id="same-id")
            ctx.emit(
                "post_llm_call", session_id="same-id", assistant_response="new event"
            )
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not failures
    created = requests_for(runtime, "/intention")
    assert len(created) == 2
    original_id, new_id = [r["body"]["session_id"] for r in created]
    with runtime.profile("a"):
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "new lifetime"}, session_id="same-id"
            )
        ) == {"result": "new lifetime"}
        ctx.emit("on_session_end", session_id="same-id")
    events = requests_for(runtime, "/events")
    assert [r["url"].split("/")[-2] for r in events] == [original_id, new_id]
    assert "old event" in json.dumps(events[0]["body"])
    assert "new event" not in json.dumps(events[0]["body"])
    assert "new event" in json.dumps(events[1]["body"])


@pytest.mark.parametrize("change_identity", [False, True])
def test_completion_owner_keeps_late_recording_on_original_state(
    runtime, monkeypatch, change_identity
):
    old = runtime.register("a", {"session_recording": True})
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
    sid = requests_for(runtime, "/intention")[0]["body"]["session_id"]
    entered, release = threading.Event(), threading.Event()
    record = plugin._record_event
    failures = []

    def paused_record(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return record(*args, **kwargs)

    def produce():
        try:
            old.emit(
                "post_llm_call",
                session_id="same-id",
                assistant_response="late old event",
            )
        except BaseException as exc:
            failures.append(exc)

    monkeypatch.setattr(plugin, "_record_event", paused_record)
    thread = threading.Thread(target=produce)
    thread.start()
    try:
        assert entered.wait(5)
        with runtime.profile("a"):
            current = (
                runtime.register("a", {"url": "https://new.invalid"})
                if change_identity
                else old
            )
            current.emit("on_session_end", session_id="same-id")
            current.emit("on_session_start", session_id="same-id")
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not failures
    events = requests_for(runtime, "/events")
    assert len(events) == 1
    assert events[0]["url"] == f"https://a.invalid/api/v1/session/{sid}/events"
    assert events[0]["headers"]["Authorization"] == "Bearer key-a"
    assert "late old event" in json.dumps(events[0]["body"])


def test_completion_owner_serializes_idle_before_terminal_effects(runtime):
    ctx = runtime.register("a")
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="same-id")
    entered, release = threading.Event(), threading.Event()
    failures, applied = [], []
    terminal_started, terminal_done = threading.Event(), threading.Event()

    def hold_idle(req):
        if req.full_url.endswith("/status"):
            status = json.loads(req.data)["status"]
            if status == "idle":
                entered.set()
                assert release.wait(5)
            # Model the server applying the status after the held request.
            applied.append(status)

    def end(completed):
        try:
            if completed:
                terminal_started.set()
            ctx.emit("on_session_end", session_id="same-id", completed=completed)
        except BaseException as exc:
            failures.append(exc)
        finally:
            if completed:
                terminal_done.set()

    runtime.request_hook.append(hold_idle)
    idle = threading.Thread(target=end, args=(False,))
    terminal = threading.Thread(target=end, args=(True,))
    idle.start()
    try:
        assert entered.wait(5)
        terminal.start()
        assert terminal_started.wait(5)
        # An unserialized implementation completes while idle is still held.
        # The fixed implementation waits until this owner can emit in order.
        terminal_done.wait(0.2)
    finally:
        release.set()
        idle.join(5)
        if terminal.ident is not None:
            terminal.join(5)
    assert not idle.is_alive() and not terminal.is_alive() and not failures
    ctx.emit("on_session_end", session_id="same-id", completed=False)
    ctx.emit("on_session_end", session_id="same-id", completed=True)
    assert [r["body"]["status"] for r in requests_for(runtime, "/status")] == [
        "idle",
        "completed",
    ]
    assert len(requests_for(runtime, "/agent-summary")) == 1

    assert applied == ["idle", "completed"], "late idle must not overwrite completed"


def test_completion_owner_allows_one_idle_per_active_interval(runtime):
    ctx = runtime.register("a")
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="same-id")
        for _ in range(2):
            ctx.emit("on_session_end", session_id="same-id", completed=False)
        ctx.emit("pre_llm_call", session_id="same-id", user_message="Continue")
        for _ in range(2):
            ctx.emit("on_session_end", session_id="same-id", completed=False)
        ctx.emit("on_session_end", session_id="same-id", completed=True)
    assert [r["body"]["status"] for r in requests_for(runtime, "/status")] == [
        "idle",
        "active",
        "idle",
        "completed",
    ]
    assert len(requests_for(runtime, "/agent-summary")) == 1


@pytest.mark.parametrize("idle", [False, True])
@pytest.mark.parametrize("transport_fails", [False, True])
def test_session_eviction_retires_completion_owners(
    runtime, monkeypatch, caplog, idle, transport_fails
):
    import gc
    import logging
    import weakref

    monkeypatch.setattr(plugin, "MAX_SESSIONS", 3)
    ctx = runtime.register("a", {"session_recording": True})
    if transport_fails:
        # Captured LogRecords retain exception tracebacks; keep the test logger
        # from pinning the very states whose collectability this test checks.
        caplog.set_level(logging.CRITICAL, logger="hermes_intaris.client")

        def fail_effect(req):
            if req.full_url.endswith(("/events", "/status", "/agent-summary")):
                raise TimeoutError("synthetic lifecycle outage")

        runtime.request_hook.append(fail_effect)
    references = []
    with runtime.profile("a") as home:
        profile = plugin._profiles[str(home)]
        for index in range(12):
            sid = f"session-{index}"
            ctx.emit("on_session_start", session_id=sid)
            references.append(weakref.ref(profile.sessions[sid]))
            ctx.emit(
                "post_llm_call", session_id=sid, assistant_response=f"event-{index}"
            )
            if idle:
                ctx.emit("on_session_end", session_id=sid, completed=False)
        assert len(profile.sessions) == 3
        retained = sum(
            len(owners)
            for (owner_home, _), owners in plugin._completion_owners.items()
            if owner_home == str(home)
        )
        assert retained == 3, "eviction must retire owners as well as session entries"
        gc.collect()
        assert all(ref() is None for ref in references[:-3])
        ctx.emit("on_session_start", session_id="session-11")
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "retained"}, session_id="session-11"
            )
        ) == {"result": "retained"}
    created = [r["body"]["session_id"] for r in requests_for(runtime, "/intention")]
    completed = [
        r["url"].split("/")[-2]
        for r in requests_for(runtime, "/status")
        if r["body"]["status"] == "completed"
    ]
    summaries = [
        r["url"].split("/")[-2] for r in requests_for(runtime, "/agent-summary")
    ]
    assert completed == created[:-3]
    assert summaries == created[:-3]
    events = requests_for(runtime, "/events")
    assert all(
        any(f"event-{index}" in json.dumps(r["body"]) for r in events)
        for index in range(9)
    )


@pytest.mark.parametrize("phase", ["before_http", "during_http"])
def test_session_eviction_settles_pending_creation_and_preserves_reused_id(
    runtime, monkeypatch, phase
):
    monkeypatch.setattr(plugin, "MAX_SESSIONS", 1)
    ctx = runtime.register("a")
    entered, release = threading.Event(), threading.Event()
    failures = []
    ensure = plugin._ensure_session

    def hold_before(profile, task_id, state, *args, **kwargs):
        if task_id == "same-id" and not entered.is_set():
            entered.set()
            assert release.wait(5)
        return ensure(profile, task_id, state, *args, **kwargs)

    def hold_during(req):
        if req.full_url.endswith("/intention") and not entered.is_set():
            entered.set()
            assert release.wait(5)

    if phase == "before_http":
        monkeypatch.setattr(plugin, "_ensure_session", hold_before)
    else:
        runtime.request_hook.append(hold_during)

    def start():
        try:
            with runtime.profile("a"):
                ctx.emit("on_session_start", session_id="same-id")
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=start)
    thread.start()
    try:
        assert entered.wait(5)
        with runtime.profile("a") as home:
            profile = plugin._profiles[str(home)]
            original = profile.sessions["same-id"]
            ctx.emit("on_session_start", session_id="other-id")
            assert original._ended.is_set()
            ctx.emit("on_session_start", session_id="same-id")
            replacement = profile.sessions["same-id"]
            replacement_id = replacement.intaris_session_id
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not failures
    assert original._ended.is_set() and not original.start_confirmed
    assert original._completion.status == "completed"
    assert profile.sessions["same-id"] is replacement
    assert replacement.start_confirmed and not replacement._ended.is_set()
    owners = [
        owner
        for (owner_home, _), group in plugin._completion_owners.items()
        if owner_home == str(home)
        for owner in group.values()
    ]
    assert len(owners) == 1 and owners[0].state is replacement
    created = requests_for(runtime, "/intention")
    assert len(created) == (3 if phase == "during_http" else 2)
    completed = [
        r["url"].split("/")[-2]
        for r in requests_for(runtime, "/status")
        if r["body"]["status"] == "completed"
    ]
    expected = {r["body"]["session_id"] for r in created} - {replacement_id}
    assert set(completed) == expected and len(completed) == len(expected)
    with runtime.profile("a"):
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "new lifetime"}, session_id="same-id"
            )
        ) == {"result": "new lifetime"}
    assert (
        requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == replacement_id
    )


def test_session_eviction_flush_does_not_hold_map_or_delete_reused_id(
    runtime, monkeypatch
):
    monkeypatch.setattr(plugin, "MAX_SESSIONS", 1)
    ctx = runtime.register("a", {"session_recording": True})
    with runtime.profile("a") as home:
        profile = plugin._profiles[str(home)]
        ctx.emit("on_session_start", session_id="same-id")
        original = profile.sessions["same-id"]
        ctx.emit("post_llm_call", session_id="same-id", assistant_response="old event")
    original_id = original.intaris_session_id
    entered, release = threading.Event(), threading.Event()

    def hold_flush(req):
        if req.full_url.endswith(f"/{original_id}/events"):
            entered.set()
            assert release.wait(5)

    def start(session_id):
        with runtime.profile("a"):
            ctx.emit("on_session_start", session_id=session_id)
            return profile.sessions.get(session_id)

    runtime.request_hook.append(hold_flush)
    with ThreadPoolExecutor(max_workers=2) as workers:
        eviction = workers.submit(start, "other-id")
        try:
            assert entered.wait(5), "eviction must flush the original recording"
            assert original._ended.is_set()
            # Same-home map and global owner locks must remain usable during HTTP.
            replacement = workers.submit(start, "same-id").result(3)
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="same-id")
        finally:
            release.set()
        # The intermediate entry was itself evicted before its start resumed.
        assert eviction.result(5) is None
    assert profile.sessions["same-id"] is replacement
    assert replacement.start_confirmed and not replacement._ended.is_set()
    statuses = requests_for(runtime, "/status")
    assert len(statuses) == 1
    assert statuses[0]["url"].endswith(f"/{original_id}/status")
    assert statuses[0]["body"] == {"status": "completed"}
    assert len(requests_for(runtime, "/agent-summary")) == 1
    assert len(requests_for(runtime, "/events")) == 1
    with runtime.profile("a"):
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "new lifetime"}, session_id="same-id"
            )
        ) == {"result": "new lifetime"}


@pytest.mark.parametrize("is_async", [False, True])
@pytest.mark.parametrize("pause", ["control", "native", "foreign"])
def test_real_hermes_eviction_waits_for_outer_guard(
    runtime, monkeypatch, is_async, pause
):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("Set HERMES_SOURCE to test real Hermes dispatch and observer hooks")
    evict = pause != "control"
    import tools.registry as registry_module
    from hermes_cli import config, lifecycle, plugins

    monkeypatch.setattr(plugin, "MAX_SESSIONS", 1)
    monkeypatch.setattr(registry_module, "discover_builtin_tools", lambda: None)
    monkeypatch.setattr(plugins, "discover_plugins", lambda *a, **k: None)
    monkeypatch.setattr(lifecycle, "_observe", lambda *a, **k: None)
    monkeypatch.delitem(sys.modules, "model_tools", raising=False)
    model_tools = importlib.import_module("model_tools")
    monkeypatch.setattr(model_tools, "registry", runtime.registry)
    settings = {
        "plugins": {
            "entries": {
                "intaris": {
                    "allow_tool_override": True,
                    "settings": {
                        "url": "https://a.invalid",
                        "user_id": "a",
                        "session_recording": True,
                        "mcp_tools": False,
                    },
                }
            }
        }
    }
    monkeypatch.setattr(plugins, "load_config_readonly", lambda: settings)
    monkeypatch.setattr(config, "load_config", lambda: settings)
    entered, release = threading.Event(), threading.Event()
    native_returned = threading.Event()
    outer_returned = threading.Event()
    terminal_observations = []
    post_calls, failures, result = [], [], []

    def native(args, **kwargs):
        if pause != "foreign":
            entered.set()
            assert release.wait(5)
        native_returned.set()
        return json.dumps({"result": "native-finished"})

    async def async_native(args, **kwargs):
        await asyncio.sleep(0)
        return native(args, **kwargs)

    def observe_terminal(req):
        if req.full_url.endswith(("/status", "/agent-summary")):
            terminal_observations.append(
                (native_returned.is_set(), outer_returned.is_set())
            )

    runtime.request_hook.append(observe_terminal)
    runtime.secrets["a"] = {"INTARIS_API_KEY": "key-a"}
    with runtime.profile("a") as home:
        runtime.registry.register(
            name="read_file",
            toolset="files",
            schema={"name": "read_file", "parameters": {}},
            handler=async_native if is_async else native,
            check_fn=None,
            requires_env=[],
            is_async=is_async,
            description="Blocked test native",
            emoji="",
        )
        manifest = plugins.PluginManifest(
            name="intaris", source="entrypoint", path="hermes_intaris"
        )
        manager = plugins.PluginManager(scope_key=str(home))
        manager._track_tool_override_policy(manifest, "hermes_intaris")
        ctx = plugins.PluginContext(manifest, manager)
        plugin.register(ctx)
        monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)
        manager.invoke_hook("on_session_start", session_id="same-id")
        profile = plugin._profiles[str(home)]
        original = profile.sessions["same-id"]
        original_id = original.intaris_session_id
        guarded = runtime.guarded_entry("read_file").handler

        def after_native(result):
            if pause == "foreign":
                entered.set()
                assert release.wait(5)
            outer_returned.set()
            return result

        @wraps(guarded)
        def foreign(args, **kwargs):
            return after_native(guarded(args, **kwargs))

        @wraps(guarded)
        async def async_foreign(args, **kwargs):
            return after_native(await guarded(args, **kwargs))

        runtime.registry.register(
            name="read_file",
            toolset="files",
            schema={"name": "read_file", "parameters": {}},
            handler=async_foreign if is_async else foreign,
            scope=str(home),
            check_fn=None,
            requires_env=[],
            is_async=is_async,
            description="Foreign wrapper",
            emoji="",
        )
        plugin.register(plugins.PluginContext(manifest, manager))

        def observe(**kwargs):
            post_calls.append(
                dict(
                    kwargs,
                    admission_present=bool(
                        plugin._active_invocations.get((str(home), "same-id"))
                    ),
                )
            )

        manager._hooks["post_tool_call"].append(observe)

    def invoke():
        try:
            with runtime.profile("a"):
                result.append(
                    model_tools.handle_function_call(
                        "read_file",
                        {"path": "old"},
                        task_id="worker-task",
                        session_id="same-id",
                        tool_call_id="host-call-1",
                        skip_tool_request_middleware=True,
                        skip_tool_execution_middleware=True,
                    )
                )
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=invoke)
    worker.start()
    try:
        assert entered.wait(5), failures
        if evict:
            with runtime.profile("a"):
                manager.invoke_hook("on_session_start", session_id="other-id")
        early = [
            r
            for r in requests_for(runtime, "/status")
            if r["url"].endswith(f"/{original_id}/status")
        ]
        early_summary = [
            r
            for r in requests_for(runtime, "/agent-summary")
            if r["url"].endswith(f"/{original_id}/agent-summary")
        ]
        assert not outer_returned.is_set()
        assert not early, "completion must wait for the captured outer guard"
        assert not early_summary, "summary must wait for the captured outer guard"
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive() and not failures
    assert json.loads(result[0]) == {"result": "native-finished"}
    assert len(post_calls) == 1
    assert post_calls[0]["tool_call_id"] == "host-call-1"
    assert post_calls[0]["session_id"] == "same-id"
    assert not post_calls[0]["admission_present"]
    plugin._flush_recording_buffer(profile, "same-id")
    events = list(original.recording_buffer)
    for req in requests_for(runtime, "/events"):
        if req["url"].endswith(f"/{original_id}/events"):
            events.extend(req["body"])
    recorded_results = [e for e in events if e["type"] == "tool_result"]
    if evict:
        assert terminal_observations == [(True, True), (True, True)]
    else:
        assert terminal_observations == []
    # Baseline qualification, separate from the introduced timing regression:
    # Hermes emits post_tool_call after guard release; capped-session lookup
    # already omitted this recording before completion ownership was introduced.
    assert len(recorded_results) == (0 if evict else 1)
    if not evict:
        assert recorded_results[0]["data"]["call_id"] == "call-1"
    manager.unload()
    for loop in (
        model_tools._tool_loop,
        getattr(model_tools._worker_thread_local, "loop", None),
    ):
        if loop is not None and not loop.is_running():
            loop.close()


@pytest.mark.parametrize("mode", ["homes", "unload", "replacement"])
@pytest.mark.parametrize("transport_fails", [False, True])
def test_retired_owner_budget_counts_sessions_and_generations(
    runtime, monkeypatch, caplog, mode, transport_fails
):
    import gc
    import logging
    import weakref

    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 2)
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 3, raising=False)
    if transport_fails:
        caplog.set_level(logging.CRITICAL, logger="hermes_intaris.client")

        def fail(req):
            if req.full_url.endswith(("/status", "/agent-summary")):
                raise TimeoutError("synthetic lifecycle outage")

        runtime.request_hook.append(fail)
    references = []
    for generation in range(7):
        name = f"home-{generation}" if mode == "homes" else "a"
        ctx = runtime.register(name, {"agent_id": str(generation)})
        with runtime.profile(name) as home:
            for sid in ("same-id", "second-id"):
                ctx.emit("on_session_start", session_id=sid)
                state = plugin._profiles[str(home)].sessions[sid]
                references.append(weakref.ref(state))
        if mode != "replacement":
            for callback in ctx.unload:
                callback()
        count = sum(len(group) for group in plugin._completion_owners.values())
        live = 2 if mode == "replacement" else 0
        assert count <= live + 3, "retired budget counts owners, not homes or SIDs"
    del state
    gc.collect()
    assert all(ref() is None for ref in references[: -(live + 3)])
    completed = [
        r
        for r in requests_for(runtime, "/status")
        if r["body"]["status"] == "completed"
    ]
    assert len(completed) >= 14 - live - 3
    assert len(completed) == len(requests_for(runtime, "/agent-summary"))
    assert len({r["url"] for r in completed}) == len(completed)


def test_retired_owner_cache_eviction_and_compatible_adoption(runtime, monkeypatch):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 1)
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 10, raising=False)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        state = plugin._profiles[str(home)].sessions["same-id"]
    for callback in old.unload:
        callback()
    current = runtime.register("a")
    owner = state._completion
    original_register = plugin._register_profile

    def fail(*args):
        raise RuntimeError("synthetic replacement failure")

    with monkeypatch.context() as failure:
        failure.setattr(plugin, "_register_profile", fail)
        with pytest.raises(RuntimeError, match="synthetic replacement failure"):
            runtime.register("a", {"agent_id": "failed"})
    assert plugin._register_profile is original_register
    current = runtime.register("a")
    for name in ("b", "c", "d"):
        ctx = runtime.register(name)
        with runtime.profile(name):
            ctx.emit("on_session_start", session_id="same-id")
        for callback in ctx.unload:
            callback()
    # Cache eviction must retire B/C, but cannot complete adopted live A.
    assert len(requests_for(runtime, "/agent-summary")) == 2
    assert owner.status == "active" and not state._ended.is_set()
    assert plugin._profiles[str(home)].sessions["same-id"] is state
    with runtime.profile("a"):
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "still live"}, session_id="same-id"
            )
        ) == {"result": "still live"}
        current.emit("on_session_end", session_id="same-id")
    assert len(requests_for(runtime, "/agent-summary")) == 3


@pytest.mark.parametrize("phase", ["before_http", "during_http"])
def test_retired_owner_settles_creation_and_same_sid_reuse(runtime, monkeypatch, phase):
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 0, raising=False)
    # An expired batch must leave actual pending work to settle its own lifetime.
    monkeypatch.setattr(plugin, "TEARDOWN_FLUSH_TIMEOUT_S", 0)
    old = runtime.register("a")
    entered, release = threading.Event(), threading.Event()
    ensure = plugin._ensure_session

    def before(profile, sid, state, *args, **kwargs):
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        return ensure(profile, sid, state, *args, **kwargs)

    def during(req):
        if req.full_url.endswith("/intention") and not entered.is_set():
            entered.set()
            assert release.wait(5)

    if phase == "before_http":
        monkeypatch.setattr(plugin, "_ensure_session", before)
    else:
        runtime.request_hook.append(during)

    def start():
        with runtime.profile("a"):
            old.emit("on_session_start", session_id="same-id")

    with ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(start)
        try:
            assert entered.wait(5)
            with runtime.profile("a") as home:
                original = plugin._profiles[str(home)].sessions["same-id"]
                current = runtime.register("a", {"agent_id": "new"})
                assert original._ended.is_set(), (
                    "retirement must cancel pending creation"
                )
                current.emit("on_session_start", session_id="same-id")
                replacement = plugin._profiles[str(home)].sessions["same-id"]
                assert (
                    sum(len(group) for group in plugin._completion_owners.values()) == 1
                )
        finally:
            release.set()
        pending.result(5)
    assert original._completion.status == "completed"
    assert not original.start_confirmed
    assert replacement.start_confirmed and not replacement._ended.is_set()
    assert plugin._profiles[str(home)].sessions["same-id"] is replacement
    assert len(requests_for(runtime, "/agent-summary")) == int(phase == "during_http")
    assert len(requests_for(runtime, "/intention")) == 1 + int(phase == "during_http")


@pytest.mark.parametrize("operation", ["replace", "unload"])
@pytest.mark.parametrize("effect", ["status", "events"])
def test_retired_owner_effects_release_registration_locks(
    runtime, monkeypatch, operation, effect
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 0, raising=False)
    flush = plugin._flush_recording_buffer

    def leave_retirement_buffer(profile, *args, **kwargs):
        # Isolate retirement I/O from the earlier teardown flush; a captured
        # producer can leave a buffer after that earlier flush has finished.
        if isinstance(profile, plugin.ProfileRuntime) and not profile.active:
            return
        return flush(profile, *args, **kwargs)

    monkeypatch.setattr(plugin, "_flush_recording_buffer", leave_retirement_buffer)
    old = runtime.register("a", {"session_recording": True})
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        original = plugin._profiles[str(home)].sessions["same-id"]
        old.emit(
            "post_llm_call",
            session_id="same-id",
            assistant_response="retired recording",
        )
    entered, release = threading.Event(), threading.Event()

    def hold(req):
        if req.full_url.endswith(f"/{original.intaris_session_id}/{effect}"):
            entered.set()
            assert release.wait(5)

    runtime.request_hook.append(hold)

    def retire():
        if operation == "replace":
            return runtime.register("a", {"agent_id": "new"})
        for callback in old.unload:
            callback()

    with ThreadPoolExecutor(max_workers=2) as workers:
        retiring = workers.submit(retire)
        try:
            assert entered.wait(5), "retirement must finish the old remote session"
            assert original._ended.is_set()
            # The same home's outer registration lock, not only globals, must be free.
            current = workers.submit(runtime.register, "a", {"agent_id": "new"}).result(
                3
            )
            with runtime.profile("a"):
                current.emit("on_session_start", session_id="same-id")
                replacement = plugin._profiles[str(home)].sessions["same-id"]
                assert json.loads(
                    runtime.guarded_entry("read_file").handler(
                        {"path": "replacement"}, session_id="same-id"
                    )
                ) == {"result": "replacement"}
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="same-id")
        finally:
            release.set()
        retiring.result(5)
    assert plugin._profiles[str(home)].sessions["same-id"] is replacement
    assert replacement.start_confirmed and not replacement._ended.is_set()
    assert len(requests_for(runtime, "/agent-summary")) == 1


@pytest.mark.parametrize("is_async", [False, True])
def test_retired_owner_cancels_outer_foreign_wrapper(runtime, monkeypatch, is_async):
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 0)
    # An expired batch must leave actual pending work to settle its own lifetime.
    monkeypatch.setattr(plugin, "TEARDOWN_FLUSH_TIMEOUT_S", 0)
    entered, release = threading.Event(), threading.Event()
    with runtime.profile("a") as home:
        old = runtime.register("a")
        old.emit("on_session_start", session_id="same-id")
        state = plugin._profiles[str(home)].sessions["same-id"]
        predecessor = runtime.guarded_entry("read_file").handler

        @wraps(predecessor)
        def wrapper(args, **kwargs):
            entered.set()
            assert release.wait(5)
            return predecessor({"path": "transformed"}, **kwargs)

        @wraps(predecessor)
        async def async_wrapper(args, **kwargs):
            entered.set()
            assert release.wait(5)
            return await asyncio.to_thread(
                predecessor, {"path": "transformed"}, **kwargs
            )

        Context(runtime.registry, home).register_tool(
            name="read_file",
            toolset="test",
            schema={"name": "read_file"},
            handler=async_wrapper if is_async else wrapper,
            is_async=is_async,
            description="Preserved foreign wrapper",
            override=True,
        )
        runtime.register("a")
        handler = runtime.guarded_entry("read_file").handler

    def invoke():
        with runtime.profile("a"):
            result = handler({"path": "original"}, session_id="same-id")
            return json.loads(asyncio.run(result) if is_async else result)

    with ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(invoke)
        try:
            assert entered.wait(5)
            assert len(state._completion.admissions) == 1
            current = runtime.register("a", {"agent_id": "new"})
            assert state._ended.is_set() and state._completion.status == "completed"
            assert not requests_for(runtime, "/agent-summary"), (
                "outer call still owns its lifetime"
            )
            with runtime.profile("a"):
                current.emit("on_session_start", session_id="same-id")
                replacement = plugin._profiles[str(home)].sessions["same-id"]
            assert sum(len(group) for group in plugin._completion_owners.values()) == 1
        finally:
            release.set()
        assert "CANCELLED" in pending.result(5).get("error", "")
    assert not requests_for(runtime, "/evaluate")
    assert not plugin._active_invocations
    assert len(requests_for(runtime, "/agent-summary")) == 1
    assert plugin._profiles[str(home)].sessions["same-id"] is replacement
    assert replacement.start_confirmed and not replacement._ended.is_set()


@pytest.mark.parametrize("cache_cap", [1, 100])
def test_retired_owner_releases_client_and_session_dictionary(
    runtime, monkeypatch, tmp_path, cache_cap
):
    import gc
    import weakref

    class SessionMap(dict):
        pass

    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", cache_cap)
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 2)
    references = []
    for generation in range(8):
        # No host callback/lease retains these runtimes; only adapter ownership does.
        home = str(tmp_path / f"home-{generation}")
        profile = plugin.ProfileRuntime(
            home=home,
            cfg=plugin.Config(),
            client=plugin.IntarisClient(
                "https://gc.invalid", "test-key", "user", str(generation)
            ),
            sessions=SessionMap(),
            registered=True,
        )
        plugin._profiles[home] = profile
        state = plugin._get_or_create_state(profile, "same-id")
        plugin._ensure_session(profile, "same-id", state)
        references.append(
            tuple(
                weakref.ref(item)
                for item in (state, state._completion, profile.client, profile.sessions)
            )
        )
        plugin._close_profile(profile)
    del profile, state
    gc.collect()
    for group in references[: -min(cache_cap, 2)]:
        assert all(ref() is None for ref in group), (
            "no global index may pin discarded heavy ownership"
        )


@pytest.mark.parametrize("operation", ["unload", "replace"])
@pytest.mark.parametrize("recording", [False, True])
@pytest.mark.parametrize("transport_fails", [False, True])
def test_retirement_batch_shares_teardown_deadline(
    runtime, monkeypatch, operation, recording, transport_fails
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 0)
    old = runtime.register("a", {"session_recording": recording})
    states = []
    with runtime.profile("a") as home:
        for index in range(3):
            old.emit("on_session_start", session_id=f"session-{index}")
            states.append(plugin._profiles[str(home)].sessions[f"session-{index}"])
            old.emit(
                "post_llm_call",
                session_id=f"session-{index}",
                assistant_response=f"buffer-{index}",
            )
    clock, attempts = [0.0], []

    def slow_http(req, *, timeout):
        attempts.append((clock[0], timeout, req.full_url.rsplit("/", 1)[-1]))
        clock[0] += min(3.0, timeout)
        if transport_fails:
            raise TimeoutError("synthetic lifecycle timeout")
        response = io.BytesIO(b'{"ok":true}')
        response.status = 200
        return response

    with monkeypatch.context() as slow:
        slow.setattr(plugin.time, "monotonic", lambda: clock[0])
        slow.setattr("urllib.request.urlopen", slow_http)
        if operation == "replace":
            runtime.register("a", {"session_recording": recording, "agent_id": "new"})
        else:
            for callback in old.unload:
                callback()
    assert clock[0] <= 5.0, f"retirement exceeded shared deadline: {attempts}"
    assert attempts
    assert all(0 < timeout <= 5.0 - started for started, timeout, _ in attempts)
    assert all(
        state._ended.is_set() and state._completion.status == "completed"
        for state in states
    )
    assert not plugin._completion_owners and not plugin._retired_owners
    # Expired best-effort retirement must not reopen admission or remove a new SID.
    current = runtime.register("a", {"agent_id": "new"})
    with runtime.profile("a"):
        current.emit("on_session_start", session_id="session-0")
        replacement = plugin._profiles[str(home)].sessions["session-0"]
    assert replacement not in states
    assert replacement.start_confirmed and not replacement._ended.is_set()


def test_retirement_batch_bounds_effect_lock_wait(runtime, monkeypatch):
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 0)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        state = plugin._profiles[str(home)].sessions["same-id"]
    clock, timeouts = [0.0], []

    class BusyEffectsLock:
        def acquire(self, *, timeout=-1):
            timeouts.append(timeout)
            clock[0] += 11.0 if timeout < 0 else timeout
            return timeout < 0

        def release(self):
            pass

        def __enter__(self):
            self.acquire()
            return self

        def __exit__(self, *args):
            self.release()

    state._completion.effects_lock = BusyEffectsLock()
    with monkeypatch.context() as slow:
        slow.setattr(plugin.time, "monotonic", lambda: clock[0])
        runtime.register("a", {"agent_id": "new"})
    assert clock[0] <= 5.0, (
        "an existing effect worker cannot bypass retirement's batch deadline"
    )
    assert timeouts == [5.0]
    assert state._ended.is_set() and state._completion.status == "completed"
    assert not requests_for(runtime, "/agent-summary")
    assert not plugin._completion_owners


@pytest.mark.parametrize("failure", ["exception", "abandoned"])
def test_adopted_continuity_survives_cache_eviction_and_failed_reload(
    runtime, monkeypatch, failure
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 1)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        original = plugin._profiles[str(home)].sessions["same-id"]
        original_id = original.intaris_session_id
        original_owner = original._completion
        for callback in old.unload:
            callback()
    entered, release = threading.Event(), threading.Event()
    register = plugin._register_profile

    def fail_registration(profile, ctx, *args):
        if profile.home == str(home):
            entered.set()
            assert release.wait(5)
            if failure == "exception":
                raise RuntimeError("synthetic pending replacement failure")
            ctx._load_abandoned = True
            return
        return register(profile, ctx, *args)

    with monkeypatch.context() as failed, ThreadPoolExecutor(max_workers=1) as workers:
        failed.setattr(plugin, "_register_profile", fail_registration)
        pending = workers.submit(runtime.register, "a")
        try:
            assert entered.wait(5)
            provisional = plugin._profiles[str(home)]
            assert provisional.sessions["same-id"] is original
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="other-id")
                for callback in other.unload:
                    callback()
            assert str(home) not in plugin._retired_sessions
            assert original_owner.status == "active" and not original._ended.is_set()
        finally:
            release.set()
        if failure == "exception":
            with pytest.raises(
                RuntimeError, match="synthetic pending replacement failure"
            ):
                pending.result(5)
        else:
            pending.result(5)
    current = runtime.register("a")
    with runtime.profile("a"):
        recovered = plugin._profiles[str(home)]
        assert recovered.sessions.get("same-id") is original, (
            "retry must retain adopted successful continuity"
        )
        assert original._completion is original_owner
        assert original.start_confirmed and not original._ended.is_set()
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "retry"}, session_id="same-id"
            )
        ) == {"result": "retry"}
        current.emit("on_session_end", session_id="same-id")
    assert (
        len(
            [
                r
                for r in requests_for(runtime, "/intention")
                if r["url"].startswith("https://a.invalid")
            ]
        )
        == 1
    )
    assert requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == original_id
    summaries = [
        r
        for r in requests_for(runtime, "/agent-summary")
        if r["url"].startswith("https://a.invalid")
    ]
    assert len(summaries) == 1 and summaries[0]["url"].endswith(
        f"/{original_id}/agent-summary"
    )


@pytest.mark.parametrize("failure", ["exception", "abandoned"])
@pytest.mark.parametrize("changed", ["agent_id", "allow_paths"])
def test_unloaded_predecessor_survives_eviction_and_incompatible_rollback(
    runtime, monkeypatch, failure, changed
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 1)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        predecessor = plugin._profiles[str(home)]
        original = predecessor.sessions["same-id"]
        original_id = original.intaris_session_id
        owner = original._completion
    entered, release = threading.Event(), threading.Event()
    register = plugin._register_profile

    def fail_registration(profile, ctx, *args):
        if profile.home == str(home):
            entered.set()
            assert release.wait(5)
            if failure == "exception":
                raise RuntimeError("synthetic incompatible replacement failure")
            ctx._load_abandoned = True
            return
        return register(profile, ctx, *args)

    with monkeypatch.context() as failed, ThreadPoolExecutor(max_workers=1) as workers:
        failed.setattr(plugin, "_register_profile", fail_registration)
        pending = workers.submit(runtime.register, "a", {changed: "/replacement"})
        try:
            assert entered.wait(5)
            provisional = plugin._profiles[str(home)]
            assert provisional.predecessor is predecessor
            assert provisional.sessions is not predecessor.sessions
            assert not provisional.continuity_adopted
            for callback in old.unload:
                callback()
            assert predecessor.closed.is_set() and not predecessor.active
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="other-id")
                for callback in other.unload:
                    callback()
            assert str(home) not in plugin._retired_sessions
            assert owner.status == "active" and not original._ended.is_set()
        finally:
            release.set()
        if failure == "exception":
            with pytest.raises(
                RuntimeError, match="synthetic incompatible replacement failure"
            ):
                pending.result(5)
        else:
            pending.result(5)
    current = runtime.register("a")
    with runtime.profile("a"):
        recovered = plugin._profiles[str(home)]
        assert recovered.sessions.get("same-id") is original, (
            "rollback must retain the unloaded successful predecessor"
        )
        assert original._completion is owner
        assert original.start_confirmed and not original._ended.is_set()
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "retry"}, session_id="same-id"
            )
        ) == {"result": "retry"}
        current.emit("on_session_end", session_id="same-id")
    created = [
        r
        for r in requests_for(runtime, "/intention")
        if r["url"].startswith("https://a.invalid")
    ]
    assert len(created) == 1
    assert requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == original_id
    summaries = [
        r
        for r in requests_for(runtime, "/agent-summary")
        if r["url"].startswith("https://a.invalid")
    ]
    assert len(summaries) == 1 and summaries[0]["url"].endswith(
        f"/{original_id}/agent-summary"
    )


@pytest.mark.parametrize("compatible", [True, False])
def test_replacement_success_accounts_evicted_predecessor(
    runtime, monkeypatch, compatible
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 1)
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 1)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        original = plugin._profiles[str(home)].sessions["same-id"]
        owner = original._completion
    entered, release = threading.Event(), threading.Event()
    register = plugin._register_profile

    def paused_registration(profile, ctx, *args):
        if profile.home == str(home):
            entered.set()
            assert release.wait(5)
        return register(profile, ctx, *args)

    with monkeypatch.context() as pause, ThreadPoolExecutor(max_workers=1) as workers:
        pause.setattr(plugin, "_register_profile", paused_registration)
        pending = workers.submit(
            runtime.register, "a", {} if compatible else {"agent_id": "new"}
        )
        try:
            assert entered.wait(5)
            for callback in old.unload:
                callback()
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="other-id")
                for callback in other.unload:
                    callback()
            assert str(home) not in plugin._retired_sessions
            assert not original._ended.is_set()
        finally:
            release.set()
        current = pending.result(5)
    pressure = runtime.register("c")
    with runtime.profile("c"):
        pressure.emit("on_session_start", session_id="pressure-id")
        for callback in pressure.unload:
            callback()
    if compatible:
        assert not original._ended.is_set() and original.start_confirmed
        assert owner.token not in plugin._retired_owners
        with runtime.profile("a"):
            assert plugin._profiles[str(home)].sessions["same-id"] is original
            assert json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "retained"}, session_id="same-id"
                )
            ) == {"result": "retained"}
            current.emit("on_session_end", session_id="same-id")
    else:
        assert owner.status == "completed" and original._ended.is_set(), (
            "released predecessor must remain subject to retired-owner pressure"
        )
        assert owner.token not in plugin._completion_owners.get(
            (str(home), "same-id"), {}
        )
    assert sum(len(group) for group in plugin._completion_owners.values()) <= 1
    summaries = [
        r
        for r in requests_for(runtime, "/agent-summary")
        if r["url"].startswith("https://a.invalid")
    ]
    assert len(summaries) == 1


@pytest.mark.parametrize("failure", ["exception", "abandoned"])
def test_compatible_failed_reload_keeps_predecessor_outside_retired_budget(
    runtime, monkeypatch, failure
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 100)
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 1)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        predecessor = plugin._profiles[str(home)]
        original = predecessor.sessions["same-id"]
        original_id = original.intaris_session_id

    def fail_registration(profile, ctx, *args):
        if failure == "exception":
            raise RuntimeError("synthetic compatible replacement failure")
        ctx._load_abandoned = True

    with monkeypatch.context() as failed:
        failed.setattr(plugin, "_register_profile", fail_registration)
        if failure == "exception":
            with pytest.raises(
                RuntimeError, match="synthetic compatible replacement failure"
            ):
                runtime.register("a")
        else:
            runtime.register("a")
    assert plugin._profiles[str(home)] is predecessor and predecessor.active
    other = runtime.register("b")
    with runtime.profile("b"):
        other.emit("on_session_start", session_id="other-id")
        for callback in other.unload:
            callback()
    assert original.start_confirmed and not original._ended.is_set(), (
        "another home's retirement must not end a restored live predecessor"
    )
    assert original._completion.token not in plugin._retired_owners
    current = runtime.register("a")
    with runtime.profile("a"):
        assert plugin._profiles[str(home)].sessions["same-id"] is original
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "retry"}, session_id="same-id"
            )
        ) == {"result": "retry"}
        current.emit("on_session_end", session_id="same-id")
    created = [
        r
        for r in requests_for(runtime, "/intention")
        if r["url"].startswith("https://a.invalid")
    ]
    assert len(created) == 1
    assert requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == original_id


@pytest.mark.parametrize("compatible", [True, False])
def test_rollback_cleanup_protects_referenced_continuity(
    runtime, monkeypatch, compatible
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 1)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        predecessor = plugin._profiles[str(home)]
        original = predecessor.sessions["same-id"]
        original_id = original.intaris_session_id
    entered, release = threading.Event(), threading.Event()
    register = plugin._register_profile

    def fail_after_registration(profile, ctx, *args):
        register(profile, ctx, *args)
        if profile.home == str(home):
            handle = profile.registrations[-1]
            dispose = handle.dispose

            def paused_dispose():
                entered.set()
                assert release.wait(5)
                dispose()

            handle.dispose = paused_dispose
            raise RuntimeError("synthetic cleanup-boundary failure")

    with monkeypatch.context() as failed, ThreadPoolExecutor(max_workers=1) as workers:
        failed.setattr(plugin, "_register_profile", fail_after_registration)
        pending = workers.submit(
            runtime.register, "a", {} if compatible else {"agent_id": "new"}
        )
        try:
            assert entered.wait(5)
            provisional = plugin._profiles[str(home)]
            assert not provisional.active and provisional.predecessor is predecessor
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="other-id")
                for callback in other.unload:
                    callback()
            assert str(home) not in plugin._retired_sessions
            ended_during_cleanup = original._ended.is_set()
        finally:
            release.set()
        with pytest.raises(RuntimeError, match="synthetic cleanup-boundary failure"):
            pending.result(5)
    assert not ended_during_cleanup, "published ownership lasts through closing cleanup"
    assert original.start_confirmed and not original._ended.is_set()
    current = runtime.register("a")
    with runtime.profile("a"):
        assert plugin._profiles[str(home)].sessions["same-id"] is original
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "retry"}, session_id="same-id"
            )
        ) == {"result": "retry"}
        current.emit("on_session_end", session_id="same-id")
    created = [
        r
        for r in requests_for(runtime, "/intention")
        if r["url"].startswith("https://a.invalid")
    ]
    assert len(created) == 1
    assert requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == original_id


@pytest.mark.parametrize("compatible", [True, False])
def test_published_predecessor_leaves_retired_budget_after_unload_wait(
    runtime, monkeypatch, compatible
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 100)
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 1)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        predecessor = plugin._profiles[str(home)]
        original = predecessor.sessions["same-id"]
    closing, allow_close = threading.Event(), threading.Event()
    waiting, registering, allow_register = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    handle = predecessor.registrations[-1]
    dispose = handle.dispose
    closed_wait = predecessor.closed.wait
    register = plugin._register_profile

    def paused_dispose():
        closing.set()
        assert allow_close.wait(5)
        dispose()

    def observed_wait(*args, **kwargs):
        waiting.set()
        return closed_wait(*args, **kwargs)

    def fail_registration(profile, ctx, *args):
        if profile.home == str(home):
            registering.set()
            assert allow_register.wait(5)
            raise RuntimeError("synthetic post-unload replacement failure")
        return register(profile, ctx, *args)

    handle.dispose = paused_dispose
    predecessor.closed.wait = observed_wait
    with monkeypatch.context() as failed, ThreadPoolExecutor(max_workers=2) as workers:
        failed.setattr(plugin, "_register_profile", fail_registration)
        unload = workers.submit(old.unload[0])
        pending = None
        try:
            assert closing.wait(5)
            pending = workers.submit(
                runtime.register, "a", {} if compatible else {"agent_id": "new"}
            )
            assert waiting.wait(5)
            allow_close.set()
            unload.result(5)
            assert registering.wait(5)
            assert plugin._profiles[str(home)].predecessor is predecessor
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="other-id")
                for callback in other.unload:
                    callback()
            ended_while_published = original._ended.is_set()
        finally:
            allow_close.set()
            allow_register.set()
        assert pending is not None
        with pytest.raises(
            RuntimeError, match="synthetic post-unload replacement failure"
        ):
            pending.result(5)
    assert not ended_while_published, (
        "published predecessor must leave retired-owner budget"
    )
    current = runtime.register("a")
    with runtime.profile("a"):
        assert plugin._profiles[str(home)].sessions["same-id"] is original
        assert original.start_confirmed and not original._ended.is_set()
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "retry"}, session_id="same-id"
            )
        ) == {"result": "retry"}
        current.emit("on_session_end", session_id="same-id")


@pytest.mark.parametrize("compatible", [True, False])
@pytest.mark.parametrize("outcome", ["success", "failure"])
@pytest.mark.parametrize("terminal_cancel", [False, True])
def test_reload_protects_predecessor_before_unload_wait_returns(
    runtime, monkeypatch, compatible, outcome, terminal_cancel
):
    monkeypatch.setattr(plugin, "MAX_RETIRED_PROFILES", 100)
    monkeypatch.setattr(plugin, "MAX_RETIRED_OWNERS", 1)
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        predecessor = plugin._profiles[str(home)]
        original = predecessor.sessions["same-id"]
        original_id = original.intaris_session_id
        end_session = old.hooks["on_session_end"][0]
    closing, allow_close = threading.Event(), threading.Event()
    waiting, woke, allow_return = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    handle = predecessor.registrations[-1]
    dispose = handle.dispose
    closed_wait = predecessor.closed.wait
    register = plugin._register_profile

    def paused_dispose():
        closing.set()
        assert allow_close.wait(5)
        dispose()

    def paused_wait(*args, **kwargs):
        waiting.set()
        result = closed_wait(*args, **kwargs)
        woke.set()
        assert allow_return.wait(5)
        return result

    def replacement_registration(profile, ctx, *args):
        if profile.home == str(home) and outcome == "failure":
            raise RuntimeError("synthetic wakeup-gap registration failure")
        return register(profile, ctx, *args)

    handle.dispose = paused_dispose
    predecessor.closed.wait = paused_wait
    with (
        monkeypatch.context() as replacement,
        ThreadPoolExecutor(max_workers=2) as workers,
    ):
        replacement.setattr(plugin, "_register_profile", replacement_registration)
        unload = workers.submit(old.unload[0])
        pending = None
        try:
            assert closing.wait(5)
            pending = workers.submit(
                runtime.register, "a", {} if compatible else {"agent_id": "new"}
            )
            assert waiting.wait(5)
            allow_close.set()
            unload.result(5)
            assert woke.wait(5)
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="other-id")
                for callback in other.unload:
                    callback()
            ended_in_gap = original._ended.is_set()
            if terminal_cancel:
                # Host may have captured this callback before unload disposed it.
                with runtime.profile("a"):
                    end_session(session_id="same-id")
                assert original._ended.is_set()
                assert original._completion.status == "completed"
                assert "same-id" not in predecessor.sessions
        finally:
            allow_close.set()
            allow_return.set()
        assert pending is not None
        if outcome == "failure":
            with pytest.raises(
                RuntimeError, match="synthetic wakeup-gap registration failure"
            ):
                pending.result(5)
        else:
            current = pending.result(5)
    assert not ended_in_gap, (
        "reload must protect its captured predecessor before waking"
    )
    if outcome == "failure":
        current = runtime.register("a")
    if terminal_cancel:
        with runtime.profile("a"):
            current_profile = plugin._profiles[str(home)]
            assert "same-id" not in current_profile.sessions
            assert original._ended.is_set() and not original.start_confirmed
            assert original._completion.status == "completed"
            assert original._completion.token not in plugin._retired_owners
            assert not plugin._completion_owners.get((str(home), "same-id"))
            assert "error" in json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "cancelled"}, session_id="same-id"
                )
            )
            assert not requests_for(runtime, "/evaluate")
            # A later explicit start owns a distinct lifetime under the same SID.
            current.emit("on_session_start", session_id="same-id")
            fresh = current_profile.sessions["same-id"]
            assert fresh is not original and fresh._ended is not original._ended
            assert fresh.intaris_session_id != original_id
            assert fresh.start_confirmed and not fresh._ended.is_set()
            assert original._ended.is_set() and not original.start_confirmed
            assert json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "fresh"}, session_id="same-id"
                )
            ) == {"result": "fresh"}
            current.emit("on_session_end", session_id="same-id")
        assert requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == (
            fresh.intaris_session_id
        )
        summaries = [
            r
            for r in requests_for(runtime, "/agent-summary")
            if r["url"].endswith(f"/{original_id}/agent-summary")
        ]
        assert len(summaries) == 1
    elif compatible or outcome == "failure":
        with runtime.profile("a"):
            assert plugin._profiles[str(home)].sessions["same-id"] is original
            assert original.start_confirmed and not original._ended.is_set()
            assert json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "retained"}, session_id="same-id"
                )
            ) == {"result": "retained"}
            current.emit("on_session_end", session_id="same-id")
        assert (
            requests_for(runtime, "/evaluate")[-1]["body"]["session_id"] == original_id
        )
        created = [
            r
            for r in requests_for(runtime, "/intention")
            if r["url"].startswith("https://a.invalid")
        ]
        assert len(created) == 1


@pytest.mark.parametrize("compatible", [False, True])
@pytest.mark.parametrize("completed", [False, True])
@pytest.mark.parametrize("paused_call", [False, True])
def test_stale_predecessor_end_cannot_cancel_fresh_successor(
    runtime, compatible, completed, paused_call
):
    old = runtime.register("a")
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same-id")
        predecessor = plugin._profiles[str(home)]
        original = predecessor.sessions["same-id"]
        captured_end = old.hooks["on_session_end"][0]
        current = runtime.register("a", {} if compatible else {"agent_id": "new"})
        if compatible:
            current.emit("on_session_end", session_id="same-id")
        current.emit("on_session_start", session_id="same-id")
        successor = plugin._profiles[str(home)]
        fresh = successor.sessions["same-id"]
        assert fresh is not original
        assert (successor.sessions is predecessor.sessions) == compatible
        handler = runtime.guarded_entry("read_file").handler
    entered, release = threading.Event(), threading.Event()

    def hold_evaluation():
        entered.set()
        assert release.wait(5)

    def invoke():
        with runtime.profile("a"):
            return json.loads(handler({"path": "fresh"}, session_id="same-id"))

    if paused_call:
        runtime.evaluate_hook.append(hold_evaluation)
    with ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(invoke) if paused_call else None
        try:
            if paused_call:
                assert entered.wait(5)
            with runtime.profile("a"):
                captured_end(session_id="same-id", completed=completed)
            ended_before_release = fresh._ended.is_set()
        finally:
            release.set()
        result = pending.result(5) if pending is not None else invoke()
    assert original._ended.is_set()
    assert not ended_before_release, "old callback must not cancel newer owner or call"
    assert fresh.start_confirmed and successor.sessions["same-id"] is fresh
    assert fresh._completion.birth_generation == successor.generation
    assert original._completion.birth_generation == predecessor.generation
    assert result == {"result": "fresh"}
    with runtime.profile("a"):
        current.emit("on_session_end", session_id="same-id")
    assert fresh._completion.status == "completed"
    assert not plugin._active_invocations


@pytest.mark.parametrize("compatible", [False, True])
@pytest.mark.parametrize("delivery", ["predecessor", "provisional"])
@pytest.mark.parametrize("outcome", ["success", "exception", "abandoned"])
@pytest.mark.parametrize("admission", ["native", "mcp", "pre_llm"])
def test_explicit_start_survives_direct_replacement(
    runtime, monkeypatch, compatible, delivery, outcome, admission
):
    tool = {"server": "docs", "name": "read", "description": "Read", "inputSchema": {}}
    runtime.tools["a.invalid"] = [tool]
    runtime.tools["new.invalid"] = [tool]
    settings = {"mcp_tools": True, "fail_open": True}
    old = runtime.register("a", settings)
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="existing")
    changed = settings | (
        {} if compatible else {"url": "https://new.invalid", "agent_id": "new"}
    )
    register = plugin._register_profile
    injected = False

    def receive_start(profile, ctx, *args):
        nonlocal injected
        if profile.home != str(home) or injected:
            return register(profile, ctx, *args)
        injected = True
        if delivery == "provisional":
            register(profile, ctx, *args)
        source = old if delivery == "predecessor" else ctx
        source.emit(
            "on_session_start",
            session_id="new-session",
            model="pending-model",
            platform="pending-platform",
        )
        if outcome == "exception":
            raise RuntimeError("synthetic failure after start receipt")
        if outcome == "abandoned":
            ctx._load_abandoned = True
        if delivery == "predecessor":
            return register(profile, ctx, *args)

    with monkeypatch.context() as replacement:
        replacement.setattr(plugin, "_register_profile", receive_start)
        if outcome == "exception":
            with pytest.raises(
                RuntimeError, match="synthetic failure after start receipt"
            ):
                runtime.register("a", changed)
        else:
            current = runtime.register("a", changed)
    if outcome != "success":
        current = runtime.register("a", settings)
    assert not [
        r
        for r in requests_for(runtime, "/intention")
        if r["body"]["details"]["session_key"] == "new-session"
    ], "registration must not create queued remote sessions"
    with runtime.profile("a"):
        native = runtime.guarded_entry("read_file").handler
        assert "error" in json.loads(
            native({"path": "unstarted"}, session_id="unrelated")
        )
        if admission == "mcp":
            result = json.loads(
                runtime.guarded_entry("docs_read").handler({}, session_id="new-session")
            )
            expected = (
                "a.invalid" if compatible or outcome != "success" else "new.invalid"
            )
            assert result == {"result": expected}
        else:
            if admission == "pre_llm":
                current.emit(
                    "pre_llm_call", session_id="new-session", user_message="Continue"
                )
            assert json.loads(
                native({"path": "started"}, session_id="new-session")
            ) == {"result": "started"}
        state = plugin._profiles[str(home)].sessions["new-session"]
        assert state.start_confirmed and not state._ended.is_set()
        current.emit("on_session_end", session_id="new-session")
    created = [
        r
        for r in requests_for(runtime, "/intention")
        if r["body"]["details"]["session_key"] == "new-session"
    ]
    assert len(created) == 1
    expected_url = (
        "https://a.invalid"
        if compatible or outcome != "success"
        else "https://new.invalid"
    )
    assert created[0]["url"].startswith(expected_url)
    assert created[0]["body"]["details"]["model"] == "pending-model"
    assert created[0]["body"]["details"]["platform"] == "pending-platform"


@pytest.mark.parametrize("compatible", [False, True])
@pytest.mark.parametrize("delivery", ["predecessor", "provisional"])
@pytest.mark.parametrize("order", ["terminal", "terminal_start", "idle_resume"])
def test_pending_explicit_start_respects_lifecycle_order(
    runtime, monkeypatch, compatible, delivery, order
):
    old = runtime.register("a")
    with runtime.profile("a") as home:
        pass
    register = plugin._register_profile
    captured = []

    def receive_events(profile, ctx, *args):
        if delivery == "provisional":
            register(profile, ctx, *args)
        source = old if delivery == "predecessor" else ctx
        source.emit("on_session_start", session_id="pending")
        captured.append(profile.sessions.get("pending"))
        source.emit(
            "on_session_end", session_id="pending", completed=order != "idle_resume"
        )
        if order == "terminal_start":
            source.emit("on_session_start", session_id="pending")
        if delivery == "predecessor":
            return register(profile, ctx, *args)

    with monkeypatch.context() as replacement:
        replacement.setattr(plugin, "_register_profile", receive_events)
        current = runtime.register("a", {} if compatible else {"agent_id": "new"})
    assert captured[0] is not None, "explicit start must have local evidence"
    assert not requests_for(runtime, "/intention")
    with runtime.profile("a"):
        handler = runtime.guarded_entry("read_file").handler
        if order in ("terminal", "idle_resume"):
            assert "error" in json.loads(
                handler({"path": "ended"}, session_id="pending")
            )
            assert not requests_for(runtime, "/intention")
        if order == "terminal":
            assert captured[0]._ended.is_set()
            assert "pending" not in plugin._profiles[str(home)].sessions
        else:
            if order == "idle_resume":
                current.emit(
                    "pre_llm_call", session_id="pending", user_message="Resume"
                )
            else:
                assert (
                    plugin._profiles[str(home)].sessions["pending"] is not captured[0]
                )
                assert captured[0]._ended.is_set()
            assert json.loads(handler({"path": "live"}, session_id="pending")) == {
                "result": "live"
            }
            assert len(requests_for(runtime, "/intention")) == 1
            current.emit("on_session_end", session_id="pending")


@pytest.mark.parametrize("compatible", [False, True])
def test_pending_explicit_starts_share_session_capacity(
    runtime, monkeypatch, compatible
):
    monkeypatch.setattr(plugin, "MAX_SESSIONS", 2)
    old = runtime.register("a")
    register = plugin._register_profile
    captured = []

    def receive_many(profile, ctx, *args):
        for index in range(4):
            old.emit("on_session_start", session_id=f"pending-{index}")
            captured.append(profile.sessions.get(f"pending-{index}"))
        assert len(profile.sessions) <= 2
        return register(profile, ctx, *args)

    with monkeypatch.context() as replacement:
        replacement.setattr(plugin, "_register_profile", receive_many)
        current = runtime.register("a", {} if compatible else {"agent_id": "new"})
    assert all(state is not None for state in captured)
    assert not requests_for(runtime, "/intention")
    assert all(state._ended.is_set() for state in captured[:2])
    with runtime.profile("a"):
        handler = runtime.guarded_entry("read_file").handler
        assert "error" in json.loads(
            handler({"path": "evicted"}, session_id="pending-0")
        )
        assert json.loads(handler({"path": "kept"}, session_id="pending-3")) == {
            "result": "kept"
        }
        current.emit("on_session_end", session_id="pending-3")
    assert len(requests_for(runtime, "/intention")) == 1


@pytest.mark.parametrize("recreate", [False, True])
def test_pending_start_creation_cannot_rebind_ended_call(
    runtime, monkeypatch, recreate
):
    old = runtime.register("a")
    with runtime.profile("a") as home:
        pass
    register = plugin._register_profile

    def receive(profile, ctx, *args):
        old.emit("on_session_start", session_id="pending")
        return register(profile, ctx, *args)

    with monkeypatch.context() as replacement:
        replacement.setattr(plugin, "_register_profile", receive)
        current = runtime.register("a", {"agent_id": "new"})
    entered, release = threading.Event(), threading.Event()

    def hold_creation(req):
        if req.full_url.endswith("/intention") and not entered.is_set():
            entered.set()
            assert release.wait(5)

    def invoke():
        with runtime.profile("a"):
            return json.loads(
                runtime.guarded_entry("read_file").handler(
                    {"path": "abandoned"}, session_id="pending"
                )
            )

    runtime.request_hook.append(hold_creation)
    with ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(invoke)
        try:
            assert entered.wait(5)
            assert plugin._registration_locks[str(home)].acquire(blocking=False)
            plugin._registration_locks[str(home)].release()
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="other")
            with runtime.profile("a"):
                original = plugin._profiles[str(home)].sessions["pending"]
                current.emit("on_session_end", session_id="pending")
                if recreate:
                    current.emit("on_session_start", session_id="pending")
                    fresh = plugin._profiles[str(home)].sessions["pending"]
        finally:
            release.set()
        result = pending.result(5)
    assert "error" in result
    assert not requests_for(runtime, "/evaluate"), (
        "abandoned caller cannot resolve fresh SID lifetime"
    )
    assert original._ended.is_set() and not original.start_confirmed
    if recreate:
        assert (
            fresh is not original
            and fresh.start_confirmed
            and not fresh._ended.is_set()
        )
        assert plugin._profiles[str(home)].sessions["pending"] is fresh


@pytest.mark.parametrize("compatible", [False, True])
@pytest.mark.parametrize("outcome", ["exception", "abandoned"])
@pytest.mark.parametrize("delivery", ["predecessor", "provisional"])
def test_pending_start_received_during_failed_handoff_cleanup(
    runtime, monkeypatch, compatible, outcome, delivery
):
    old = runtime.register("a")
    register = plugin._register_profile
    captured = []

    def fail_after_install(profile, ctx, *args):
        register(profile, ctx, *args)
        source = old if delivery == "predecessor" else ctx
        start = source.hooks["on_session_start"][0]

        def start_during_cleanup():
            assert not profile.active and not profile.ready
            start(session_id="cleanup-start", model="cleanup-model")
            captured.append(profile.sessions.get("cleanup-start"))

        profile.registrations.append(Handle(start_during_cleanup))
        if outcome == "exception":
            raise RuntimeError("failed after installing successor hooks")
        ctx._load_abandoned = True

    with monkeypatch.context() as replacement:
        replacement.setattr(plugin, "_register_profile", fail_after_install)
        settings = {} if compatible else {"url": "https://failed.invalid"}
        if outcome == "exception":
            with pytest.raises(RuntimeError, match="failed after installing"):
                runtime.register("a", settings)
        else:
            runtime.register("a", settings)
    assert len(captured) == 1 and captured[0] is not None
    assert not requests_for(runtime, "/intention")
    current = runtime.register("a")
    with runtime.profile("a"):
        result = runtime.guarded_entry("read_file").handler(
            {"path": "after-cleanup"}, session_id="cleanup-start"
        )
        assert json.loads(result) == {"result": "after-cleanup"}
        current.emit("on_session_end", session_id="cleanup-start")
    created = requests_for(runtime, "/intention")
    assert len(created) == 1
    assert created[0]["url"] == "https://a.invalid/api/v1/intention"
    assert created[0]["body"]["details"]["model"] == "cleanup-model"


@pytest.mark.parametrize("compatible", [False, True])
@pytest.mark.parametrize("initial_idle", [False, True])
def test_pending_duplicate_starts_coalesce_without_intervening_end(
    runtime, monkeypatch, compatible, initial_idle
):
    old = runtime.register("a")
    if initial_idle:
        with runtime.profile("a"):
            old.emit("on_session_start", session_id="same")
            old.emit("on_session_end", session_id="same", completed=False)
    register = plugin._register_profile

    def receive_duplicates(profile, ctx, *args):
        old.emit("on_session_start", session_id="same", model="first")
        state = profile.sessions["same"]
        receipt = state._pending_start
        assert receipt is not None
        old.emit("on_session_start", session_id="same", model="duplicate")
        assert state._pending_start is receipt
        return register(profile, ctx, *args)

    with monkeypatch.context() as replacement:
        replacement.setattr(plugin, "_register_profile", receive_duplicates)
        current = runtime.register("a", {} if compatible else {"agent_id": "new"})
    with runtime.profile("a"):
        assert json.loads(
            runtime.guarded_entry("read_file").handler(
                {"path": "once"}, session_id="same"
            )
        ) == {"result": "once"}
        current.emit("on_session_end", session_id="same")
    assert len(requests_for(runtime, "/intention")) == (
        1 if compatible or not initial_idle else 2
    )


@pytest.mark.parametrize("admission", ["native", "mcp"])
@pytest.mark.parametrize("terminal", [False, True])
@pytest.mark.parametrize("resume_before_release", [False, True])
def test_materializing_idle_start_cannot_clear_a_later_end(
    runtime, monkeypatch, admission, terminal, resume_before_release
):
    runtime.tools["a.invalid"] = [{"server": "docs", "name": "read", "inputSchema": {}}]
    settings = {"mcp_tools": True, "fail_open": True}
    old = runtime.register("a", settings)
    with runtime.profile("a") as home:
        old.emit("on_session_start", session_id="same")
        old.emit("on_session_end", session_id="same", completed=False)
    register = plugin._register_profile

    def receive_start(profile, ctx, *args):
        old.emit("on_session_start", session_id="same")
        return register(profile, ctx, *args)

    with monkeypatch.context() as replacement:
        replacement.setattr(plugin, "_register_profile", receive_start)
        current = runtime.register("a", settings)
    state = plugin._profiles[str(home)].sessions["same"]
    entered, release = threading.Event(), threading.Event()
    resume = plugin._resume_session

    def paused_resume(*args, **kwargs):
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        return resume(*args, **kwargs)

    def invoke():
        with runtime.profile("a"):
            entry = runtime.guarded_entry(
                "read_file" if admission == "native" else "docs_read"
            )
            return json.loads(entry.handler({"path": "live"}, session_id="same"))

    monkeypatch.setattr(plugin, "_resume_session", paused_resume)
    with ThreadPoolExecutor(max_workers=1) as workers:
        pending = workers.submit(invoke)
        try:
            assert entered.wait(5)
            with runtime.profile("a"):
                current.emit("on_session_end", session_id="same", completed=terminal)
            cancelled = state._ended
            if resume_before_release:
                with runtime.profile("a"):
                    if terminal:
                        current.emit("on_session_start", session_id="same")
                    else:
                        current.emit(
                            "pre_llm_call",
                            session_id="same",
                            user_message="New user input",
                        )
        finally:
            release.set()
        assert "error" in pending.result(5)
    assert cancelled.is_set()
    assert not requests_for(runtime, "/evaluate")
    assert not requests_for(runtime, "/mcp/call")
    if not resume_before_release:
        assert "error" in invoke(), (
            "later tool must not consume an idle-invalidated start"
        )
        assert state._ended is cancelled
        assert state.is_idle is (not terminal)
        with runtime.profile("a"):
            current.emit("on_session_start", session_id="same")
    assert invoke() == {"result": "live" if admission == "native" else "a.invalid"}


def _host_materialization_dispatch(runtime, monkeypatch):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("Set HERMES_SOURCE to exercise parallel real Hermes dispatch")
    import tools.registry as registry_module
    from hermes_cli import lifecycle, plugins

    monkeypatch.setattr(registry_module, "discover_builtin_tools", lambda: None)
    monkeypatch.setattr(plugins, "discover_plugins", lambda *a, **k: None)
    monkeypatch.setattr(lifecycle, "_observe", lambda *a, **k: None)
    monkeypatch.delitem(sys.modules, "model_tools", raising=False)
    model_tools = importlib.import_module("model_tools")
    monkeypatch.setattr(model_tools, "registry", runtime.registry)
    with runtime.profile("a") as home:
        manager = plugins.PluginManager(scope_key=str(home))
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)

    def invoke(admission, label):
        with runtime.profile("a"):
            return json.loads(
                model_tools.handle_function_call(
                    "read_file" if admission == "native" else "docs_read",
                    {"path": label},
                    task_id=f"task-{label}",
                    session_id="same",
                    tool_call_id=f"call-{label}",
                    skip_tool_request_middleware=True,
                    skip_tool_execution_middleware=True,
                )
            )

    return invoke


def _pending_handoff_for_parallel_calls(
    runtime, monkeypatch, replay_start=False, idle=False
):
    runtime.tools["a.invalid"] = [{"server": "docs", "name": "read", "inputSchema": {}}]
    settings = {"mcp_tools": True, "fail_open": True}
    old = runtime.register("a", settings)
    if idle:
        with runtime.profile("a"):
            old.emit("on_session_start", session_id="same")
            old.emit("on_session_end", session_id="same", completed=False)
    register = plugin._register_profile

    def receive_start(profile, ctx, *args):
        old.emit("on_session_start", session_id="same")
        return register(profile, ctx, *args)

    with monkeypatch.context() as replacement:
        replacement.setattr(plugin, "_register_profile", receive_start)
        current = runtime.register("a", settings)
    if replay_start:
        with runtime.profile("a"):
            current.emit("on_session_start", session_id="same")
    return current


@pytest.mark.parametrize("admission", ["native", "mcp"])
@pytest.mark.parametrize(
    "schedule", ["creating", "confirming", "resuming", "already_started"]
)
def test_real_hermes_parallel_first_calls_share_materialization(
    runtime, monkeypatch, admission, schedule
):
    invoke = _host_materialization_dispatch(runtime, monkeypatch)
    _pending_handoff_for_parallel_calls(
        runtime,
        monkeypatch,
        replay_start=schedule == "already_started",
        idle=schedule == "resuming",
    )
    entered, release, follower_entered = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    both_returned = threading.Barrier(2)
    ensure = plugin._ensure_session

    resume = plugin._resume_session

    def overlap_resume(*args, **kwargs):
        if schedule == "resuming":
            entered.set()
            both_returned.wait(5)
        return resume(*args, **kwargs)

    monkeypatch.setattr(plugin, "_resume_session", overlap_resume)

    def pause_creation(req):
        if req.full_url.endswith("/intention") and schedule == "creating":
            entered.set()
            assert release.wait(5)

    def overlap_ensure(*args, **kwargs):
        if entered.is_set():
            follower_entered.set()
        result = ensure(*args, **kwargs)
        if schedule == "confirming":
            assert result is not None
            entered.set()
            both_returned.wait(5)
        return result

    runtime.request_hook.append(pause_creation)
    monkeypatch.setattr(plugin, "_ensure_session", overlap_ensure)
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(invoke, admission, "one")
        try:
            if schedule != "already_started":
                assert entered.wait(5), (
                    first.result() if first.done() else "no creation"
                )
            second = workers.submit(invoke, admission, "two")
            if schedule == "creating":
                assert follower_entered.wait(5)
        finally:
            release.set()
        results = [first.result(5), second.result(5)]
    assert results == [
        {"result": "one" if admission == "native" else "a.invalid"},
        {"result": "two" if admission == "native" else "a.invalid"},
    ]
    assert len(requests_for(runtime, "/intention")) == 1
    calls = requests_for(runtime, "/evaluate" if admission == "native" else "/mcp/call")
    assert len(calls) == 2 and len({req["body"]["session_id"] for req in calls}) == 1


@pytest.mark.parametrize("admission", ["native", "mcp"])
@pytest.mark.parametrize("stop", ["idle", "terminal_recreate", "interrupt"])
def test_parallel_materialization_waiter_stops_before_creation_returns(
    runtime, monkeypatch, admission, stop
):
    invoke = _host_materialization_dispatch(runtime, monkeypatch)
    from tools import interrupt

    current = _pending_handoff_for_parallel_calls(runtime, monkeypatch)
    entered, release, following, follower_done = (threading.Event() for _ in range(4))
    follower_thread = []
    ensure = plugin._ensure_session

    def block_creation(req):
        if req.full_url.endswith("/intention") and not entered.is_set():
            entered.set()
            assert release.wait(5)

    def capture_follower(*args, **kwargs):
        if follower_thread and threading.get_ident() == follower_thread[0]:
            following.set()
        return ensure(*args, **kwargs)

    def follow():
        follower_thread.append(threading.get_ident())
        try:
            return invoke(admission, "follower")
        finally:
            follower_done.set()

    runtime.request_hook.append(block_creation)
    monkeypatch.setattr(plugin, "_ensure_session", capture_follower)
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(invoke, admission, "creator")
        try:
            assert entered.wait(5)
            second = workers.submit(follow)
            assert following.wait(5)
            assert not follower_done.wait(0.2), (
                "uncancelled follower must await shared creation"
            )
            with runtime.profile("a") as home:
                profile = plugin._profiles[str(home)]
                original = profile.sessions["same"]
                # Creation/waiting must not hold map/global/home registration locks.
                for lock in (
                    plugin._profiles_lock,
                    profile.sessions_lock,
                    plugin._registration_locks[str(home)],
                ):
                    assert lock.acquire(blocking=False)
                    lock.release()
                if stop == "interrupt":
                    interrupt.set_interrupt(True, follower_thread[0])
                else:
                    current.emit(
                        "on_session_end", session_id="same", completed=stop != "idle"
                    )
                    if stop == "terminal_recreate":
                        current.emit("on_session_start", session_id="same")
                        fresh = profile.sessions["same"]
                        assert fresh is not original
            other = runtime.register("b")
            with runtime.profile("b"):
                other.emit("on_session_start", session_id="other")
            assert follower_done.wait(1), (
                "cancellation must release follower while HTTP remains blocked"
            )
            assert "error" in second.result(1)
            assert not requests_for(runtime, "/evaluate")
            assert not requests_for(runtime, "/mcp/call")
        finally:
            release.set()
            if follower_thread:
                interrupt.set_interrupt(False, follower_thread[0])
        first_result = first.result(5)
    if stop == "interrupt":
        assert first_result == {
            "result": "creator" if admission == "native" else "a.invalid"
        }
    else:
        assert "error" in first_result
        assert original._ended.is_set()
        if stop == "terminal_recreate":
            assert profile.sessions["same"] is fresh and fresh.start_confirmed
