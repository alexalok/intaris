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
from functools import partial
from pathlib import Path

import hermes_intaris as plugin
import pytest


class ScopedRegistry:
    def __init__(self, home):
        self.home = home
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
        target = self.scoped[scope]
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


class Context:
    """Only the supported PluginContext calls used by this adapter."""

    def __init__(self, registry, home, settings=None):
        self.registry = registry
        self.home = str(home)
        self.settings = settings or {}
        self.hooks = {}
        self.unload = []

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_tool(self, **kwargs):
        name = kwargs["name"]
        previous = self.registry.snapshot_registration(name, scope=self.home)
        defaults = dict(check_fn=None, requires_env=[], is_async=False, emoji="")
        self.registry.register(**(defaults | kwargs), scope=self.home)
        current = self.registry.snapshot_registration(name, scope=self.home)
        return Handle(
            lambda: self.registry.restore_registration(
                name, current, previous, scope=self.home
            )
        )

    def register_hook(self, name, handler):
        self.hooks.setdefault(name, []).append(handler)
        return Handle(lambda: self.hooks[name].remove(handler))

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
            result = {"decision": "approve", "content": [{"text": req.host}]}
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

    yield types.SimpleNamespace(
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


def requests_for(runtime, suffix):
    return [r for r in runtime.requests if r["url"].endswith(suffix)]


@pytest.mark.parametrize("order", [("a", "b"), ("b", "a")])
def test_existing_wrapper_and_same_session_id_keep_profile_client(runtime, order):
    contexts, handlers = {}, {}
    for name in order:
        contexts[name] = runtime.register(name)
        with runtime.profile(name):
            contexts[name].emit("on_session_start", session_id="same-id")
            handlers[name] = runtime.registry.get_entry("read_file").handler

    for name in ("a", "b"):
        with runtime.profile(name):
            assert json.loads(handlers[name]({"path": name}))["result"] == name
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
        return runtime.registry.get_entry("read_file").handler({"path": "ok"})

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
        handler = runtime.registry.get_entry("private_a").handler
    b = runtime.register("b")
    with runtime.profile("b"):
        b.emit("on_session_start", session_id="same-id")
        assert runtime.registry.get_entry("private_a") is None
        assert runtime.registry.get_entry("private_b") is not None
    with runtime.profile("a"):
        assert runtime.registry.get_entry("private_b") is None
        assert json.loads(handler({}))["result"] == "a.invalid"
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
        runtime.registry.get_entry("read_file").handler({"path": "ok"})
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
            runtime.registry.get_entry("read_file").handler({"path": "ok"})
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
    with runtime.profile("a"):
        assert json.loads(
            runtime.registry.get_entry("read_file").handler({"path": "ok"})
        ) == {"result": "ok"}
    with runtime.profile("b"):
        assert "error" in json.loads(
            runtime.registry.get_entry("read_file").handler({"path": "ok"})
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
        handler = runtime.registry.get_entry("read_file").handler
    runtime.register("b")
    with runtime.profile("b"):
        assert "error" in json.loads(handler({"path": "must-not-run"}))
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
            runtime.registry.get_entry("read_file").handler({"path": "ok"})
    evaluated = requests_for(runtime, "/evaluate")
    assert [r["url"] for r in evaluated] == [
        "https://a.invalid/api/v1/evaluate",
        "https://b.invalid/api/v1/evaluate",
    ]
    assert [r["headers"]["Authorization"] for r in evaluated] == [
        "Bearer key-a",
        "Bearer key-b",
    ]


def test_reloading_profile_retires_old_callbacks_and_mcp_exposure(runtime):
    runtime.tools["a.invalid"] = [{"server": "old", "name": "tool"}]
    old = runtime.register("a", {"mcp_tools": True, "session_recording": True})
    with runtime.profile("a"):
        old.emit("on_session_start", session_id="same-id")
        old.emit(
            "post_llm_call", session_id="same-id", assistant_response="before reload"
        )
        handler = runtime.registry.get_entry("read_file").handler
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
        runtime.registry.get_entry("read_file").handler({"path": "ok"})
        assert "error" in json.loads(handler({"path": "must-not-run"}))
        timer.fire()
    assert timer.cancelled
    assert len(Timer.instances) == 1
    assert requests_for(runtime, "/events")[0]["url"].startswith("https://a.invalid/")
    assert [r["url"] for r in requests_for(runtime, "/evaluate")] == [
        "https://new.invalid/api/v1/evaluate"
    ]


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
    with runtime.profile("a"):
        runtime.registry.get_entry("read_file").handler({"path": "ok"})
        assert runtime.registry.get_entry("b_tool") is None
    # Host unload can be requested from another profile, but releases only A.
    with runtime.profile("b"):
        managers["a"].unload()
        runtime.registry.get_entry("read_file").handler({"path": "ok"})
        assert runtime.registry.get_entry("b_tool") is not None
    with runtime.profile("a"):
        assert runtime.registry.get_entry("a_tool") is None
        assert not getattr(
            runtime.registry.get_entry("read_file").handler,
            "_intaris_original_handler",
            None,
        )
    assert [r["headers"]["X-user-id"] for r in requests_for(runtime, "/evaluate")] == [
        "a",
        "b",
    ]
    assert Timer.instances[0].cancelled
    with runtime.profile("b"):
        managers["b"].unload()


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
            json.loads(runtime.registry.get_entry("read_file").handler({"path": "ok"}))[
                "result"
            ]
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
            json.loads(runtime.registry.get_entry("read_file").handler({"path": "ok"}))[
                "result"
            ]
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
                json.loads(tool.handler({name: "input"}))["result"] == f"{name}.invalid"
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
            runtime.registry.get_entry("read_file").handler,
            "_intaris_original_handler",
            None,
        )
