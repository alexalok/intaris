"""Startup and late-registration safety through ordinary Hermes dispatch."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from pathlib import Path

import hermes_intaris as plugin
import pytest

from .test_profiles import requests_for
from .test_profiles import runtime as profile_runtime

runtime = profile_runtime


def add_late_tool(runtime, name="terminal", *, is_async=False):
    executed = []

    def handler(args, **kwargs):
        executed.append((args, kwargs))
        return json.dumps({"result": "executed"})

    async def async_handler(args, **kwargs):
        return handler(args, **kwargs)

    runtime.registry.register(
        name=name,
        toolset="terminal",
        schema={"name": name, "parameters": {}},
        handler=async_handler if is_async else handler,
        check_fn=None,
        requires_env=[],
        is_async=is_async,
        description="Late tool",
        emoji="",
    )
    return executed


@pytest.mark.parametrize("is_async", [False, True])
def test_plugin_first_late_tool_denied_before_dispatch(runtime, is_async):
    ctx = runtime.register("a")
    executed = add_late_tool(runtime, is_async=is_async)
    with runtime.profile("a") as home:
        ctx.emit("on_session_start", session_id="s")
        client = plugin._profiles[str(home)].client
        original = client.evaluate

        def deny(*args, **kwargs):
            result = original(*args, **kwargs)
            result.data["decision"] = "deny"
            return result

        client.evaluate = deny
        result = json.loads(ctx.execute("terminal", {"command": "pwd"}, session_id="s"))
    assert "DENIED" in result.get("error", "")
    assert executed == []
    assert len(requests_for(runtime, "/evaluate")) == 1


def test_late_tool_approved_once_and_existing_guard_not_double_evaluated(runtime):
    ctx = runtime.register("a")
    executed = add_late_tool(runtime)
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="s")
        assert json.loads(
            ctx.execute("terminal", {"command": "pwd"}, session_id="s")
        ) == {"result": "executed"}
        assert json.loads(ctx.execute("read_file", {"path": "ok"}, session_id="s")) == {
            "result": "ok"
        }
    assert len(executed) == 1
    assert [r["body"]["tool"] for r in requests_for(runtime, "/evaluate")] == [
        "terminal",
        "read_file",
    ]


@pytest.mark.parametrize("point", ["factory", "evaluation"])
def test_middleware_safety_exception_cannot_fail_open(runtime, monkeypatch, point):
    ctx = runtime.register("a")
    executed = add_late_tool(runtime)
    with runtime.profile("a") as home:
        ctx.emit("on_session_start", session_id="s")

        def fail(*args, **kwargs):
            raise RuntimeError("safety failed")

        if point == "factory":
            monkeypatch.setattr(plugin, "_make_guarded_handler", fail)
        else:
            monkeypatch.setattr(plugin._profiles[str(home)].client, "evaluate", fail)
        result = json.loads(ctx.execute("terminal", {"command": "pwd"}, session_id="s"))
    assert "error" in result
    assert executed == []


def test_late_tool_keeps_profiles_and_explicit_session_binding(runtime):
    contexts = {name: runtime.register(name) for name in ("a", "b")}
    executed = add_late_tool(runtime)
    for name in ("a", "b"):
        with runtime.profile(name):
            ctx = contexts[name]
            ctx.emit("on_session_start", session_id="same-id")
            assert "error" in json.loads(ctx.execute("terminal", {"command": "pwd"}))
            assert json.loads(
                ctx.execute("terminal", {"command": "pwd"}, session_id="same-id")
            ) == {"result": "executed"}
    assert len(executed) == 2
    assert [r["headers"]["X-user-id"] for r in requests_for(runtime, "/evaluate")] == [
        "a",
        "b",
    ]


def test_execution_middleware_has_profile_owned_teardown(runtime):
    first = runtime.register("a")
    second = runtime.register("a")
    assert not first.middleware.get("tool_execution")
    assert len(second.middleware.get("tool_execution", [])) == 1
    for unload in second.unload:
        unload()
    assert not second.middleware.get("tool_execution")


@pytest.mark.parametrize("startup", ["cli", "cli-race", "gateway", "builtins-first"])
def test_full_hermes_startup_and_late_registration(tmp_path, startup):
    source = os.environ.get("HERMES_SOURCE")
    if not source:
        pytest.skip("set HERMES_SOURCE for full Hermes startup contract tests")
    home = tmp_path / "hermes"
    installed = home / "plugins/intaris"
    installed.mkdir(parents=True)
    adapter = Path(__file__).resolve().parents[1]
    (installed / "plugin.yaml").write_text(
        (adapter / "hermes_intaris/plugin.yaml").read_text()
    )
    (installed / "__init__.py").write_text("from hermes_intaris import register\n")
    (home / "config.yaml").write_text(
        json.dumps(
            {
                "plugins": {
                    "enabled": ["intaris"],
                    "entries": {"intaris": {"allow_tool_override": True}},
                },
                "terminal": {"backend": "local", "cwd": str(tmp_path)},
                "mcp_servers": {},
            }
        )
    )
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "HERMES_HOME": str(home),
        "PYTHONPATH": os.pathsep.join(
            (str(adapter), source, os.environ.get("PYTHONPATH", ""))
        ),
        "PYTHONDONTWRITEBYTECODE": "1",
        "INTARIS_API_KEY": "startup-test-key",
        "INTARIS_URL": "https://intaris.invalid",
        "INTARIS_MCP_TOOLS": "false",
        "INTARIS_CHECKPOINT_INTERVAL": "0",
        "TERMINAL_CWD": str(tmp_path),
        "TERMINAL_ENV": "local",
    }
    result = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("startup_probe.py")), startup],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "startup contract passed" in result.stdout


def test_middleware_does_not_duplicate_mcp_evaluation(runtime):
    runtime.tools["a.invalid"] = [{"server": "test", "name": "tool"}]
    ctx = runtime.register("a", {"mcp_tools": True})
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="s")
        assert json.loads(ctx.execute("test_tool", {}, session_id="s")) == {
            "result": "a.invalid"
        }
    assert not requests_for(runtime, "/evaluate")
    assert len(requests_for(runtime, "/mcp/call")) == 1


def test_foreign_wrapper_evaluates_transformed_args_once(runtime):
    ctx = runtime.register("a")
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="s")
        entry = runtime.registry.get_entry("read_file")
        original = entry.handler

        @wraps(original)
        def transformed(args, **kwargs):
            return original({"path": "changed"}, **kwargs)

        entry.handler = transformed
        assert json.loads(
            ctx.execute("read_file", {"path": "original"}, session_id="s")
        ) == {"result": "changed"}
    evaluations = requests_for(runtime, "/evaluate")
    assert len(evaluations) == 1
    assert evaluations[0]["body"]["args"] == {"path": "changed"}


def test_middleware_does_not_retry_downstream_failure(runtime):
    ctx = runtime.register("a")
    executed = add_late_tool(runtime)
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="s")
        entry = runtime.registry.get_entry("terminal")
        original = entry.handler

        def fail(args, **kwargs):
            original(args, **kwargs)
            raise RuntimeError("tool failed after execution")

        entry.handler = fail
        assert "error" in json.loads(
            ctx.execute("terminal", {"command": "pwd"}, session_id="s")
        )
    assert len(executed) == 1
    assert len(requests_for(runtime, "/evaluate")) == 1


def test_retained_middleware_cannot_dispatch_in_another_or_unloaded_profile(runtime):
    ctx = runtime.register("a")
    executed = add_late_tool(runtime)
    callback = ctx.middleware["tool_execution"][0]
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="s")
    for name in ("b", "a"):
        if name == "a":
            for unload in ctx.unload:
                unload()
        with runtime.profile(name):
            result = callback(
                tool_name="terminal",
                args={},
                session_id="s",
                next_call=lambda args: executed.append(args),
            )
            assert "error" in json.loads(result)
    assert not executed
    assert not requests_for(runtime, "/evaluate")


def test_late_tool_evaluates_final_execution_middleware_args(runtime):
    ctx = runtime.register("a")
    executed = add_late_tool(runtime)
    ctx.register_middleware(
        "tool_execution", lambda next_call, **kwargs: next_call({"command": "blocked"})
    )
    with runtime.profile("a") as home:
        ctx.emit("on_session_start", session_id="s")
        client = plugin._profiles[str(home)].client
        original = client.evaluate

        def evaluate(session_id, name, args, **kwargs):
            result = original(session_id, name, args, **kwargs)
            result.data["decision"] = (
                "deny" if args["command"] == "blocked" else "approve"
            )
            return result

        client.evaluate = evaluate
        result = json.loads(ctx.execute("terminal", {"command": "pwd"}, session_id="s"))
    assert "DENIED" in result.get("error", "")
    assert not executed
    evaluations = requests_for(runtime, "/evaluate")
    assert len(evaluations) == 1
    assert evaluations[0]["body"]["args"] == {"command": "blocked"}


def test_concurrent_late_dispatch_does_not_hold_registration_lock_during_evaluation(
    runtime,
):
    ctx = runtime.register("a")
    executed = add_late_tool(runtime)
    evaluating = threading.Barrier(2)
    runtime.evaluate_hook.append(lambda: evaluating.wait(timeout=5))
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="s")
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    runtime.worker(
                        lambda: ctx.execute(
                            "terminal", {"command": "pwd"}, session_id="s"
                        )
                    )
                )
                for _ in range(2)
            ]
            assert [json.loads(f.result(timeout=10)) for f in futures] == [
                {"result": "executed"}
            ] * 2
    assert len(executed) == 2
    assert len(requests_for(runtime, "/evaluate")) == 2


def test_late_tool_retains_registry_guard_after_first_ordinary_dispatch(runtime):
    ctx = runtime.register("a")
    executed = add_late_tool(runtime)
    with runtime.profile("a") as home:
        ctx.emit("on_session_start", session_id="s")
        ctx.execute("terminal", {"command": "pwd"}, session_id="s")
        client = plugin._profiles[str(home)].client
        original = client.evaluate

        def deny(*args, **kwargs):
            result = original(*args, **kwargs)
            result.data["decision"] = "deny"
            return result

        client.evaluate = deny
        result = json.loads(
            runtime.registry.dispatch("terminal", {"command": "pwd"}, session_id="s")
        )
    assert "DENIED" in result.get("error", "")
    assert len(executed) == 1
    assert len(requests_for(runtime, "/evaluate")) == 2
