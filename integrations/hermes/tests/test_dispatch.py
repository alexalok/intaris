"""Terminal-dispatch ownership, revocation and host compatibility contracts."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
from pathlib import Path

import hermes_intaris as plugin
import pytest

from .test_profiles import Context, requests_for
from .test_profiles import runtime as profile_runtime

runtime = profile_runtime


@pytest.mark.parametrize("change", ["remove", "replace", "mutate"])
@pytest.mark.parametrize("is_async", [False, True])
def test_source_change_during_approval_blocks_captured_and_replacement_handlers(
    runtime, change, is_async
):
    ctx = runtime.register("a")
    executed = []

    def native(args):
        executed.append("original")
        return json.dumps({"result": "original"})

    async def async_native(args):
        return native(args)

    def replacement(args):
        executed.append("replacement")
        return json.dumps({"result": "replacement"})

    with runtime.profile("a") as home:
        provider = Context(runtime.registry, home)
        handle = provider.register_tool(
            name="late_provider",
            toolset="provider",
            schema={},
            handler=async_native if is_async else native,
            is_async=is_async,
        )
        source = runtime.registry.get_entry("late_provider")
        ctx.emit("on_session_start", session_id="s")
        client = plugin._profiles[str(home)].client
        evaluate = client.evaluate

        def revoke_after_evaluation(*args, **kwargs):
            result = evaluate(*args, **kwargs)
            if change == "remove":
                handle.dispose()
            elif change == "replace":
                provider.register_tool(
                    name="late_provider",
                    toolset="provider",
                    schema={},
                    handler=replacement,
                )
            else:
                source.handler = replacement
            return result

        client.evaluate = revoke_after_evaluation
        result = json.loads(ctx.execute("late_provider", {}, session_id="s"))
    assert "registration changed" in result.get("error", "")
    assert not executed
    assert len(requests_for(runtime, "/evaluate")) == 1


@pytest.mark.parametrize("reload", [False, True])
def test_middleware_reservation_survives_unload_and_never_switches_generation(
    runtime, reload
):
    ctx = runtime.register("a")
    entered, release = threading.Event(), threading.Event()
    results = []
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="s")
    saved_dispatch = runtime.registry.dispatch

    def pause(args, next_call, **kwargs):
        entered.set()
        assert release.wait(5)
        return next_call(args)

    ctx.register_middleware("tool_execution", pause)

    def invoke():
        with runtime.profile("a"):
            results.append(
                json.loads(ctx.execute("read_file", {"path": "old"}, session_id="s"))
            )

    thread = threading.Thread(target=invoke)
    thread.start()
    try:
        assert entered.wait(5)
        for unload in ctx.unload:
            unload()
        assert runtime.registry.dispatch is saved_dispatch
        if reload:
            fresh = runtime.register("a")
            with runtime.profile("a"):
                fresh.emit("on_session_start", session_id="fresh")
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert "error" in results[0]
    assert not requests_for(runtime, "/evaluate")
    if reload:
        with runtime.profile("a"):
            assert json.loads(
                fresh.execute("read_file", {"path": "new"}, session_id="fresh")
            ) == {"result": "new"}
        assert len(requests_for(runtime, "/evaluate")) == 1
    else:
        assert "dispatch" not in vars(runtime.registry)


def test_separate_plugin_imports_share_dispatcher_and_keep_profile_owners(
    runtime, monkeypatch
):
    a = runtime.register("a")
    installed = runtime.registry.dispatch
    alias = "isolated_hermes_intaris"
    spec = importlib.util.spec_from_file_location(
        alias,
        plugin.__file__,
        submodule_search_locations=[str(Path(plugin.__file__).parent)],
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, alias, module)
    spec.loader.exec_module(module)
    with runtime.profile("b") as home_b:
        b = Context(
            runtime.registry,
            home_b,
            {
                "url": "https://b.invalid",
                "api_key": "key-b",
                "user_id": "b",
                "mcp_tools": False,
                "checkpoint_interval": 0,
            },
        )
        module.register(b)
        b.emit("on_session_start", session_id="same")
    assert runtime.registry.dispatch is installed
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same")
        assert "error" in json.loads(
            runtime.registry.dispatch(
                "read_file", {"path": "blocked"}, session_id="same", scope=str(home_b)
            )
        )
        assert json.loads(a.execute("read_file", {"path": "a"}, session_id="same")) == {
            "result": "a"
        }
    with runtime.profile("b"):
        assert json.loads(b.execute("read_file", {"path": "b"}, session_id="same")) == {
            "result": "b"
        }
        for unload in a.unload:
            unload()
        assert json.loads(
            b.execute("read_file", {"path": "b2"}, session_id="same")
        ) == {"result": "b2"}
    # A separately imported generation can reload the first home while B stays
    # active; it must reuse the same coordinator rather than stack another shim.
    with runtime.profile("a") as home_a:
        fresh = Context(
            runtime.registry,
            home_a,
            {
                "url": "https://a.invalid",
                "api_key": "key-a",
                "user_id": "a",
                "mcp_tools": False,
                "checkpoint_interval": 0,
            },
        )
        module.register(fresh)
        fresh.emit("on_session_start", session_id="fresh")
        assert runtime.registry.dispatch is installed
        assert json.loads(
            fresh.execute("read_file", {"path": "a2"}, session_id="fresh")
        ) == {"result": "a2"}
        for unload in fresh.unload:
            unload()
    for unload in b.unload:
        unload()
    assert "dispatch" not in vars(runtime.registry)
    assert [r["headers"]["X-user-id"] for r in requests_for(runtime, "/evaluate")] == [
        "a",
        "b",
        "b",
        "a",
    ]


def test_teardown_does_not_overwrite_later_dispatch_wrapper(runtime):
    ctx = runtime.register("a")
    saved = runtime.registry.dispatch

    def later(*args, **kwargs):
        return saved(*args, **kwargs)

    runtime.registry.dispatch = later
    for unload in ctx.unload:
        unload()
    assert runtime.registry.dispatch is later


def test_scope_switch_inside_middleware_blocks_before_evaluation(runtime):
    a, b = runtime.register("a"), runtime.register("b")
    with runtime.profile("a"):
        a.emit("on_session_start", session_id="same")
    with runtime.profile("b"):
        b.emit("on_session_start", session_id="same")

    def cross_profile(args, next_call, **kwargs):
        with runtime.profile("b"):
            return next_call(args)

    a.register_middleware("tool_execution", cross_profile)
    with runtime.profile("a"):
        result = json.loads(
            a.execute("read_file", {"path": "blocked"}, session_id="same")
        )
    assert "error" in result
    assert not requests_for(runtime, "/evaluate")


def test_dispatch_keeps_host_async_kwargs_and_multimodal_result(runtime):
    ctx = runtime.register("a")
    calls = []
    result = {"_multimodal": True, "content": [{"type": "text", "text": "ok"}]}

    async def narrow(args, task_id=None):
        calls.append((args, task_id))
        return result

    runtime.registry.register(
        name="late_multimodal",
        toolset="provider",
        schema={},
        handler=narrow,
        is_async=True,
    )
    with runtime.profile("a"):
        ctx.emit("on_session_start", session_id="s")
        assert (
            ctx.execute("late_multimodal", {"value": 1}, session_id="s", task_id="task")
            == result
        )
    assert calls == [({"value": 1}, "task")]
    assert len(requests_for(runtime, "/evaluate")) == 1
