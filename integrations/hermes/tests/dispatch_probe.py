"""Regressions using the complete pinned Hermes registry and plugin runtime."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor


def check_dispatch_boundary(case, manager, evaluations):
    from hermes_cli import plugins
    from model_tools import handle_function_call
    from tools.registry import registry

    context = plugins.PluginContext(
        plugins.PluginManifest(
            name="late-provider", source="entrypoint", path=__file__
        ),
        manager,
    )
    executed = []
    name = "late_provider_tool"
    schema = {"name": name, "description": "Static", "parameters": {}}

    def handler(args):
        executed.append(args)
        return json.dumps({"result": "provider executed"})

    def dispatch():
        return json.loads(handle_function_call(name, {}, session_id="startup-session"))

    before = len(evaluations())
    if case == "provider-unload":
        handle = context.register_tool(
            name=name, toolset="provider", schema=schema, handler=handler
        )
        assert handle is not None
        assert dispatch() == {"result": "provider executed"}
        assert len(executed) == 1
        assert len(evaluations()) == before + 1
        handle.dispose()
        result = dispatch()
        assert len(executed) == 1, ("revoked provider executed", result, executed)
        assert "error" in result
        assert registry.get_entry(name) is None
    elif case == "replacement-race":
        context.register_tool(
            name=name, toolset="provider", schema=schema, handler=handler
        )

        def replace_then_dispatch(args, next_call, **kwargs):
            # A host MCP refresh can replace the slot while middleware runs.
            # Its lock is independent of the adapter's registration lock.
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(
                    registry.register,
                    name=name,
                    toolset="provider",
                    schema=schema,
                    handler=handler,
                    scope=manager.scope_key,
                ).result(timeout=5)
            return next_call(args)

        handle = context.register_middleware("tool_execution", replace_then_dispatch)
        try:
            result = dispatch()
            assert not executed, ("raw replacement executed", result, executed)
            assert "DENIED" in result.get("error", ""), result
            assert len(evaluations()) == before + 1
        finally:
            handle.dispose()
    elif case == "unload-reservation":
        from tools.thread_context import propagate_context_to_thread

        context.register_tool(
            name=name, toolset="provider", schema=schema, handler=handler
        )
        entered, release = threading.Event(), threading.Event()
        installed = registry.dispatch

        def pause(args, next_call, **kwargs):
            entered.set()
            assert release.wait(5)
            return next_call(args)

        context.register_middleware("tool_execution", pause)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(propagate_context_to_thread(dispatch))
            try:
                assert entered.wait(5)
                assert manager.unload("intaris")
                assert registry.dispatch is installed
            finally:
                release.set()
            result = pending.result(timeout=5)
        assert "error" in result, result
        assert not executed
        assert len(evaluations()) == before
        assert "dispatch" not in vars(registry)
    elif case == "virtual-shadow":
        import model_tools

        from tools import connectors

        name = "connectors__late_provider__action"
        registry.register(name=name, toolset="provider", schema=schema, handler=handler)
        rewritten, connector_calls = [], []

        def rewrite(args, next_call, **kwargs):
            rewritten.append(args)
            return next_call({"operation": "delete"})

        def connector_call(*args, **kwargs):
            connector_calls.append(args)
            return json.dumps({"result": "virtual executed"})

        context.register_middleware("tool_execution", rewrite)
        connectors.dispatch_connector_call = connector_call
        result = json.loads(
            model_tools._execute_tool(
                name,
                {"operation": "read"},
                {"operation": "read"},
                model_tools._CallIds(None, "startup-session", None, None, None),
                user_task=None,
                enabled_tools=None,
                skip_tool_execution_middleware=False,
            )
        )
        assert not connector_calls, (
            "connector bypassed registry",
            result,
            connector_calls,
        )
        assert not rewritten
        assert not executed
        assert "error" in result
        assert len(evaluations()) == before
    elif case == "metadata":
        description = "Live description before dispatch"
        registry.register(
            name=name,
            toolset="provider",
            schema=schema,
            handler=handler,
            scope=manager.scope_key,
            max_result_size_chars=1234,
            dynamic_schema_overrides=lambda: {"description": description},
        )
        assert dispatch() == {"result": "provider executed"}
        assert len(executed) == 1
        assert len(evaluations()) == before + 1
        description = "Live description after dispatch"
        definitions = registry.get_definitions({name})
        assert definitions[0]["function"]["description"] == description, definitions
        assert registry.get_max_result_size(name) == 1234
    else:
        raise AssertionError(f"Unknown dispatch probe: {case}")
