"""Isolated full-module Hermes startup probe, launched by test_startup.py.

Only HTTP responses are replaced. Plugin discovery, background loader,
PluginContext, middleware, model_tools, registry and terminal are real.
"""

from __future__ import annotations

import io
import json
import shlex
import sys
import urllib.request
from types import SimpleNamespace


def main() -> None:
    requests = []
    decision = "deny"

    def urlopen(req, **kwargs):
        assert req.full_url.startswith("https://intaris.invalid/"), req.full_url
        payload = json.loads(req.data) if req.data else None
        requests.append((req.full_url, payload))
        data = {"ok": True}
        if req.full_url.endswith("/evaluate"):
            data = {
                "decision": decision,
                "call_id": "startup-call",
                "risk": "low",
                "latency_ms": 1,
            }
        response = io.BytesIO(json.dumps(data).encode())
        response.status = 200
        return response

    urllib.request.urlopen = urlopen
    from hermes_cli import plugins
    from hermes_constants import get_hermes_home
    from tools.registry import registry

    startup = sys.argv[1]
    if startup in ("cli", "cli-race"):
        from hermes_cli.main import _prepare_agent_startup

        _prepare_agent_startup(
            SimpleNamespace(command="chat", query="startup test", toolsets="terminal")
        )
        if startup == "cli":
            plugins.discover_plugins()  # Join background discovery before builtins.
    elif startup == "gateway":
        from gateway.config_loader import load_yaml_layer

        load_yaml_layer(get_hermes_home(), {})
    if startup in ("cli", "gateway"):
        assert "model_tools" not in sys.modules
        assert registry.get_entry("terminal") is None
        assert plugins.get_plugin_manager()._hooks.get("on_session_start")

    import model_tools

    manager = plugins.get_plugin_manager()
    assert registry.get_entry("terminal") is not None
    assert manager._hooks.get("on_session_start"), "Intaris failed to load"
    plugins.invoke_hook("on_session_start", session_id="startup-session")

    def evaluations():
        return [body for url, body in requests if url.endswith("/evaluate")]

    marker = get_hermes_home() / "terminal-executed"
    args = {"command": f"pwd && touch {shlex.quote(str(marker))}"}
    result = json.loads(
        model_tools.handle_function_call("terminal", args, session_id="startup-session")
    )
    assert "DENIED" in (result.get("error") or ""), (
        "terminal bypassed deny",
        result,
        evaluations(),
    )
    assert not marker.exists(), "denied terminal executed"
    assert len(evaluations()) == 1
    decision = "approve"
    result = json.loads(
        model_tools.handle_function_call("terminal", args, session_id="startup-session")
    )
    assert result.get("exit_code") == 0, result
    assert marker.exists()
    assert len(evaluations()) == 2, "existing guard and middleware double evaluated"

    executed = []

    def late(args, **kwargs):
        executed.append(args)
        return json.dumps({"result": "late executed"})

    registry.register(
        name="late_startup_tool",
        toolset="terminal",
        schema={"name": "late_startup_tool", "parameters": {}},
        handler=late,
    )
    decision = "deny"
    result = json.loads(
        model_tools.handle_function_call(
            "late_startup_tool", {}, session_id="startup-session"
        )
    )
    assert "DENIED" in (result.get("error") or ""), result
    assert not executed
    assert len(evaluations()) == 3
    decision = "approve"
    assert json.loads(
        model_tools.handle_function_call(
            "late_startup_tool", {}, session_id="startup-session"
        )
    ) == {"result": "late executed"}
    assert len(executed) == 1
    assert len(evaluations()) == 4
    # Virtual connectors have no registry guard at the terminal dispatch point.
    # Exercise the pinned execution chain with a real later middleware rewrite.
    from hermes_cli.middleware import run_tool_execution_middleware

    virtual_tool = "connectors__startup_probe__action"
    assert registry.get_entry(virtual_tool) is None
    rewritten, virtual_executed = [], []
    context = plugins.PluginContext(
        plugins.PluginManifest(
            name="startup-rewriter", source="entrypoint", path="startup_probe"
        ),
        manager,
    )

    def rewrite_virtual(args, next_call, **kwargs):
        rewritten.append(args)
        return next_call({"operation": "delete"})

    def execute_virtual(args):
        virtual_executed.append(args)
        return json.dumps({"result": "virtual executed"})

    handle = context.register_middleware("tool_execution", rewrite_virtual)
    try:
        result = json.loads(
            run_tool_execution_middleware(
                virtual_tool,
                {"operation": "read"},
                execute_virtual,
                session_id="startup-session",
            )
        )
        assert "no registry handler" in result.get("error", ""), (
            result,
            rewritten,
            virtual_executed,
        )
        assert not rewritten
        assert not virtual_executed
        assert len(evaluations()) == 4
    finally:
        handle.dispose()

    # Fail inside the safety callback before downstream: the real Hermes
    # middleware chain must receive a blocked result, never fail open.
    import hermes_intaris

    registry.register(
        name="late_fault_tool",
        toolset="terminal",
        schema={"name": "late_fault_tool", "parameters": {}},
        handler=late,
    )
    original_factory = hermes_intaris._make_guarded_handler

    def broken_guard(*args, **kwargs):
        raise RuntimeError("test safety failure")

    hermes_intaris._make_guarded_handler = broken_guard
    try:
        result = json.loads(
            model_tools.handle_function_call(
                "late_fault_tool", {}, session_id="startup-session"
            )
        )
        assert "safety guard failed" in result.get("error", ""), result
        assert len(executed) == 1
        assert len(evaluations()) == 4
    finally:
        hermes_intaris._make_guarded_handler = original_factory

    manager.unload()
    assert not manager._middleware.get("tool_execution")
    print("startup contract passed:", startup, "evaluations=4 late_dispatches=1")


if __name__ == "__main__":
    main()
