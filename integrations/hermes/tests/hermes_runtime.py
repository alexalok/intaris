"""Load pinned Hermes wait/interrupt code without starting its agent or services.

Set HERMES_SOURCE to a read-only Hermes checkout. Executor definitions are
compiled verbatim from its AST; only unrelated imports/bootstrap are omitted.
"""

from __future__ import annotations

import ast
import concurrent.futures
import contextlib
import logging
import os
import sys
import threading
import types
from pathlib import Path

import pytest


def load_runtime(monkeypatch):
    path = os.environ.get("HERMES_SOURCE")
    if not path:
        pytest.skip("set HERMES_SOURCE for real Hermes executor contract tests")
    root = Path(path)

    def module(name, attrs=None, source=None):
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs or {})
        monkeypatch.setitem(sys.modules, name, mod)
        if source:
            exec(compile(source.read_text(), str(source), "exec"), mod.__dict__)
        return mod

    # Configuration/environment boundaries only. No plugin or host code changed.
    module("utils", {"env_var_enabled": lambda name: False})
    module("agent.deadline", {"MAX_SAFE_TIMEOUT_S": 31536000})
    context = sys.modules["tools.approval_context"]
    monkeypatch.setattr(context, "_get_approval_timeout", lambda: 300, raising=False)
    monkeypatch.setattr(
        sys.modules["tools"], "approval_context", context, raising=False
    )
    interrupt = module("tools.interrupt", source=root / "tools/interrupt.py")
    human = module(
        "tools.approval_human_wait", source=root / "tools/approval_human_wait.py"
    )

    # Event-controlled virtual elapsed time; adapter scheduling remains real.
    clock = types.SimpleNamespace(now=0.0)
    clock.monotonic = lambda: clock.now
    clock.time = lambda: clock.now
    human.time = clock

    selected = {
        "_authorization_gate_lock_timeout",
        "_ConcurrentToolAuthorizationGate",
        "_registered_tool_worker",
        "_interrupt_worker_tids",
        "_poll_sequential_future",
        "_ConcurrentBatch",
    }
    source = root / "agent/tool_executor.py"
    tree = ast.parse(source.read_text(), filename=str(source))
    nodes = [node for node in tree.body if getattr(node, "name", None) in selected]
    assert {node.name for node in nodes} == selected, "Hermes executor contract changed"
    ns = {
        "contextlib": contextlib,
        "threading": threading,
        "time": clock,
        "concurrent": concurrent,
        "logger": logging.getLogger("hermes-test"),
        "_NO_REASON": object(),
        "_SEQUENTIAL_INTERRUPT_POLL_SECONDS": 0.01,
        "_ra": lambda: types.SimpleNamespace(_set_interrupt=interrupt.set_interrupt),
    }
    future_import = ast.parse("from __future__ import annotations").body
    exec(
        compile(
            ast.Module(body=future_import + nodes, type_ignores=[]), str(source), "exec"
        ),
        ns,
    )
    return types.SimpleNamespace(
        clock=clock,
        human=human,
        interrupt=interrupt,
        **ns,
    )


def agent_stub():
    return types.SimpleNamespace(
        _interrupt_requested=False,
        _tool_worker_threads=set(),
        _tool_worker_threads_lock=threading.Lock(),
        _touch_activity=lambda *args: None,
        _vprint=lambda *args, **kwargs: None,
        log_prefix="",
    )


def await_host(runtime, path, agent, future, gate, deadline):
    """Run actual host wait and interruption fan-out against a running worker."""
    if path == "sequential":
        state, _ = runtime._poll_sequential_future(
            agent, future, "synthetic", deadline, 0, gate
        )
        if state != "done":
            future.cancel()
            runtime._interrupt_worker_tids(agent, list(agent._tool_worker_threads))
        return state == "done"
    batch = runtime._ConcurrentBatch.__new__(runtime._ConcurrentBatch)
    batch.agent = agent
    batch.authorization_gate = gate
    batch.timeout_s = deadline
    batch.gate = types.SimpleNamespace(abandon=lambda: None)
    batch.parsed_calls = [types.SimpleNamespace(name="synthetic")]
    batch.timed_out_indices = set()
    return not batch.await_completion([future], {future: 0}, deadline)
