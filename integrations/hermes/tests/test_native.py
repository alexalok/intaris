"""Native transport tests; no Hermes import or Telegram network at collection."""

from __future__ import annotations

import ast
import asyncio
import importlib
import importlib.util
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import time
import types
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest
from hermes_intaris.waits import Invocation, WaitStopped


def native_module():
    assert importlib.util.find_spec("hermes_intaris.native"), "native transport missing"
    return importlib.import_module("hermes_intaris.native")


def host_file(relative):
    source = os.environ.get("HERMES_SOURCE")
    if not source:
        pytest.skip("set HERMES_SOURCE for real Hermes contract tests")
    path = Path(source) / relative
    if not path.is_file():
        pytest.skip(f"Hermes source unavailable: {relative}")
    return path


@pytest.fixture
def real_interrupt(monkeypatch):
    """Execute installed Hermes' public interrupt API without gateway startup."""
    path = host_file("tools/interrupt.py")
    utils = types.ModuleType("utils")
    utils.env_var_enabled = lambda name: False
    monkeypatch.setitem(sys.modules, "utils", utils)
    module = types.ModuleType("tools.interrupt")
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    monkeypatch.setitem(sys.modules, "tools.interrupt", module)
    return module


class Context:
    def __init__(self):
        self.hooks = {}
        self.factories = []
        self.handles = []

    def get_config(self, *args):
        raise AssertionError("native transport must not read plugin settings")

    def register_hook(self, name, callback):
        self.hooks[name] = callback
        handle = types.SimpleNamespace(disposed=False)
        handle.dispose = lambda: setattr(handle, "disposed", True)
        self.handles.append(handle)
        return handle

    def register_telegram_handler(self, factory):
        self.factories.append(factory)


class BadRequest(Exception):
    pass


class Bot:
    id = 123

    def __init__(self, loop):
        self.loop = loop
        self.sends = []
        self.edits = []
        self.answers = []
        self.send_started = threading.Event()
        self.send_gate = None
        self.edit_gate = None
        self.send_error = False
        self.send_errors = []

    def check_loop(self):
        assert asyncio.get_running_loop() is self.loop

    async def send_message(self, **kwargs):
        self.check_loop()
        self.sends.append(kwargs)
        self.send_started.set()
        if self.send_gate:
            await self.send_gate.wait()
        if self.send_error:
            raise RuntimeError("message thread not found")
        if self.send_errors:
            raise self.send_errors.pop(0)
        message = self.message()
        message.chat.id = int(kwargs["chat_id"])
        message.message_thread_id = kwargs["message_thread_id"]
        return message

    def message(self):
        return types.SimpleNamespace(
            message_id=77,
            chat=types.SimpleNamespace(id=-100),
            message_thread_id=42,
            from_user=types.SimpleNamespace(id=self.id),
            get_bot=lambda: self,
        )

    async def edit_message_text(self, **kwargs):
        self.check_loop()
        if kwargs.get("reply_markup") and self.edit_gate:
            await self.edit_gate.wait()
        self.edits.append(kwargs)

    async def answer_callback_query(self, **kwargs):
        self.check_loop()
        self.answers.append(kwargs)


class Application:
    def __init__(self, loop):
        self.bot = Bot(loop)
        self.handlers = []

    def add_handler(self, handler, group=0):
        self.handlers.append(handler)

    def remove_handler(self, handler, group=0):
        self.handlers.remove(handler)


class Budget(Invocation):
    """Real cooperative request/check behavior with a pre-opened human budget."""

    def __init__(self):
        self.ended = threading.Event()
        super().__init__(self.ended, 60)
        self._is_interrupted = lambda: False
        self._is_thread_interrupted = lambda tid: False
        self._deadline = time.monotonic() + 60


class Server:
    def __init__(self):
        self.requests = []
        self.status = "cancelled"
        self.open_reply = {
            "ok": True,
            "lease_id": "x" * 32,
            "new": True,
            "expires_at": time.time() + 60,
            "route": {"chat_id": "-100", "thread_id": "42", "actor_ids": ["9"]},
            "text": "Redacted audit description",
        }
        self.bind_ok = True
        self.close_ok = True
        self.open_gate = None
        self.open_started = threading.Event()
        self.fallback_reply = {
            **self.open_reply,
            "new": False,
            "route": {"chat_id": "-200", "thread_id": "7", "actor_ids": ["8", "9"]},
        }
        self.fallback_gate = None
        self.fallback_started = threading.Event()
        self.transport_profiles = {}
        self.transport_ok = True
        self.transport_gate = None
        self.transport_started = threading.Event()

    def request(self, path, payload, *, deadline=None):
        self.requests.append(payload)
        op = payload["op"]
        if op == "fallback_transport":
            self.transport_started.set()
            if self.transport_gate:
                assert self.transport_gate.wait(3)
            return {
                "ok": self.transport_ok,
                "transport_profile": self.transport_profiles.get(
                    payload["profile"], payload["profile"]
                ),
            }
        if op == "open":
            self.open_started.set()
            if self.open_gate:
                assert self.open_gate.wait(3)
            return dict(self.open_reply)
        if op == "bind":
            return {"ok": self.bind_ok}
        if op == "fallback":
            self.fallback_started.set()
            if self.fallback_gate:
                assert self.fallback_gate.wait(3)
            return dict(self.fallback_reply)
        if op == "resolve":
            self.status = payload["decision"]
            return {"ok": True, "status": self.status}
        return {"ok": self.close_ok, "status": self.status}

    def ops(self, op):
        return [request for request in self.requests if request["op"] == op]


def until(predicate):
    deadline = time.monotonic() + 3
    while not predicate():
        assert time.monotonic() < deadline, "native operation did not finish"
        time.sleep(0.005)


@pytest.fixture
def harness(monkeypatch):
    native = native_module()
    exchange = native._exchange
    monkeypatch.setenv("INTARIS_NATIVE_APPROVAL_SOCKET", "/run/intaris/native.sock")
    monkeypatch.setattr(native, "_trusted_socket", lambda path: True)
    server = Server()
    monkeypatch.setattr(native, "_exchange", server.request)
    telegram = types.ModuleType("telegram")
    telegram.InlineKeyboardButton = lambda text, callback_data: types.SimpleNamespace(
        text=text, callback_data=callback_data
    )
    telegram.InlineKeyboardMarkup = lambda rows: types.SimpleNamespace(
        inline_keyboard=rows
    )
    ext = types.ModuleType("telegram.ext")
    ext.CallbackQueryHandler = lambda callback, pattern: types.SimpleNamespace(
        callback=callback, pattern=pattern
    )
    monkeypatch.setitem(sys.modules, "telegram", telegram)
    monkeypatch.setitem(sys.modules, "telegram.ext", ext)
    error = types.ModuleType("telegram.error")
    error.BadRequest = BadRequest
    monkeypatch.setitem(sys.modules, "telegram.error", error)
    deadline_module = types.ModuleType("agent.deadline")

    async def bounded(awaitable, timeout, **kwargs):
        return types.SimpleNamespace(timed_out=False, value=await awaitable)

    deadline_module.run_bounded_async = bounded
    monkeypatch.setitem(sys.modules, "agent.deadline", deadline_module)
    constants = types.ModuleType("hermes_constants")
    constants.get_hermes_home = lambda: Path("/profiles/alpha")
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    gateway_module = types.ModuleType("gateway.session_identity")
    gateway_module.identity_of = lambda source: source.identity
    monkeypatch.setitem(sys.modules, "gateway.session_identity", gateway_module)

    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    ctx = Context()
    native_transport = native.NativeApprovals("/profiles/alpha", ctx)
    app = Application(loop)
    adapter = object()

    async def install():
        for factory in ctx.factories:
            factory(app, adapter)

    asyncio.run_coroutine_threadsafe(install(), loop).result(3)
    source = types.SimpleNamespace(
        platform=types.SimpleNamespace(value="telegram"),
        chat_id="-100",
        thread_id="42",
        user_id="1",
        identity=types.SimpleNamespace(
            runtime_home=Path("/profiles/alpha"),
            transport_profile="alpha",
            multiplexed=True,
            transport_inferred=False,
        ),
    )
    entry = types.SimpleNamespace(
        session_id="hermes-root",
        session_key="gateway-root",
        origin=source,
        transport_profile="alpha",
    )
    lookups = []

    def lookup(session_id):
        lookups.append(session_id)
        return entry if session_id == entry.session_id else None

    store = types.SimpleNamespace(lookup_by_session_id=lookup)
    gateway = types.SimpleNamespace(
        session_store=store,
        _restored_source=lambda entry: entry.origin,
        _delivery_adapter_for=lambda source: adapter,
    )
    h = types.SimpleNamespace(
        native=native_transport,
        ctx=ctx,
        app=app,
        adapter=adapter,
        source=source,
        entry=entry,
        gateway=gateway,
        store=store,
        server=server,
        exchange=exchange,
        loop=loop,
        budget=Budget(),
        lookups=lookups,
    )
    h.pre = lambda: ctx.hooks["pre_gateway_dispatch"](
        event=types.SimpleNamespace(source=source), gateway=gateway, session_store=store
    )

    def admit(actor="9", **overrides):
        snapshot = {
            "platform": "telegram",
            "chat_id": "-100",
            "thread_id": "42",
            "user_id": actor,
            "profile": "alpha",
        }
        snapshot.update(overrides)
        return ctx.hooks["post_gateway_admission"](
            session_key="gateway-root",
            platform="telegram",
            source=snapshot,
            text="untrusted inbound text",
            message_id="55",
        )

    h.admit = admit
    h.pre()
    h.admit()
    yield h
    native_transport.dispose()
    if app.bot.send_gate:
        loop.call_soon_threadsafe(app.bot.send_gate.set)
    if app.bot.edit_gate:
        loop.call_soon_threadsafe(app.bot.edit_gate.set)

    async def drain():
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 3)

    asyncio.run_coroutine_threadsafe(drain(), loop).result(4)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(3)
    loop.close()


@pytest.fixture
def real_deadline(harness, monkeypatch):
    """Use the pinned host primitive for cancellation-shielded I/O regressions."""
    path = host_file("agent/deadline.py")
    module = types.ModuleType("agent.deadline")
    monkeypatch.setitem(sys.modules, "agent.deadline", module)
    exec(compile(path.read_text(), str(path), "exec"), module.__dict__)
    monkeypatch.setattr(native_module(), "_TELEGRAM_TIMEOUT", 0.03, raising=False)
    return module


async def wait_ignoring_cancellation(gate):
    while not gate.is_set():
        try:
            await gate.wait()
        except asyncio.CancelledError:
            pass


@contextmanager
def pending(h, session_id="hermes-root"):
    with h.native.pending(
        session_id, "audit-call", h.budget, intaris_session_id="hm-uuid"
    ):
        yield


def click(h, *, actor="9", decision="a", **changes):
    message = h.app.bot.message()
    query = types.SimpleNamespace(
        id="callback-id",
        data=f"intaris:{decision}:" + "x" * 32,
        message=message,
        from_user=types.SimpleNamespace(id=actor),
        get_bot=lambda: h.app.bot,
    )
    context = types.SimpleNamespace(application=h.app, bot=h.app.bot)
    for key, value in changes.items():
        target, attr = key.split("__")
        setattr(
            {"message": message, "query": query, "context": context}[target],
            attr,
            value,
        )
    update = types.SimpleNamespace(callback_query=query)
    return asyncio.run_coroutine_threadsafe(
        h.app.handlers[0].callback(update, context), h.loop
    )


def actionable(h):
    return bool(h.app.bot.edits and h.app.bot.edits[-1].get("reply_markup"))


def test_disabled_without_process_env_never_reads_settings(monkeypatch):
    native = native_module()
    monkeypatch.delenv("INTARIS_NATIVE_APPROVAL_SOCKET", raising=False)
    ctx = Context()
    transport = native.NativeApprovals("/profiles/alpha", ctx)
    with transport.pending(
        "hermes-root", "audit-call", Budget(), intaris_session_id="hm-uuid"
    ):
        pass
    assert not ctx.hooks and not ctx.factories
    transport.dispose()


@pytest.mark.parametrize(
    "path", ["", "relative.sock", "/run/../run/native.sock", "/run//native.sock"]
)
def test_invalid_launch_socket_path_disables_all_registration(monkeypatch, path):
    native = native_module()
    monkeypatch.setenv("INTARIS_NATIVE_APPROVAL_SOCKET", path)
    ctx = Context()
    transport = native.NativeApprovals("/profiles/alpha", ctx)
    assert not ctx.hooks and not ctx.factories
    transport.dispose()


def test_missing_startup_socket_recovers_on_next_wait_without_reload(
    harness, monkeypatch
):
    h = harness
    native = native_module()
    available = False
    connections = []
    monkeypatch.setattr(native, "_trusted_socket", lambda path: available)
    monkeypatch.setattr(native, "_exchange", h.exchange)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, seconds):
            assert 0 < seconds <= 2

        def connect(self, path):
            connections.append(path)

        def sendall(self, wire):
            result = h.server.request(connections[-1], json.loads(wire))
            self.response = json.dumps(result).encode() + b"\n"

        def recv(self, size):
            chunk, self.response = self.response[:size], self.response[size:]
            return chunk

    monkeypatch.setattr(native.socket, "socket", lambda *args: Connection())
    ctx = Context()
    delayed = native.NativeApprovals("/profiles/alpha", ctx)
    original, h.native = h.native, delayed
    try:
        assert delayed.enabled and ctx.hooks and ctx.factories

        async def install():
            ctx.factories[0](h.app, h.adapter)

        asyncio.run_coroutine_threadsafe(install(), h.loop).result(3)
        with pending(h):
            assert not connections and not h.server.requests
            assert not h.app.bot.sends
        assert delayed.enabled
        available = True
        with pending(h):
            until(lambda: actionable(h))
            assert len(h.server.ops("open")) == 1
            assert len(h.server.ops("bind")) == 1
        until(lambda: not actionable(h))
        assert len(h.server.ops("close")) == 1
        # Losing trust/availability later must still block before connect.
        available = False
        count = len(connections)
        with pending(h):
            assert len(connections) == count
    finally:
        delayed.dispose()
        h.native = original


def test_exact_hermes_route_and_distinct_intaris_id(harness):
    h = harness
    h.admit("8")
    h.admit("9")
    with pending(h):
        until(lambda: actionable(h))
        opened = h.server.ops("open")[0]
        assert opened["session_id"] == "hm-uuid"
        assert opened["profile"] == "/profiles/alpha"
        assert opened["origin"] == {
            "chat_id": "-100",
            "thread_id": "42",
            "user_id": "9",
        }
        assert 0 < opened["remaining_seconds"] <= 60
        assert h.lookups and set(h.lookups) == {"hermes-root"}
        assert h.app.handlers[0].pattern == "^intaris:"
        assert h.app.bot.sends[0]["message_thread_id"] == 42
        assert not h.app.bot.sends[0].get("reply_markup")
        assert h.server.ops("bind")[0]["message_id"] == "77"
        keyboard = h.app.bot.edits[-1]["reply_markup"].inline_keyboard[0]
        assert [button.callback_data for button in keyboard] == [
            "intaris:a:" + "x" * 32,
            "intaris:d:" + "x" * 32,
        ]
    until(lambda: not actionable(h))


def test_routing_snapshot_eviction_requires_fallback_until_readmission(harness):
    from hermes_intaris import MAX_SESSIONS

    h = harness
    for index in range(MAX_SESSIONS):
        h.ctx.hooks["post_gateway_admission"](
            session_key=f"session-{index}",
            platform="telegram",
            source={"platform": "telegram", "chat_id": "-200", "user_id": "8"},
        )
    assert len(h.native._admitted) == MAX_SESSIONS
    binding, origin = h.native._route("hermes-root")
    assert binding.bot is h.app.bot and origin is None
    h.admit("9")
    assert len(h.native._admitted) == MAX_SESSIONS
    assert h.native._route("hermes-root")[1]["user_id"] == "9"


def test_child_eviction_does_not_inherit_a_different_session(harness):
    from hermes_intaris import MAX_SESSIONS

    h = harness
    child = h.ctx.hooks["subagent_start"]
    child(parent_session_id="hermes-root", child_session_id="old-child")
    for index in range(MAX_SESSIONS):
        child(parent_session_id="hermes-root", child_session_id=f"child-{index}")
    assert len(h.native._parents) == MAX_SESSIONS
    assert h.native._route("old-child")[1] is None
    assert h.native._route(f"child-{MAX_SESSIONS - 1}")[1]["user_id"] == "9"


def test_recent_conflicting_child_stays_unroutable_under_cache_pressure(harness):
    from hermes_intaris import MAX_SESSIONS

    h = harness
    child = h.ctx.hooks["subagent_start"]
    child(parent_session_id="hermes-root", child_session_id="conflict")
    for index in range(MAX_SESSIONS + 1):
        child(parent_session_id="other-root", child_session_id="conflict")
        child(parent_session_id="hermes-root", child_session_id=f"child-{index}")
    assert len(h.native._parents) == MAX_SESSIONS
    with pytest.raises(ValueError, match="Ambiguous child session"):
        h.native._route("conflict")


def test_pre_auth_only_captures_runner_and_never_supplies_actor(harness):
    h = harness
    h.entry.session_key = "unadmitted"
    h.source.user_id = "999"
    h.pre()
    with pending(h):
        until(lambda: actionable(h))
        assert "origin" not in h.server.ops("open")[0]


def test_explicit_child_maps_to_exact_parent(harness):
    h = harness
    h.ctx.hooks["subagent_start"](
        parent_session_id="hermes-root", child_session_id="child"
    )
    h.ctx.hooks["subagent_start"](
        parent_session_id="child", child_session_id="grandchild"
    )
    with pending(h, "grandchild"):
        until(lambda: actionable(h))
        assert h.server.ops("open")[0]["origin"]["user_id"] == "9"
        assert "hermes-root" in h.lookups


def test_shared_bot_routes_routed_profile_and_dispatches_its_callback(
    harness, monkeypatch
):
    h = harness
    native = native_module()
    ctx = Context()
    beta = native.NativeApprovals("/profiles/beta", ctx)
    monkeypatch.setattr(
        sys.modules["hermes_constants"],
        "get_hermes_home",
        lambda: Path("/profiles/beta"),
    )
    h.source.identity.runtime_home = Path("/profiles/beta")
    # Only alpha owns the transport factory and saw the pre-auth gateway hook.
    ctx.hooks["post_gateway_admission"](
        session_key="gateway-root",
        platform="telegram",
        source={
            "platform": "telegram",
            "chat_id": "-100",
            "thread_id": "42",
            "user_id": "9",
            "profile": "beta",
        },
    )
    try:
        with beta.pending(
            "hermes-root", "audit-beta", h.budget, intaris_session_id="hm-beta"
        ):
            until(lambda: actionable(h))
            assert h.server.ops("open")[0]["profile"] == "/profiles/beta"
            click(h).result(3)
            assert h.server.ops("resolve")[0]["profile"] == "/profiles/beta"
    finally:
        beta.dispose()


@pytest.mark.parametrize("source", ["cron", "webhook"])
def test_shared_fallback_transport_routes_background_profile_and_callback(
    harness, source
):
    h = harness
    beta = native_module().NativeApprovals("/profiles/beta", Context())
    h.server.transport_profiles["/profiles/beta"] = "/profiles/alpha"
    h.server.open_reply["route"]["actor_ids"] = ["8", "9"]
    if source == "webhook":
        h.source.platform.value = "webhook"
    try:
        with beta.pending(
            "hermes-root" if source == "webhook" else "cron-session",
            "audit-beta",
            h.budget,
            intaris_session_id="hm-beta",
        ):
            until(lambda: actionable(h))
            assert h.server.ops("fallback_transport") == [
                {"op": "fallback_transport", "profile": "/profiles/beta"}
            ]
            opened = h.server.ops("open")[0]
            assert opened["profile"] == "/profiles/beta"
            assert opened["session_id"] == "hm-beta"
            assert opened["call_id"] == "audit-beta"
            assert "origin" not in opened
            click(h, actor="8").result(3)
            assert h.server.ops("resolve")[0]["profile"] == "/profiles/beta"
    finally:
        beta.dispose()


@pytest.mark.parametrize(
    "fault", ["unmapped", "missing", "ambiguous", "invalid", "disabled", "refused"]
)
def test_shared_fallback_does_not_guess_transport(harness, fault):
    h = harness
    beta = native_module().NativeApprovals("/profiles/beta", Context())
    if fault == "missing":
        h.server.transport_profiles["/profiles/beta"] = "/profiles/missing"
    elif fault == "invalid":
        h.server.transport_profiles["/profiles/beta"] = "alpha"
    elif fault == "disabled":
        h.server.transport_profiles["/profiles/beta"] = None
    elif fault == "refused":
        h.server.transport_profiles["/profiles/beta"] = "/profiles/alpha"
        h.server.transport_ok = False
    elif fault == "ambiguous":
        h.server.transport_profiles["/profiles/beta"] = "/profiles/alpha"

        async def install():
            h.ctx.factories[0](Application(h.loop), object())

        asyncio.run_coroutine_threadsafe(install(), h.loop).result(3)
    try:
        with beta.pending(
            "cron-session", "audit-beta", h.budget, intaris_session_id="hm-beta"
        ):
            assert not h.server.ops("open")
            assert not h.app.bot.sends
    finally:
        beta.dispose()


def test_explicit_mapping_wins_over_runtime_profiles_own_bot(harness, monkeypatch):
    h = harness
    ctx = Context()
    beta = native_module().NativeApprovals("/profiles/beta", ctx)
    beta_app = Application(h.loop)
    monkeypatch.setattr(native_module(), "_home", lambda: "/profiles/beta")

    async def install():
        ctx.factories[0](beta_app, object())

    asyncio.run_coroutine_threadsafe(install(), h.loop).result(3)
    h.server.transport_profiles["/profiles/beta"] = "/profiles/alpha"
    try:
        with beta.pending(
            "cron-session", "audit-beta", h.budget, intaris_session_id="hm-beta"
        ):
            until(lambda: actionable(h))
            assert len(h.app.bot.sends) == 1
            assert not beta_app.bot.sends
            # A later policy lookup must not move a live prompt or its callback.
            h.server.transport_profiles["/profiles/beta"] = "/profiles/beta"
            click(h).result(3)
            assert h.server.ops("resolve")[0]["profile"] == "/profiles/beta"
    finally:
        beta.dispose()


def test_origin_transport_does_not_use_background_mapping(harness):
    h = harness
    h.server.transport_profiles["/profiles/alpha"] = "/profiles/unavailable"
    with pending(h):
        until(lambda: actionable(h))
        assert not h.server.ops("fallback_transport")
        assert h.server.ops("open")[0]["origin"]["chat_id"] == "-100"


@pytest.mark.parametrize("configured", [None, "1"])
@pytest.mark.parametrize("returned", [None, 1])
def test_general_topic_aliases_bind_and_resolve_same_fallback_message(
    harness, monkeypatch, configured, returned
):
    h = harness
    h.server.open_reply["route"]["thread_id"] = configured
    send = h.app.bot.send_message

    async def general_send(**kwargs):
        message = await send(**kwargs)
        message.message_thread_id = returned
        return message

    monkeypatch.setattr(h.app.bot, "send_message", general_send)
    with pending(h, "cron-session"):
        until(lambda: actionable(h))
        assert h.app.bot.sends[0]["message_thread_id"] is None
        assert h.server.ops("bind")[0]["thread_id"] == configured
        click(h, message__message_thread_id=42).result(3)
        assert not h.server.ops("resolve")
        click(h, message__message_thread_id=returned).result(3)
        assert h.server.ops("resolve")[0]["thread_id"] == configured


def test_general_fallback_rejects_delivery_in_different_topic(harness, monkeypatch):
    h = harness
    h.server.open_reply["route"]["thread_id"] = None
    send = h.app.bot.send_message

    async def wrong_topic(**kwargs):
        message = await send(**kwargs)
        message.message_thread_id = 42
        return message

    monkeypatch.setattr(h.app.bot, "send_message", wrong_topic)
    with pending(h, "cron-session"):
        until(lambda: h.server.ops("close"))
        assert not h.server.ops("bind")
        assert not actionable(h)


def test_cancellation_during_transport_lookup_does_not_open_lease(harness):
    h = harness
    h.server.transport_gate = threading.Event()
    done = threading.Event()
    errors = []

    def run():
        try:
            with pending(h, "cron-session"):
                pass
        except WaitStopped as exc:
            errors.append(str(exc))
        finally:
            done.set()

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert h.server.transport_started.wait(1)
        h.budget.ended.set()
        assert done.wait(1), "transport lookup must observe cancellation promptly"
        assert errors and errors[0].startswith("CANCELLED")
    finally:
        h.server.transport_gate.set()
        worker.join(3)
    assert not h.server.ops("open")
    assert not h.app.bot.sends


def test_shared_transport_survives_unload_of_transport_profile(harness, monkeypatch):
    h = harness
    ctx = Context()
    beta = native_module().NativeApprovals("/profiles/beta", ctx)
    monkeypatch.setattr(
        sys.modules["hermes_constants"],
        "get_hermes_home",
        lambda: Path("/profiles/beta"),
    )
    h.source.identity.runtime_home = Path("/profiles/beta")
    ctx.hooks["post_gateway_admission"](
        session_key="gateway-root",
        platform="telegram",
        source={
            "platform": "telegram",
            "chat_id": "-100",
            "thread_id": "42",
            "user_id": "9",
        },
    )
    try:
        with beta.pending(
            "hermes-root", "audit-beta", h.budget, intaris_session_id="hm-beta"
        ):
            until(lambda: actionable(h))
            h.native.dispose()
            click(h).result(3)
            assert h.server.ops("resolve")[0]["profile"] == "/profiles/beta"
    finally:
        beta.dispose()


def test_reloaded_factory_runs_with_installed_hermes_deduplication(
    harness, monkeypatch
):
    h = harness
    # Execute the installed host's actual factory-deduplication method, without
    # loading its optional gateway dependencies or starting a Telegram updater.
    path = host_file("gateway/platforms/base.py")
    tree = ast.parse(path.read_text())
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "BasePlatformAdapter"
    )
    method = next(
        node
        for node in cls.body
        if getattr(node, "name", None) == "_wire_plugin_handlers"
    )
    ns = {"Any": object, "logger": __import__("logging").getLogger(__name__)}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(path), "exec"), ns)
    host_adapter = types.SimpleNamespace(
        platform=types.SimpleNamespace(value="telegram"),
        name="Telegram",
        _plugin_handler_native=None,
        _plugin_handlers_wired=None,
    )
    plugins = types.ModuleType("hermes_cli.plugins")
    factories = [(h.ctx.factories[0], "intaris")]
    plugins.get_plugin_manager = lambda: types.SimpleNamespace(
        get_platform_handler_factories=lambda platform: factories
    )
    monkeypatch.setitem(sys.modules, "hermes_cli.plugins", plugins)

    async def wire():
        ns["_wire_plugin_handlers"](host_adapter, h.app)

    asyncio.run_coroutine_threadsafe(wire(), h.loop).result(3)
    h.native.dispose()
    until(lambda: not h.app.handlers)
    ctx = Context()
    replacement = native_module().NativeApprovals("/profiles/alpha", ctx)
    factories[:] = [(ctx.factories[0], "intaris")]
    try:
        asyncio.run_coroutine_threadsafe(wire(), h.loop).result(3)
        assert len(h.app.handlers) == 1, "host skipped the replacement native factory"
    finally:
        replacement.dispose()


def rebuild_application(h):
    replacement = Application(h.loop)

    async def install():
        h.ctx.factories[0](replacement, h.adapter)

    asyncio.run_coroutine_threadsafe(install(), h.loop).result(3)
    return replacement


@pytest.mark.parametrize("session_id", ["hermes-root", "missing-session"])
def test_rebuilt_application_replaces_same_adapter_for_exact_and_fallback_routes(
    harness, session_id
):
    h = harness
    old = h.app
    h.app = rebuild_application(h)
    with pending(h, session_id):
        until(lambda: actionable(h))
        assert len(h.app.bot.sends) == 1
        assert not old.bot.sends
    until(lambda: not old.handlers)


def test_rebuild_between_route_lookup_and_wait_cannot_open_old_transport(
    harness, monkeypatch
):
    h = harness
    route = h.native._route

    def racing_route(session_id):
        target = route(session_id)
        h.app = rebuild_application(h)
        return target

    monkeypatch.setattr(h.native, "_route", racing_route)
    with pending(h):
        assert not h.server.ops("open")


@pytest.mark.parametrize("late_send", [False, True])
def test_reconnect_retires_shared_profile_prompts_and_accepts_new_wait(
    harness, monkeypatch, late_send
):
    h = harness
    old = h.app
    if late_send:
        old.bot.send_gate = asyncio.Event()
    ctx = Context()
    beta = native_module().NativeApprovals("/profiles/beta", ctx)
    monkeypatch.setattr(
        sys.modules["hermes_constants"],
        "get_hermes_home",
        lambda: Path("/profiles/beta"),
    )
    h.source.identity.runtime_home = Path("/profiles/beta")
    ctx.hooks["post_gateway_admission"](
        session_key="gateway-root",
        platform="telegram",
        source={
            "platform": "telegram",
            "chat_id": "-100",
            "thread_id": "42",
            "user_id": "9",
        },
    )
    try:
        with beta.pending(
            "hermes-root", "old-call", h.budget, intaris_session_id="hm-beta"
        ):
            if late_send:
                assert old.bot.send_started.wait(3)
            else:
                until(lambda: actionable(h))
            h.app = rebuild_application(h)
            until(lambda: h.server.ops("close"))
            assert h.server.ops("close")[0]["reason"] == "cancelled"
            if late_send:
                h.loop.call_soon_threadsafe(old.bot.send_gate.set)
            until(lambda: old.bot.edits and not old.bot.edits[-1].get("reply_markup"))
            assert not old.handlers
        h.server.open_reply["lease_id"] = "y" * 32
        with beta.pending(
            "hermes-root", "new-call", Budget(), intaris_session_id="hm-beta"
        ):
            until(lambda: actionable(h))
            assert len(h.app.bot.sends) == 1
            assert h.server.ops("open")[-1]["profile"] == "/profiles/beta"
    finally:
        beta.dispose()


def test_replacing_application_bot_cannot_retarget_existing_lease(harness):
    h = harness
    original = h.app.bot
    with pending(h):
        until(lambda: actionable(h))
        h.app.bot = Bot(h.loop)
        click(h).result(3)
        assert not h.server.ops("resolve")
        h.app.bot = original


def test_child_mapping_never_crosses_profile_scope(harness, monkeypatch):
    h = harness
    monkeypatch.setattr(
        sys.modules["hermes_constants"],
        "get_hermes_home",
        lambda: Path("/profiles/beta"),
    )
    h.ctx.hooks["subagent_start"](
        parent_session_id="hermes-root", child_session_id="child"
    )
    with pending(h, "child"):
        until(lambda: actionable(h))
        assert "origin" not in h.server.ops("open")[0]
        assert set(h.lookups) == {"child"}


def test_multiple_bots_cannot_be_selected_as_fallback(harness):
    h = harness
    other = Application(h.loop)

    async def install():
        h.ctx.factories[0](other, object())

    asyncio.run_coroutine_threadsafe(install(), h.loop).result(3)
    with pending(h, "missing-session"):
        assert not h.server.ops("open")


def test_callback_checks_remaining_budget_even_before_expiry_timer(harness):
    h = harness
    with pytest.raises(WaitStopped):
        with pending(h):
            until(lambda: actionable(h))
            h.budget._deadline = time.monotonic() - 1
            click(h).result(3)
            assert not h.server.ops("resolve")
    assert h.server.ops("close")[0]["reason"] == "expired"


def test_enable_edit_completing_after_cancellation_is_followed_by_removal(harness):
    h = harness
    h.app.bot.edit_gate = asyncio.Event()
    with pytest.raises(WaitStopped):
        with pending(h):
            until(lambda: h.server.ops("bind"))
            h.budget.ended.set()
            h.budget.check()
    h.loop.call_soon_threadsafe(h.app.bot.edit_gate.set)
    until(lambda: h.app.bot.edits and not actionable(h))
    assert not h.server.ops("resolve")


@pytest.mark.parametrize(
    "fault", ["profile", "thread", "key", "adapter", "ambiguous_parent"]
)
def test_ambiguous_or_mismatched_route_never_sends(harness, fault):
    h = harness
    if fault == "profile":
        h.source.identity.runtime_home = Path("/profiles/other")
    elif fault == "thread":
        h.source.thread_id = "43"
    elif fault == "key":
        h.entry.session_id = "different-id"
        h.store.lookup_by_session_id = lambda session_id: h.entry
    elif fault == "adapter":
        h.gateway._delivery_adapter_for = lambda source: object()
    else:
        hook = h.ctx.hooks["subagent_start"]
        hook(parent_session_id="hermes-root", child_session_id="child")
        hook(parent_session_id="other-parent", child_session_id="child")
    with pending(h, "child" if fault == "ambiguous_parent" else "hermes-root"):
        assert not h.server.ops("open")
        assert not h.app.bot.sends


@pytest.mark.parametrize(
    "reply",
    [{"ok": True, "lease_id": None}, {"ok": False, "error": "denied"}, {"new": False}],
)
def test_no_route_error_or_duplicate_never_creates_prompt(harness, reply):
    h = harness
    h.server.open_reply.update(reply)
    with pending(h):
        pass
    assert not h.app.bot.sends
    assert not h.server.ops("close")


@pytest.mark.parametrize(
    "fault",
    [
        "actor",
        "chat",
        "thread",
        "message",
        "application",
        "bot",
        "query_bot",
        "author",
        "data",
    ],
)
def test_callback_rejects_forged_identity_without_consuming_lease(harness, fault):
    h = harness
    kwargs = {
        "actor": {"actor": "666"},
        "chat": {"message__chat": types.SimpleNamespace(id=-200)},
        "thread": {"message__message_thread_id": 43},
        "message": {"message__message_id": 78},
        "application": {"context__application": object()},
        "bot": {"context__bot": object()},
        "query_bot": {"query__get_bot": lambda: object()},
        "author": {"message__from_user": types.SimpleNamespace(id=999)},
        "data": {"query__data": "ea:approve:session"},
    }[fault]
    with pending(h):
        until(lambda: actionable(h))
        click(h, **kwargs).result(3)
        assert not h.server.ops("resolve")
        click(h).result(3)
        assert len(h.server.ops("resolve")) == 1
        assert h.server.ops("resolve")[0]["actor_id"] == "9"


def test_callback_one_use_and_server_is_only_resolver(harness):
    h = harness
    with pending(h):
        until(lambda: actionable(h))
        futures = [click(h) for _ in range(8)]
        for future in futures:
            future.result(3)
        assert len(h.server.ops("resolve")) == 1
        resolved = h.server.ops("resolve")[0]
        assert resolved == {
            "op": "resolve",
            "profile": "/profiles/alpha",
            "lease_id": "x" * 32,
            "decision": "approve",
            "actor_id": "9",
            "chat_id": "-100",
            "thread_id": "42",
            "message_id": "77",
        }
    until(lambda: not actionable(h))
    assert "Approved" in h.app.bot.edits[-1]["text"]


def test_callback_claim_cannot_resolve_after_wait_closed(harness):
    h = harness
    acknowledged = threading.Event()
    release = asyncio.Event()

    async def answer(**kwargs):
        acknowledged.set()
        await release.wait()

    h.app.bot.answer_callback_query = answer
    with pending(h):
        until(lambda: actionable(h))
        callback = click(h)
        assert acknowledged.wait(3)
    h.loop.call_soon_threadsafe(release.set)
    callback.result(3)
    assert not h.server.ops("resolve")


@pytest.mark.parametrize("identity", ["owner", "acting_for"])
@pytest.mark.parametrize("phase", ["before_click", "after_claim"])
def test_callback_observes_origin_interrupt_before_audit_poll_latches(
    harness, real_interrupt, identity, phase
):
    h = harness
    target = threading.get_ident() if identity == "owner" else 987654321
    token = real_interrupt.acting_for_tid.set(
        target if identity == "acting_for" else None
    )
    try:
        h.budget = Invocation(threading.Event(), 60)
        h.budget._deadline = time.monotonic() + 60
    finally:
        real_interrupt.acting_for_tid.reset(token)
    if phase == "after_claim":
        original_answer = h.app.bot.answer_callback_query

        async def answer(**kwargs):
            real_interrupt.set_interrupt(True, target)
            await original_answer(**kwargs)

        h.app.bot.answer_callback_query = answer
    try:
        with pytest.raises(WaitStopped, match="interrupted"):
            with pending(h):
                until(lambda: actionable(h))
                if phase == "before_click":
                    real_interrupt.set_interrupt(True, target)
                # Original worker remains parked here: only the callback loop
                # and callback's to_thread worker can notice the interrupt.
                click(h).result(3)
                assert not h.server.ops("resolve")
    finally:
        real_interrupt.set_interrupt(False, target)


def test_cross_thread_check_ignores_unrelated_worker_interrupt(real_interrupt):
    invocation = Invocation(threading.Event(), 60)
    errors = []

    def worker():
        real_interrupt.set_interrupt(True)
        try:
            invocation.check()
        except WaitStopped as exc:
            errors.append(exc)
        finally:
            real_interrupt.set_interrupt(False)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(3)
    assert not thread.is_alive()
    assert errors == []
    invocation.check()


def test_cross_thread_check_without_owner_api_fails_closed(monkeypatch):
    module = types.ModuleType("tools.interrupt")
    module.is_interrupted = lambda: False
    monkeypatch.setitem(sys.modules, "tools.interrupt", module)
    invocation = Invocation(threading.Event(), 60)
    errors = []

    def worker():
        try:
            invocation.request(lambda: errors.append("transport called"))
        except WaitStopped as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(3)
    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], WaitStopped)


def test_fallback_uses_only_server_approved_actors(harness):
    h = harness
    h.entry.origin = None
    h.server.open_reply["route"]["actor_ids"] = ["8", "9"]
    with pending(h):
        until(lambda: actionable(h))
        assert "origin" not in h.server.ops("open")[0]
        click(h, actor="8", decision="d").result(3)
        assert h.server.ops("resolve")[0]["decision"] == "deny"


def test_ui_resolution_status_comes_from_close_reply(harness):
    h = harness
    with pending(h):
        until(lambda: actionable(h))
        h.server.status = "deny"
    until(lambda: not actionable(h))
    assert "Denied" in h.app.bot.edits[-1]["text"]
    assert h.server.ops("close")[0]["reason"] == "completed"


def test_failed_close_cannot_display_approval(harness):
    h = harness
    with pending(h):
        until(lambda: actionable(h))
        h.server.close_ok = False
        h.server.status = "approve"
    until(lambda: not actionable(h))
    assert "No longer actionable" in h.app.bot.edits[-1]["text"]


def test_unclassified_delivery_failure_never_retries(harness):
    h = harness
    h.app.bot.send_error = True
    with pending(h):
        until(lambda: h.server.ops("close"))
        assert h.server.ops("close")[0]["reason"] == "failed"
    assert len(h.app.bot.sends) == 1
    assert h.app.bot.sends[0]["message_thread_id"] == 42
    assert not h.server.ops("bind")
    assert not h.server.ops("fallback")


@pytest.mark.parametrize("error", ["Message thread not found", "TOPIC_CLOSED"])
@pytest.mark.parametrize("thread_id", ["7", None])
def test_unavailable_topic_uses_configured_fallback_once(harness, error, thread_id):
    h = harness
    h.app.bot.send_errors = [BadRequest(error)]
    h.server.fallback_reply["route"]["thread_id"] = thread_id
    with pending(h):
        until(lambda: actionable(h))
        assert len(h.app.bot.sends) == 2
        assert h.app.bot.sends[0]["message_thread_id"] == 42
        assert h.app.bot.sends[1]["chat_id"] == "-200"
        assert h.app.bot.sends[1]["message_thread_id"] == (
            int(thread_id) if thread_id is not None else None
        )
        assert len(h.server.ops("open")) == len(h.server.ops("fallback")) == 1
        bound = h.server.ops("bind")[0]
        assert bound["chat_id"] == "-200" and bound["thread_id"] == thread_id
        assert bound["lease_id"] == h.server.open_reply["lease_id"]
        click(h).result(3)  # The old origin no longer owns this prompt.
        assert not h.server.ops("resolve")
        click(
            h,
            actor="8",
            message__chat=types.SimpleNamespace(id=-200),
            message__message_thread_id=int(thread_id) if thread_id else None,
        ).result(3)
        assert h.server.ops("resolve")[0]["actor_id"] == "8"


@pytest.mark.parametrize(
    "error", [TimeoutError("send timed out"), BadRequest("Message is too long")]
)
def test_ambiguous_or_unrelated_delivery_failure_does_not_fallback(harness, error):
    h = harness
    h.app.bot.send_errors = [error]
    with pending(h):
        until(lambda: h.server.ops("close"))
    assert len(h.app.bot.sends) == 1
    assert not h.server.ops("fallback")


def test_failed_fallback_topic_does_not_send_third_prompt(harness):
    h = harness
    h.app.bot.send_errors = [BadRequest("TOPIC_CLOSED")] * 2
    with pending(h):
        until(lambda: h.server.ops("close"))
    assert len(h.app.bot.sends) == 2
    assert len(h.server.ops("fallback")) == 1
    assert not h.server.ops("bind")


@pytest.mark.parametrize("invalid", ["missing", "same", "lease", "expiry"])
def test_invalid_fallback_response_does_not_send(harness, invalid):
    h = harness
    h.app.bot.send_errors = [BadRequest("TOPIC_CLOSED")]
    if invalid == "missing":
        h.server.fallback_reply = {"ok": False}
    elif invalid == "same":
        h.server.fallback_reply["route"] = h.server.open_reply["route"]
    elif invalid == "lease":
        h.server.fallback_reply["lease_id"] = "y" * 32
    else:
        h.server.fallback_reply["expires_at"] += 60
    with pending(h):
        until(lambda: h.server.ops("close"))
    assert len(h.server.ops("fallback")) == 1
    assert len(h.app.bot.sends) == 1
    assert not h.server.ops("bind")


def test_cancellation_during_fallback_prevents_second_send(harness):
    h = harness
    h.app.bot.send_errors = [BadRequest("TOPIC_CLOSED")]
    h.server.fallback_gate = threading.Event()
    try:
        with pytest.raises(WaitStopped):
            with pending(h):
                assert h.server.fallback_started.wait(3)
                h.budget.ended.set()
                h.budget.check()
    finally:
        h.server.fallback_gate.set()
    until(lambda: h.server.ops("close"))
    assert len(h.app.bot.sends) == 1
    assert not h.server.ops("bind")


def test_failed_bind_never_enables_buttons(harness):
    h = harness
    h.server.bind_ok = False
    with pending(h):
        until(lambda: h.server.ops("close"))
    assert not any(edit.get("reply_markup") for edit in h.app.bot.edits)


def test_send_completing_after_cancellation_cannot_leave_buttons(harness):
    h = harness
    h.app.bot.send_gate = asyncio.Event()
    with pytest.raises(WaitStopped):
        with pending(h):
            assert h.app.bot.send_started.wait(3)
            h.budget.ended.set()
            h.budget.check()
    h.loop.call_soon_threadsafe(h.app.bot.send_gate.set)
    until(lambda: h.app.bot.edits)
    assert not any(edit.get("reply_markup") for edit in h.app.bot.edits)
    assert h.server.ops("close")[0]["reason"] == "cancelled"


def test_open_completing_after_cancellation_is_closed_without_delivery(harness):
    h = harness
    h.server.open_gate = threading.Event()
    errors = []

    def worker():
        try:
            with pending(h):
                pass
        except WaitStopped as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    assert h.server.open_started.wait(3)
    h.budget.ended.set()
    thread.join(3)
    assert errors and not thread.is_alive()
    h.server.open_gate.set()
    until(lambda: h.server.ops("close"))
    assert not h.app.bot.sends


def test_expiry_removes_buttons_and_closes_lease(harness):
    h = harness
    h.server.open_reply["expires_at"] = time.time() + 0.25
    with pending(h):
        until(lambda: actionable(h))
        until(lambda: h.server.ops("close"))
        click(h).result(3)
        assert not h.server.ops("resolve")
        assert h.server.ops("close")[0]["reason"] == "expired"


def test_dispose_closes_prompts_and_makes_captured_callbacks_inert(harness):
    h = harness
    with pending(h):
        until(lambda: actionable(h))
        callback = h.app.handlers[0].callback
        h.native.dispose()
        until(lambda: not actionable(h))
        assert all(handle.disposed for handle in h.ctx.handles)
        future = asyncio.run_coroutine_threadsafe(
            callback(types.SimpleNamespace(callback_query=None), None), h.loop
        )
        future.result(3)
        assert not h.server.ops("resolve")


def test_dispose_shares_one_budget_across_unavailable_lease_closes(
    harness, monkeypatch
):
    h = harness
    native = native_module()
    monkeypatch.setattr(native, "_TIMEOUT", 0.05)

    def unavailable_close(path, payload, *, deadline=None):
        if payload["op"] == "close":
            remaining = (
                0.05 if deadline is None else max(0, deadline - time.monotonic())
            )
            time.sleep(min(0.05, remaining))
            raise TimeoutError("bridge unavailable")
        return h.server.request(path, payload)

    with ExitStack() as waits:
        for index in range(8):
            h.server.open_reply["lease_id"] = f"{index:032d}"
            waits.enter_context(
                h.native.pending(
                    "hermes-root",
                    f"call-{index}",
                    h.budget,
                    intaris_session_id="hm-uuid",
                )
            )
        until(lambda: len(h.server.ops("bind")) == 8)
        prompts = list(h.native._prompts)
        monkeypatch.setattr(native, "_exchange", unavailable_close)
        started = time.monotonic()
        h.native.dispose()
        elapsed = time.monotonic() - started
        assert elapsed < 0.2, f"teardown used per-prompt budgets: {elapsed}"
        assert not h.native._prompts and not h.native._leases
        assert all(
            not prompt.active and prompt.reason == "cancelled" for prompt in prompts
        )
        assert all(handle.disposed for handle in h.ctx.handles)


@pytest.mark.parametrize("operation", ["send", "enable_edit"])
def test_telegram_hard_deadline_retires_shielded_io_and_late_result(
    harness, real_deadline, monkeypatch, operation
):
    h = harness
    gate = asyncio.Event()
    started = threading.Event()
    completed = threading.Event()
    target = "send_message" if operation == "send" else "edit_message_text"
    original = getattr(h.app.bot, target)

    async def shielded(**kwargs):
        if operation == "send" or kwargs.get("reply_markup"):
            started.set()
            await wait_ignoring_cancellation(gate)
        result = await original(**kwargs)
        if operation == "send" or kwargs.get("reply_markup"):
            completed.set()
        return result

    monkeypatch.setattr(h.app.bot, target, shielded)
    try:
        with pending(h):
            assert started.wait(1)
            until(lambda: h.server.ops("close"))
            assert h.server.ops("close")[0]["reason"] == "failed"
            assert not h.server.ops("fallback")
            h.loop.call_soon_threadsafe(gate.set)
            assert completed.wait(1)
            until(lambda: h.app.bot.edits and not actionable(h))
            assert not h.server.ops("resolve")
    finally:
        h.loop.call_soon_threadsafe(gate.set)


def test_expired_teardown_budget_retires_locally_without_another_rpc(harness):
    h = harness
    with pending(h):
        until(lambda: actionable(h))
        h.native.dispose(deadline=time.monotonic() - 1)
        until(lambda: not actionable(h))
        assert not h.server.ops("close")
        assert not h.native._leases and not h.native._prompts


def test_callback_acknowledgement_has_hard_deadline(
    harness, real_deadline, monkeypatch
):
    h = harness
    gate = asyncio.Event()

    async def shielded_answer(**kwargs):
        await wait_ignoring_cancellation(gate)

    monkeypatch.setattr(h.app.bot, "answer_callback_query", shielded_answer)
    try:
        with pending(h):
            until(lambda: actionable(h))
            click(h).result(0.5)
            assert h.server.ops("resolve")[0]["decision"] == "approve"
    finally:
        h.loop.call_soon_threadsafe(gate.set)


@pytest.mark.parametrize(
    "fault", [None, "relative", "owner", "mode", "access", "symlink", "not_socket"]
)
def test_socket_trust_checks_every_parent(monkeypatch, fault):
    native = native_module()
    checked = []
    monkeypatch.setattr(native.os, "geteuid", lambda: 501)

    def lstat(path):
        path = str(path)
        checked.append(path)
        mode = stat.S_IFSOCK | 0o600 if path.endswith(".sock") else stat.S_IFDIR | 0o755
        uid = 0
        if path == "/run":
            if fault == "owner":
                uid = 501
            if fault == "mode":
                mode |= 0o020
            if fault == "symlink":
                mode = stat.S_IFLNK | 0o777
        if path.endswith(".sock") and fault == "not_socket":
            mode = stat.S_IFREG | 0o600
        return types.SimpleNamespace(st_mode=mode, st_uid=uid)

    monkeypatch.setattr(native.os, "lstat", lstat)
    monkeypatch.setattr(
        native.os,
        "access",
        lambda path, mode, **kwargs: fault == "access" and str(path) == "/run",
    )
    assert native._trusted_socket(
        "run/native.sock" if fault == "relative" else "/run/intaris/native.sock"
    ) is (fault is None)
    if fault is None:
        assert set(checked) == {"/", "/run", "/run/intaris", "/run/intaris/native.sock"}


@pytest.mark.parametrize(
    "response,valid",
    [
        (b'{"ok":true}\n', True),
        (b'{"ok":true}', False),
        (b'{"ok":NaN}\n', False),
        (b"[]\n", False),
        (b"x" * 65536 + b"\n", False),
    ],
    ids=["valid", "unterminated", "nan", "array", "oversize"],
)
def test_unix_exchange_enforces_newline_json_and_size(monkeypatch, response, valid):
    native = native_module()
    monkeypatch.setattr(native, "_trusted_socket", lambda path: True)
    received = []
    with (
        tempfile.TemporaryDirectory(dir="/tmp", prefix="native-") as directory,
        socket.socket(socket.AF_UNIX) as listener,
    ):
        path = str(Path(directory) / "n.sock")
        listener.bind(path)
        listener.listen(1)

        def server():
            conn, _ = listener.accept()
            with conn:
                data = b""
                while not data.endswith(b"\n"):
                    data += conn.recv(4096)
                received.append(json.loads(data))
                try:
                    conn.sendall(response)
                except BrokenPipeError:
                    pass

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        if valid:
            assert native._exchange(
                path, {"op": "open", "profile": "/profiles/alpha"}
            ) == {"ok": True}
        else:
            with pytest.raises((ValueError, OSError)):
                native._exchange(path, {"op": "open", "profile": "/profiles/alpha"})
        thread.join(3)
    assert received == [{"op": "open", "profile": "/profiles/alpha"}]


def test_unix_exchange_obeys_earlier_aggregate_deadline(monkeypatch):
    native = native_module()
    monkeypatch.setattr(native, "_trusted_socket", lambda path: True)
    release = threading.Event()
    with (
        tempfile.TemporaryDirectory(dir="/tmp", prefix="native-") as directory,
        socket.socket(socket.AF_UNIX) as listener,
    ):
        path = str(Path(directory) / "n.sock")
        listener.bind(path)
        listener.listen(1)

        def server():
            conn, _ = listener.accept()
            with conn:
                conn.recv(4096)
                release.wait(1)

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            with pytest.raises(TimeoutError):
                native._exchange(path, {"op": "close"}, deadline=started + 0.03)
            assert time.monotonic() - started < 0.3
        finally:
            release.set()
            thread.join(2)
        assert not thread.is_alive()
