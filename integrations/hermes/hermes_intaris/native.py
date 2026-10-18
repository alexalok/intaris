"""Optional native Telegram approvals backed by an operator-owned Unix service.

The existing audit poll remains the execution authority. This module only
correlates admitted Hermes sessions, presents leases, and forwards button claims.
Hermes and Telegram imports stay inside their runtime entry points.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import socket
import stat
import threading
import time
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from itertools import count
from pathlib import Path
from typing import Any

from .waits import Invocation, WaitStopped

logger = logging.getLogger(__name__)
_TIMEOUT = 2.0
_MAX_BYTES = 65536
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32}\Z")
_CALLBACK = re.compile(r"intaris:([ad]):([A-Za-z0-9_-]{32})\Z")
_hub_lock = threading.RLock()
_instances: weakref.WeakSet[NativeApprovals] = weakref.WeakSet()
_generations = count(1)
_BOT_TIMEOUTS = {
    "read_timeout": _TIMEOUT,
    "write_timeout": _TIMEOUT,
    "connect_timeout": _TIMEOUT,
    "pool_timeout": _TIMEOUT,
}


def _valid_socket_path(path: str) -> bool:
    """Validate the launch setting without requiring the bridge to exist yet."""
    return bool(path and os.path.isabs(path) and os.path.normpath(path) == path)


def _trusted_socket(path: str) -> bool:
    """Reject paths that this gateway user (including ACLs) could replace."""
    if not _valid_socket_path(path):
        return False
    try:
        for parent in reversed(Path(path).parents):
            info = os.lstat(parent)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid == os.geteuid()
                or info.st_mode & 0o022
                or os.access(parent, os.W_OK, effective_ids=True)
            ):
                return False
        return stat.S_ISSOCK(os.lstat(path).st_mode)
    except (OSError, ValueError, NotImplementedError):
        return False


def _bad_constant(value: str) -> None:
    raise ValueError("Non-finite native protocol value")


def _exchange(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """One bounded newline-JSON request on a freshly validated Unix socket."""
    if not _trusted_socket(path):
        raise ValueError("Untrusted native approval socket")
    wire = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode() + b"\n"
    if len(wire) > _MAX_BYTES:
        raise ValueError("Native request too large")
    deadline = time.monotonic() + _TIMEOUT
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:

        def remaining() -> None:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise TimeoutError("Native approval request timed out")
            connection.settimeout(timeout)

        remaining()
        connection.connect(path)
        remaining()
        connection.sendall(wire)
        data = bytearray()
        while b"\n" not in data:
            remaining()
            chunk = connection.recv(min(4096, _MAX_BYTES + 1 - len(data)))
            if not chunk:
                raise ValueError("Native response missing newline")
            data.extend(chunk)
            if len(data) > _MAX_BYTES:
                raise ValueError("Native response too large")
        line, extra = bytes(data).split(b"\n", 1)
        if extra:
            raise ValueError("Multiple native responses")
        result = json.loads(line, parse_constant=_bad_constant)
        if not isinstance(result, dict):
            raise ValueError("Native response must be an object")
        return result


def _home() -> str | None:
    try:
        from hermes_constants import get_hermes_home

        return str(get_hermes_home().resolve())
    except (ImportError, OSError, ValueError):
        return None


def _identifier(value: Any, *, signed: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("Missing Telegram identity")
    value = str(value)
    if not re.fullmatch(r"-?[1-9][0-9]*" if signed else r"[1-9][0-9]*", value):
        raise ValueError("Invalid Telegram identity")
    return value


def _thread(value: Any) -> str | None:
    return None if value is None else _identifier(value)


def _approval_route(route: dict[str, Any]) -> dict[str, Any]:
    actors = frozenset(_identifier(actor) for actor in route["actor_ids"])
    if not actors or not isinstance(route["actor_ids"], list):
        raise ValueError("Missing native approvers")
    return {
        "chat_id": _identifier(route["chat_id"], signed=True),
        "thread_id": _thread(route["thread_id"]),
        "actor_ids": actors,
    }


class _Unroutable(ValueError):
    """A known but inconsistent route must not be replaced with a guess."""


@dataclass(eq=False)
class _Binding:
    application: Any
    adapter: Any
    loop: asyncio.AbstractEventLoop
    home: str | None
    bot: Any
    handler: Any = None


@dataclass(eq=False)
class _Prompt:
    invocation: Invocation
    binding: _Binding
    origin: dict[str, Any] | None
    lease_id: str | None = None
    route: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    message_id: str | None = None
    expires_at: float = 0
    deadline: float = 0
    active: bool = False
    claimed: bool = False
    reason: str | None = None
    close_sent: bool = False
    status: str = ""
    timer: threading.Timer | None = None
    # Constructed on the application loop, used to serialize button edits.
    io_lock: asyncio.Lock | None = None


class NativeApprovals:
    """Own native approvals for one resolved Hermes profile home."""

    def __init__(self, home: str, ctx: Any, *, max_sessions: int = 100) -> None:
        self.home = str(Path(home).resolve())
        self._max_sessions = max(1, max_sessions)
        self._lock = threading.RLock()
        self._disposed = False
        self._handles: list[Any] = []
        self._bindings: list[_Binding] = []
        self._gateways: list[Any] = []
        self._admitted: dict[str, dict[str, Any]] = {}
        self._parents: dict[str, str | None] = {}
        self._prompts: set[_Prompt] = set()
        self._leases: dict[str, _Prompt] = {}
        # Deliberately process launch config, never profile/plugin config or secrets.
        self._socket = os.environ.get("INTARIS_NATIVE_APPROVAL_SOCKET", "")
        # Hermes may start before the bridge. Keep hooks ready for subsequent
        # waits; every exchange still validates current filesystem/socket trust.
        self.enabled = _valid_socket_path(self._socket)
        if not self.enabled:
            return
        with _hub_lock:
            _instances.add(self)
        try:
            for name, callback in (
                ("pre_gateway_dispatch", self._capture_gateway),
                ("post_gateway_admission", self._admit),
                ("subagent_start", self._child),
            ):
                self._handles.append(ctx.register_hook(name, callback))

            def install(application: Any, adapter: Any) -> None:
                self._install(application, adapter)

            # Hermes deduplicates by (plugin, factory.__qualname__), even after
            # plugin reload. A disposed generation must not suppress its heir.
            install.__qualname__ = f"NativeApprovals.install_{next(_generations)}"
            handle = ctx.register_telegram_handler(install)
            if handle is not None:
                self._handles.append(handle)
        except Exception:
            self.dispose()
            logger.warning("Native approval hooks unavailable")

    def _capture_gateway(
        self, event: Any, gateway: Any, session_store: Any, **kwargs: Any
    ) -> None:
        # This hook runs BEFORE authorization. Do not inspect/cache event.source.
        with self._lock:
            if (
                not self._disposed
                and session_store is not None
                and getattr(gateway, "session_store", None) is session_store
                and all(item is not gateway for item in self._gateways)
            ):
                self._gateways.append(gateway)

    def _admit(
        self, session_key: str, platform: str, source: dict[str, Any], **kwargs: Any
    ) -> None:
        with self._lock:
            if self._disposed or _home() != self.home or not session_key:
                return
            # Replace, including invalid actor data: never retain an older actor.
            self._admitted.pop(session_key, None)
            if platform == "telegram" and isinstance(source, dict):
                self._admitted[session_key] = dict(source)
            self._trim_routes()

    def _child(
        self, parent_session_id: str, child_session_id: str, **kwargs: Any
    ) -> None:
        with self._lock:
            if self._disposed or _home() != self.home:
                return
            if not isinstance(parent_session_id, str) or not isinstance(
                child_session_id, str
            ):
                return
            if not parent_session_id or not child_session_id:
                return
            previous = self._parents.pop(child_session_id, parent_session_id)
            self._parents[child_session_id] = (
                parent_session_id if previous == parent_session_id else None
            )
            self._trim_routes()

    def _trim_routes(self) -> None:
        # Called under _lock. Eviction loses correlation, so subsequent waits
        # use only the operator fallback until fresh admission restores it.
        # Active prompts already captured their immutable origin and lease.
        for routes in (self._admitted, self._parents):
            while len(routes) > self._max_sessions:
                routes.pop(next(iter(routes)))

    def _install(self, application: Any, adapter: Any) -> None:
        from telegram.ext import CallbackQueryHandler

        loop = asyncio.get_running_loop()
        superseded: set[_Binding] = set()
        retiring: list[tuple[NativeApprovals, _Prompt]] = []
        with _hub_lock, self._lock:
            if self._disposed or any(
                b.application is application for b in self._bindings
            ):
                return
            for owner in _instances:
                with owner._lock:
                    existing = next(
                        (b for b in owner._bindings if b.application is application),
                        None,
                    )
                if existing is not None:
                    if existing.adapter is not adapter or existing.loop is not loop:
                        raise _Unroutable("Application has conflicting adapters")
                    self._bindings.append(existing)
                    return
            binding = _Binding(application, adapter, loop, _home(), application.bot)

            async def callback(update: Any, context: Any) -> None:
                # A shared bot's factory belongs to its transport profile. Route
                # only an exact lease claim to its independently owned profile.
                query = getattr(update, "callback_query", None)
                data = getattr(query, "data", None)
                match = _CALLBACK.fullmatch(data) if isinstance(data, str) else None
                if match is None:
                    return
                owners = []
                with _hub_lock:
                    for owner in _instances:
                        with owner._lock:
                            prompt = owner._leases.get(match[2])
                            if (
                                not owner._disposed
                                and prompt is not None
                                and prompt.binding is binding
                            ):
                                owners.append(owner)
                if len(owners) == 1:
                    await owners[0]._callback(binding, update, context)

            binding.handler = CallbackQueryHandler(callback, pattern="^intaris:")
            application.add_handler(binding.handler)
            # Hermes can rebuild an application on the SAME adapter. Replace
            # every coordinator's reference atomically before accepting claims.
            for owner in _instances:
                with owner._lock:
                    old = {b for b in owner._bindings if b.adapter is adapter}
                    if not old:
                        continue
                    superseded.update(old)
                    owner._bindings = [b for b in owner._bindings if b not in old]
                    owner._bindings.append(binding)
                    for prompt in owner._prompts:
                        if prompt.binding in old:
                            prompt.active = False
                            prompt.reason = prompt.reason or "cancelled"
                            if prompt.timer is not None:
                                prompt.timer.cancel()
                            retiring.append((owner, prompt))
            if binding not in self._bindings:
                self._bindings.append(binding)
        for previous in superseded:
            self._remove_handler(previous)
        for owner, prompt in retiring:
            # Never block the gateway loop on IPC, and never send a superseded
            # prompt through the replacement bot. Cleanup uses its captured bot.
            self._schedule(
                binding, asyncio.to_thread(owner._finish, prompt, "cancelled")
            )

    def _route(self, session_id: str) -> tuple[_Binding, dict[str, Any] | None]:
        from gateway.session_identity import identity_of

        with self._lock:
            seen = set()
            while session_id in self._parents:
                if session_id in seen or self._parents[session_id] is None:
                    raise _Unroutable("Ambiguous child session")
                seen.add(session_id)
                session_id = self._parents[session_id]
            admitted = dict(self._admitted)
        # Runners and native applications are host objects shared across routed
        # profiles. They confer no destination/actor authority: the exact entry,
        # pinned home and adapter below must still agree with this profile.
        gateways_by_id = {}
        bindings_by_id = {}
        with _hub_lock:
            for owner in _instances:
                with owner._lock:
                    gateways_by_id.update((id(g), g) for g in owner._gateways)
                    bindings_by_id.update((id(b), b) for b in owner._bindings)
        gateways = list(gateways_by_id.values())
        bindings = list(bindings_by_id.values())
        matches = []
        for gateway in gateways:
            entry = gateway.session_store.lookup_by_session_id(session_id)
            if entry is not None:
                if entry.session_id != session_id or not entry.session_key:
                    raise _Unroutable("Session identity mismatch")
                matches.append((gateway, entry))
        if len(matches) > 1:
            raise _Unroutable("Ambiguous session route")
        if matches:
            gateway, entry = matches[0]
            source = gateway._restored_source(entry)
            if (
                source is not None
                and getattr(source.platform, "value", source.platform) == "telegram"
            ):
                identity = identity_of(source)
                if (
                    identity is None
                    or str(Path(identity.runtime_home).resolve()) != self.home
                ):
                    raise _Unroutable("Profile identity unavailable")
                if identity.multiplexed and (
                    identity.transport_inferred
                    or entry.transport_profile != identity.transport_profile
                ):
                    raise _Unroutable("Transport identity unavailable")
                adapter = gateway._delivery_adapter_for(source)
                candidates = [b for b in bindings if b.adapter is adapter]
                if len(candidates) != 1:
                    raise _Unroutable("Exact Telegram adapter unavailable")
                self._retain_transport(candidates[0], gateway)
                snapshot = admitted.get(entry.session_key)
                if snapshot is not None:
                    if (
                        snapshot.get("platform") != "telegram"
                        or str(snapshot.get("chat_id")) != str(source.chat_id)
                        or _thread(snapshot.get("thread_id"))
                        != _thread(source.thread_id)
                    ):
                        raise _Unroutable("Admitted source mismatch")
                    try:
                        origin = {
                            "chat_id": _identifier(
                                snapshot.get("chat_id"), signed=True
                            ),
                            "thread_id": _thread(snapshot.get("thread_id")),
                            "user_id": _identifier(snapshot.get("user_id")),
                        }
                    except ValueError:
                        origin = None
                    return candidates[0], origin
                return candidates[0], None
        # Only the operator service can choose a fallback destination. A native
        # application still needs an exact profile owner; never pick a session.
        candidates = [b for b in bindings if b.home == self.home]
        if len(candidates) != 1:
            raise _Unroutable("Fallback transport ambiguous or unavailable")
        self._retain_transport(candidates[0])
        return candidates[0], None

    def _retain_transport(self, binding: _Binding, gateway: Any = None) -> None:
        with _hub_lock, self._lock:
            if self._disposed:
                raise _Unroutable("Native transport disposed")
            if not any(binding in owner._bindings for owner in _instances):
                raise _Unroutable("Native transport superseded")
            if binding not in self._bindings:
                self._bindings.append(binding)
            if gateway is not None and all(g is not gateway for g in self._gateways):
                self._gateways.append(gateway)

    def _rpc(self, op: str, **fields: Any) -> dict[str, Any]:
        return _exchange(self._socket, {"op": op, "profile": self.home, **fields})

    @staticmethod
    def _schedule(binding: _Binding, coroutine: Any) -> None:
        try:
            asyncio.run_coroutine_threadsafe(coroutine, binding.loop)
        except RuntimeError:
            coroutine.close()
            logger.warning("Native Telegram application loop unavailable")

    @contextmanager
    def pending(
        self,
        session_id: str,
        call_id: str,
        invocation: Invocation,
        *,
        intaris_session_id: str,
    ) -> Iterator[None]:
        """Present an escalation while the caller continues its ordinary audit poll."""
        prompt = None
        reason = "completed"
        try:
            invocation.check()
            with self._lock:
                enabled = self.enabled and not self._disposed
            if enabled:
                try:
                    binding, origin = self._route(session_id)
                    remaining = invocation.remaining_seconds
                    if not math.isfinite(remaining) or remaining <= 0:
                        raise WaitStopped("APPROVAL WAIT TIMEOUT (native approval)")
                    prompt = _Prompt(invocation, binding, origin)
                    with self._lock:
                        if self._disposed or binding not in self._bindings:
                            raise _Unroutable("Native transport disposed or superseded")
                        self._prompts.add(prompt)
                    invocation.request(
                        lambda: self._open(
                            prompt, intaris_session_id, call_id, remaining
                        )
                    )
                except WaitStopped:
                    raise
                except Exception:
                    logger.warning("Native approval unavailable; continuing audit wait")
                    if prompt is not None:
                        self._finish(prompt, "failed")
            yield
            invocation.check()
        except WaitStopped as exc:
            # remaining_seconds checks cancellation too; reading it here would
            # raise again before recording the terminal reason.
            reason = (
                "expired"
                if str(exc).startswith("APPROVAL WAIT TIMEOUT")
                else "cancelled"
            )
            raise
        except BaseException:
            reason = "cancelled"
            raise
        finally:
            if prompt is not None:
                self._finish(prompt, reason)

    def _open(
        self, prompt: _Prompt, session_id: str, call_id: str, remaining: float
    ) -> None:
        fields = {
            "session_id": session_id,
            "call_id": call_id,
            "remaining_seconds": remaining,
        }
        if prompt.origin is not None:
            fields["origin"] = prompt.origin
        response = self._rpc("open", **fields)
        if response.get("ok") is not True or response.get("new") is not True:
            return
        lease_id = response.get("lease_id")
        if lease_id is None:
            return
        if not isinstance(lease_id, str) or not _TOKEN.fullmatch(lease_id):
            raise ValueError("Invalid native lease")
        with self._lock:
            if lease_id in self._leases:
                return
            prompt.lease_id = lease_id
        try:
            route = _approval_route(response["route"])
            origin = prompt.origin
            if (
                origin
                and (route["chat_id"], route["thread_id"])
                == (origin["chat_id"], origin["thread_id"])
                and origin["user_id"] in route["actor_ids"]
            ):
                route["actor_ids"] = frozenset((origin["user_id"],))
            expiry = response["expires_at"]
            if (
                isinstance(expiry, bool)
                or not isinstance(expiry, (float, int))
                or not math.isfinite(expiry)
            ):
                raise ValueError("Invalid native expiry")
            text = response["text"]
            if not isinstance(text, str) or not text:
                raise ValueError("Missing native description")
            with self._lock:
                prompt.route = route
                prompt.text = text[:3500]
                prompt.expires_at = expiry
                duration = min(
                    expiry - time.time(), prompt.invocation.remaining_seconds
                )
                prompt.deadline = time.monotonic() + max(0, duration)
                live = not self._disposed and prompt.reason is None and duration > 0
                if live:
                    self._leases[lease_id] = prompt
                    prompt.timer = threading.Timer(
                        duration, self._finish, args=(prompt, "expired")
                    )
                    prompt.timer.daemon = True
                    prompt.timer.start()
            if live:
                self._schedule(prompt.binding, self._deliver(prompt))
            else:
                self._finish(prompt, "expired" if duration <= 0 else "cancelled")
        except BaseException:
            self._finish(prompt, "failed")
            raise

    def _live(self, prompt: _Prompt) -> bool:
        # Caller holds _lock for every read/claim of actionable state.
        if (
            self._disposed
            or prompt.reason is not None
            or prompt.binding not in self._bindings
            or prompt.binding.application.bot is not prompt.binding.bot
        ):
            return False
        if time.time() >= prompt.expires_at or time.monotonic() >= prompt.deadline:
            return False
        try:
            prompt.invocation.check()
        except WaitStopped:
            return False
        return True

    async def _send(self, prompt: _Prompt) -> Any:
        from telegram.error import BadRequest

        for attempt in range(2):
            with self._lock:
                if not self._live(prompt):
                    raise ValueError("Native approval no longer active")
                route = prompt.route
            thread_id = route["thread_id"]
            try:
                return await prompt.binding.bot.send_message(
                    chat_id=route["chat_id"],
                    message_thread_id=int(thread_id) if thread_id is not None else None,
                    text=prompt.text,
                    parse_mode=None,
                    reply_markup=None,
                    **_BOT_TIMEOUTS,
                )
            except BadRequest as exc:
                # Only definite topic rejections prove that no message was sent.
                # Timeouts/network failures and later bind/edit errors never retry.
                if (
                    attempt
                    or thread_id is None
                    or not any(
                        marker in str(exc).lower()
                        for marker in (
                            "message thread not found",
                            "thread not found",
                            "topic_closed",
                            "topic_deleted",
                            "topic not found",
                        )
                    )
                ):
                    raise
                with self._lock:
                    if not self._live(prompt):
                        raise ValueError("Native approval no longer active") from exc
                response = await asyncio.to_thread(
                    prompt.invocation.request,
                    lambda: self._rpc(
                        "fallback",
                        lease_id=prompt.lease_id,
                        chat_id=route["chat_id"],
                        thread_id=thread_id,
                    ),
                )
                if (
                    response.get("ok") is not True
                    or response.get("lease_id") != prompt.lease_id
                    or response.get("expires_at") != prompt.expires_at
                ):
                    raise ValueError("Native fallback rejected") from exc
                fallback = _approval_route(response["route"])
                if (fallback["chat_id"], fallback["thread_id"]) == (
                    route["chat_id"],
                    thread_id,
                ):
                    raise ValueError(
                        "Native fallback did not change destination"
                    ) from exc
                with self._lock:
                    if not self._live(prompt):
                        raise ValueError("Native approval no longer active") from exc
                    prompt.route = fallback

    async def _deliver(self, prompt: _Prompt) -> None:
        from telegram import InlineKeyboardButton, InlineKeyboardMarkup

        prompt.io_lock = asyncio.Lock()
        try:
            async with prompt.io_lock:
                with self._lock:
                    if not self._live(prompt):
                        return
                message = await self._send(prompt)
                thread_id = prompt.route["thread_id"]
                with self._lock:
                    prompt.message_id = _identifier(message.message_id)
                    matches = (
                        _identifier(message.chat.id, signed=True)
                        == prompt.route["chat_id"]
                        and _thread(message.message_thread_id) == thread_id
                    )
                    live = self._live(prompt)
                if not matches:
                    raise ValueError("Telegram delivered to a different route")
                if live:
                    response = await asyncio.to_thread(
                        prompt.invocation.request,
                        lambda: self._rpc("bind", **self._message_fields(prompt)),
                    )
                    if response.get("ok") is not True:
                        raise ValueError("Native message binding rejected")
                    with self._lock:
                        live = self._live(prompt)
                    if live:
                        keyboard = InlineKeyboardMarkup(
                            [
                                [
                                    InlineKeyboardButton(
                                        "Approve",
                                        callback_data=f"intaris:a:{prompt.lease_id}",
                                    ),
                                    InlineKeyboardButton(
                                        "Deny",
                                        callback_data=f"intaris:d:{prompt.lease_id}",
                                    ),
                                ]
                            ]
                        )
                        await self._edit(prompt, prompt.text, keyboard)
                        with self._lock:
                            prompt.active = self._live(prompt)
                with self._lock:
                    live = self._live(prompt)
                if not live:
                    await self._edit(prompt, self._status_text(prompt), None)
        except Exception:
            logger.warning("Native Telegram prompt failed; delivery stopped")
            await asyncio.to_thread(self._finish, prompt, "failed")

    @staticmethod
    def _message_fields(prompt: _Prompt) -> dict[str, Any]:
        return {
            "lease_id": prompt.lease_id,
            "chat_id": prompt.route["chat_id"],
            "thread_id": prompt.route["thread_id"],
            "message_id": prompt.message_id,
        }

    async def _edit(self, prompt: _Prompt, text: str, markup: Any) -> None:
        await prompt.binding.bot.edit_message_text(
            chat_id=prompt.route["chat_id"],
            message_id=int(prompt.message_id),
            text=text,
            reply_markup=markup,
            parse_mode=None,
            **_BOT_TIMEOUTS,
        )

    def _status_text(self, prompt: _Prompt) -> str:
        with self._lock:
            status = {"approve": "Approved", "deny": "Denied"}.get(
                prompt.status, "No longer actionable"
            )
            return f"{prompt.text}\n\n{status}"

    async def _retire(self, prompt: _Prompt) -> None:
        if prompt.io_lock is None:
            return
        async with prompt.io_lock:
            with self._lock:
                has_message = prompt.message_id is not None
            if has_message:
                try:
                    await self._edit(prompt, self._status_text(prompt), None)
                except Exception:
                    logger.warning(
                        "Native prompt buttons could not be removed; lease is inactive"
                    )

    def _finish(self, prompt: _Prompt, reason: str) -> None:
        with self._lock:
            prompt.active = False
            if prompt.reason is None:
                prompt.reason = reason
            if prompt.timer is not None:
                prompt.timer.cancel()
            self._prompts.discard(prompt)
            lease_id = prompt.lease_id
            if lease_id is None or prompt.close_sent:
                return
            prompt.close_sent = True
            self._leases.pop(lease_id, None)
            reason = prompt.reason
        try:
            response = self._rpc("close", lease_id=lease_id, reason=reason)
            with self._lock:
                if response.get("ok") is True and response.get("status") in (
                    "approve",
                    "deny",
                ):
                    prompt.status = response["status"]
        except Exception:
            logger.warning("Native lease close failed; local buttons remain inactive")
        finally:
            self._schedule(prompt.binding, self._retire(prompt))

    async def _answer(self, binding: _Binding, query: Any, text: str) -> None:
        try:
            await binding.bot.answer_callback_query(
                callback_query_id=query.id, text=text, **_BOT_TIMEOUTS
            )
        except Exception:
            logger.debug("Native callback acknowledgement unavailable")

    async def _callback(self, binding: _Binding, update: Any, context: Any) -> None:
        query = getattr(update, "callback_query", None)
        if query is None:
            return
        prompt = None
        try:
            data = query.data
            match = _CALLBACK.fullmatch(data) if isinstance(data, str) else None
            if match is None:
                return
            actor = _identifier(query.from_user.id)
            message = query.message
            bot = binding.bot
            with self._lock:
                candidate = self._leases.get(match[2])
                if (
                    candidate is not None
                    and candidate.binding is binding
                    and candidate.active
                    and not candidate.claimed
                    and self._live(candidate)
                    and context.application is binding.application
                    and context.bot is bot
                    and query.get_bot() is bot
                    and message.get_bot() is bot
                    and message.from_user.id == bot.id
                    and _identifier(message.chat.id, signed=True)
                    == candidate.route["chat_id"]
                    and _thread(message.message_thread_id)
                    == candidate.route["thread_id"]
                    and _identifier(message.message_id) == candidate.message_id
                    and actor in candidate.route["actor_ids"]
                ):
                    candidate.claimed = True
                    candidate.active = False
                    prompt = candidate
        except (AttributeError, ValueError, TypeError):
            pass
        if prompt is None:
            await self._answer(binding, query, "No longer actionable or not authorized")
            return
        await self._answer(binding, query, "Reviewing decision")

        def resolve() -> dict[str, Any]:
            # Acknowledgement and the worker handoff both yield. A close that
            # happened meanwhile retires even a previously valid button claim.
            with self._lock:
                if not self._live(prompt) or not prompt.claimed:
                    return {"ok": False}
            return self._rpc(
                "resolve",
                **self._message_fields(prompt),
                decision="approve" if match[1] == "a" else "deny",
                actor_id=actor,
            )

        try:
            response = await asyncio.to_thread(
                prompt.invocation.request,
                resolve,
            )
            reason = "completed" if response.get("ok") is True else "failed"
        except Exception:
            reason = "failed"
        # Only the server resolves the audit. Never dispatch or return approval.
        await asyncio.to_thread(self._finish, prompt, reason)

    def dispose(self) -> None:
        """Retire hooks, timers and prompts; captured callbacks become inert."""
        with _hub_lock, self._lock:
            if self._disposed:
                return
            self._disposed = True
            _instances.discard(self)
            self.enabled = False
            prompts = list(self._prompts)
            bindings = list(self._bindings)
            handles, self._handles = self._handles, []
            self._admitted.clear()
            self._parents.clear()
            self._gateways.clear()
            for prompt in prompts:
                prompt.active = False
                if prompt.timer is not None:
                    prompt.timer.cancel()
        for handle in reversed(handles):
            if handle is not None:
                try:
                    handle.dispose()
                except Exception:
                    logger.warning("Native hook disposal failed")
        for prompt in prompts:
            self._finish(prompt, "cancelled")
        for binding in bindings:
            self._remove_handler(binding)

    @staticmethod
    def _remove_handler(binding: _Binding) -> None:
        def remove() -> None:
            with _hub_lock:
                for owner in _instances:
                    with owner._lock:
                        if binding in owner._bindings:
                            return
                if binding.handler is None:
                    return
                handler, binding.handler = binding.handler, None
                binding.application.remove_handler(handler)

        try:
            binding.loop.call_soon_threadsafe(remove)
        except RuntimeError:
            pass
