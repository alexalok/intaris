"""Linux peer-authenticated Unix transport for native Hermes approval actions.

The operator trusts each configured Unix user, including its tool subprocesses,
to present native approval actions for explicitly mapped profiles. Kernel peer
credentials identify that user; there is no per-process attestation or reusable
decision credential in the Hermes profile.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import hashlib
import json
import logging
import os
import socket
import stat
import struct
from pathlib import Path
from typing import Any

from intaris.notifications.hermes_bridge import HermesApprovalBridge, telegram_id

logger = logging.getLogger(__name__)
_LIMIT = 65536
_MAX_CONNECTIONS = 32


def _absolute(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or os.path.normpath(value) != value
    ):
        raise ValueError("Native approval paths must be absolute and normalized")
    return value


def parse_config(raw: dict) -> dict:
    """Validate operator-owned configuration without guessing security defaults."""
    try:
        if not isinstance(raw, dict) or set(raw) - {
            "socket_path",
            "gateways",
            "fallback_chat_id",
            "fallback_thread_id",
        }:
            raise ValueError("Invalid bridge configuration")
        fallback_chat = raw.get("fallback_chat_id")
        fallback_thread = raw.get("fallback_thread_id")
        if fallback_chat is not None:
            fallback_chat = telegram_id(fallback_chat)
        if fallback_thread is not None:
            if fallback_chat is None:
                raise ValueError("Fallback topic needs a fallback chat")
            fallback_thread = telegram_id(fallback_thread, positive=True)
        path = _absolute(raw["socket_path"])
        if len(os.fsencode(path)) > 100:
            raise ValueError("Unix socket path too long")
        if not isinstance(raw["gateways"], list) or not raw["gateways"]:
            raise ValueError("At least one gateway required")
        gateways = []
        profiles_seen = set()
        identities_seen = set()
        uids_seen = set()
        for gateway in raw["gateways"]:
            if not isinstance(gateway, dict):
                raise ValueError("Invalid gateway configuration")
            if "pid_file" in gateway:
                raise ValueError(
                    "Gateway attestation was removed; remove pid_file only after "
                    "accepting that all processes under the configured UID are trusted"
                )
            if set(gateway) != {"uid", "profiles"}:
                raise ValueError("Invalid gateway configuration")
            uid = gateway["uid"]
            if type(uid) is not int or uid <= 0 or uid == os.getuid():
                raise ValueError("Gateway UID must differ from the Intaris service UID")
            if uid in uids_seen:
                raise ValueError("Each gateway must have a distinct Unix UID")
            uids_seen.add(uid)
            profiles = {}
            if not isinstance(gateway["profiles"], dict) or not gateway["profiles"]:
                raise ValueError("Explicit profiles required")
            for home, policy in gateway["profiles"].items():
                _absolute(home)
                if home in profiles_seen:
                    raise ValueError("Profile has multiple gateway owners")
                profiles_seen.add(home)
                if not isinstance(policy, dict) or set(policy) - {
                    "user_id",
                    "agent_id",
                    "approver_ids",
                    "fallback_chat_id",
                    "fallback_thread_id",
                    "fallback_transport_profile",
                }:
                    raise ValueError("Invalid profile policy")
                for key in ("user_id", "agent_id"):
                    if (
                        not isinstance(policy.get(key), str)
                        or not policy[key].strip()
                        or policy[key] == "*"
                    ):
                        raise ValueError("Explicit tenant and agent required")
                identity = (policy["user_id"], policy["agent_id"])
                if identity in identities_seen:
                    raise ValueError(
                        "Each native profile needs a distinct tenant/agent identity"
                    )
                identities_seen.add(identity)
                actors = policy.get("approver_ids")
                if not isinstance(actors, list) or not actors:
                    raise ValueError("Explicit Telegram approvers required")
                policy = dict(policy)
                if "fallback_transport_profile" in policy:
                    transport_home = _absolute(policy["fallback_transport_profile"])
                    if transport_home not in gateway["profiles"]:
                        raise ValueError(
                            "Fallback transport must belong to the same gateway"
                        )
                # An explicit chat override starts a new destination: never
                # carry a topic belonging to the global fallback into it.
                if "fallback_chat_id" not in policy:
                    if fallback_chat is not None:
                        policy["fallback_chat_id"] = fallback_chat
                    if (
                        "fallback_thread_id" not in policy
                        and fallback_thread is not None
                    ):
                        policy["fallback_thread_id"] = fallback_thread
                policy["approver_ids"] = list(
                    dict.fromkeys(telegram_id(a, positive=True) for a in actors)
                )
                if policy.get("fallback_chat_id") is not None:
                    policy["fallback_chat_id"] = telegram_id(policy["fallback_chat_id"])
                if policy.get("fallback_thread_id") is not None:
                    if not policy.get("fallback_chat_id"):
                        raise ValueError("Fallback topic needs a fallback chat")
                    policy["fallback_thread_id"] = telegram_id(
                        policy["fallback_thread_id"], positive=True
                    )
                profiles[home] = policy
            gateways.append({"uid": uid, "profiles": profiles})
        return {"socket_path": path, "gateways": gateways}
    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid INTARIS_TELEGRAM_BRIDGE configuration") from exc


def _protected_path(path: str, gateway_uid: int, *, directory: bool = False) -> None:
    """Reject symlinks and any path the gateway or an unrelated user can replace."""
    target = Path(path)
    for item in (target, *target.parents):
        info = os.lstat(item)
        expected_dir = item != target or directory
        valid_type = (
            stat.S_ISDIR(info.st_mode) if expected_dir else stat.S_ISREG(info.st_mode)
        )
        if (
            not valid_type
            or info.st_uid not in (0, os.getuid())
            or info.st_uid == gateway_uid
            or info.st_mode & 0o022
        ):
            raise PermissionError(
                "Native approval path must be protected from the gateway"
            )


def authorize_peer(cfg: dict, *, uid: int, profile: str) -> dict:
    """Return exactly one operator policy for this kernel-authenticated user."""
    for gateway in cfg["gateways"]:
        if gateway["uid"] == uid and profile in gateway["profiles"]:
            return gateway["profiles"][profile]
    raise PermissionError("Gateway Unix user/profile is not authorized")


class HermesApprovalSocket:
    """Serve bounded native approval requests on a private Linux Unix socket."""

    def __init__(self, config: dict, bridge: HermesApprovalBridge) -> None:
        self._config = config
        self._bridge = bridge
        self._server: asyncio.Server | None = None
        self._sweeper: asyncio.Task | None = None
        self._connections: set[asyncio.Task] = set()
        self._socket_identity: tuple[int, int] | None = None
        self._staged_path: Path | None = None
        self._closing = False

    async def start(self) -> None:
        """Start without deleting a pre-existing socket or weakening permissions."""
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("Native Telegram approvals require Linux SO_PEERCRED")
        path = Path(self._config["socket_path"])
        for gateway in self._config["gateways"]:
            _protected_path(str(path.parent), gateway["uid"], directory=True)
        if os.path.lexists(path):
            raise RuntimeError(
                "Native approval socket already exists; verify its owner before removal"
            )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._closing = False
        try:
            # Do not publish the configured path until metadata and permissions
            # are known. Even a failed first lstat cannot strand that path.
            # A short sibling name fits Linux sockaddr_un with the 100-byte
            # configured-path limit. bind never removes an existing entry.
            # Finite, stable slots also bound debris if metadata cannot be read.
            # Unidentified entries are never removed or reused automatically.
            name = hashlib.sha256(os.fsencode(path)).hexdigest()[:6]
            for slot in range(4):
                staged = path.with_name(f".{name}{slot}")
                try:
                    listener.bind(str(staged))
                    break
                except OSError as exc:
                    if exc.errno != errno.EADDRINUSE:
                        raise
            else:
                raise OSError(
                    errno.EADDRINUSE,
                    "Native socket staging paths occupied; verify owners before removal",
                )
            self._staged_path = staged
            info = staged.lstat()
            self._socket_identity = (info.st_dev, info.st_ino)
            os.chmod(staged, 0o660)
            # A hard link publishes the same inode without replacing a path
            # created by another listener after the initial existence check.
            os.link(staged, path, follow_symlinks=False)
            # Passing a socket avoids asyncio's implicit stale-path deletion.
            self._server = await asyncio.start_unix_server(
                self._accept,
                sock=listener,
                limit=_LIMIT,
                backlog=_MAX_CONNECTIONS,
                start_serving=False,
            )
            self._unlink_owned_socket(staged)
            self._staged_path = None
            await self._server.start_serving()
            self._sweeper = asyncio.create_task(self._sweep())
        except BaseException:
            listener.close()
            if self._staged_path and self._socket_identity is None:
                # Without an inode identity, unlinking could delete a foreign
                # replacement. No configured public socket is left behind.
                logger.warning(
                    "Cannot identify unpublished native socket %s; leaving it untouched",
                    self._staged_path,
                )
            try:
                await self.close()
            except Exception:
                logger.exception("Native approval startup cleanup failed")
            raise

    def _unlink_owned_socket(self, path: Path) -> None:
        if self._socket_identity is None:
            return
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if (
            stat.S_ISSOCK(info.st_mode)
            and (info.st_dev, info.st_ino) == self._socket_identity
        ):
            path.unlink()

    async def _sweep(self) -> None:
        while True:
            try:
                await self._bridge.sweep()
            except Exception:
                logger.exception("Native approval expiry sweep failed")
            await asyncio.sleep(1)

    def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> asyncio.Task | None:
        # Admission is synchronous: pending callbacks cannot reserve unlimited
        # tasks before the first handler runs, and no untrusted peer waits for
        # a newline. The listener backlog bounds each event-loop accept batch.
        try:
            if self._closing or len(self._connections) >= _MAX_CONNECTIONS:
                raise PermissionError("Native approval connection limit reached")
            sock = writer.get_extra_info("socket")
            _pid, uid, _gid = struct.unpack(
                "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if not any(gateway["uid"] == uid for gateway in self._config["gateways"]):
                raise PermissionError("Gateway Unix user is not authorized")
        except Exception:
            with contextlib.suppress(Exception):
                writer.write(
                    b'{"ok":false,"error":"Native approval request refused"}\n'
                )
            writer.close()
            return None
        task = asyncio.create_task(self._handle(reader, writer, uid=uid))
        self._connections.add(task)

        def finished(task: asyncio.Task) -> None:
            # Also runs if close() cancels a task before _handle starts.
            writer.close()
            self._connections.discard(task)

        task.add_done_callback(finished)
        return task

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        uid: int,
    ) -> None:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=2)
            if not raw.endswith(b"\n") or len(raw) > _LIMIT:
                raise ValueError("Invalid frame")
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise ValueError("Invalid request")
            profile = request.get("profile")
            if not isinstance(profile, str):
                raise ValueError("Missing profile")
            policy = authorize_peer(self._config, uid=uid, profile=profile)
            result = await self._bridge.handle(policy, profile, request)
        except asyncio.CancelledError:
            raise
        except Exception:
            result = {"ok": False, "error": "Native approval request refused"}
        finally:
            if "result" in locals():
                with contextlib.suppress(Exception):
                    writer.write(json.dumps(result).encode() + b"\n")
                    await asyncio.wait_for(writer.drain(), timeout=2)
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=2)

    async def close(self) -> None:
        """Close this listener and only unlink the socket inode it created."""
        self._closing = True
        server, self._server = self._server, None
        if server:
            server.close()
        if self._sweeper:
            self._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sweeper
            self._sweeper = None
        for task in list(self._connections):
            task.cancel()
        if self._connections:
            await asyncio.gather(*self._connections, return_exceptions=True)
        if server:
            await server.wait_closed()
        self._unlink_owned_socket(Path(self._config["socket_path"]))
        if self._staged_path:
            self._unlink_owned_socket(self._staged_path)
            self._staged_path = None
        self._socket_identity = None
