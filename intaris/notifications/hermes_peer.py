"""Linux peer-authenticated Unix transport for native Hermes approval actions.

The operator attests the gateway's UID, PID and process start time. Tool
subprocesses have different PIDs even when they inherit its UID and environment.
There is deliberately no reusable decision credential in the Hermes profile.
"""

from __future__ import annotations

import asyncio
import contextlib
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
        for gateway in raw["gateways"]:
            if set(gateway) != {"uid", "pid_file", "profiles"}:
                raise ValueError("Invalid gateway configuration")
            uid = gateway["uid"]
            if type(uid) is not int or uid <= 0 or uid == os.getuid():
                raise ValueError("Gateway UID must differ from the Intaris service UID")
            pid_file = _absolute(gateway["pid_file"])
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
            gateways.append({"uid": uid, "pid_file": pid_file, "profiles": profiles})
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


def read_attestation(path: str, gateway_uid: int) -> tuple[int, str]:
    """Read an operator-owned PID/start-time attestation, never a gateway PID file."""
    _protected_path(path, gateway_uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.getuid())
            or info.st_uid == gateway_uid
            or info.st_mode & 0o022
        ):
            raise PermissionError("Untrusted gateway attestation")
        raw = os.read(fd, 129)
    finally:
        os.close(fd)
    fields = raw.split()
    if len(raw) > 128 or len(fields) != 2 or not all(f.isdigit() for f in fields):
        raise PermissionError("Malformed gateway attestation")
    pid, start = int(fields[0]), fields[1].decode("ascii")
    if pid <= 1 or int(start) <= 0:
        raise PermissionError("Invalid gateway process identity")
    return pid, start


def process_start_time(pid: int) -> str:
    """Read Linux process birth ticks; PID reuse cannot reuse an attestation."""
    # comm may contain both spaces and parentheses. Fields after its final ')'
    # start at field 3 (state), so starttime (field 22) is index 19.
    data = Path(f"/proc/{pid}/stat").read_text()
    return data.rsplit(")", 1)[1].split()[19]


def authorize_peer(cfg: dict, *, pid: int, uid: int, profile: str) -> dict:
    """Return exactly one operator policy for this kernel-authenticated peer."""
    for gateway in cfg["gateways"]:
        if gateway["uid"] != uid or profile not in gateway["profiles"]:
            continue
        try:
            expected_pid, start = read_attestation(gateway["pid_file"], uid)
            if expected_pid == pid and process_start_time(pid) == start:
                return gateway["profiles"][profile]
        except (OSError, ValueError, IndexError):
            pass
    raise PermissionError("Gateway process/profile is not authorized")


class HermesApprovalSocket:
    """Serve bounded native approval requests on a private Linux Unix socket."""

    def __init__(self, config: dict, bridge: HermesApprovalBridge) -> None:
        self._config = config
        self._bridge = bridge
        self._server: asyncio.Server | None = None
        self._sweeper: asyncio.Task | None = None
        self._connections: set[asyncio.Task] = set()
        self._socket_identity: tuple[int, int] | None = None

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
        self._server = await asyncio.start_unix_server(
            self._accept, path=path, limit=_LIMIT
        )
        os.chmod(path, 0o660)
        info = path.stat()
        self._socket_identity = (info.st_dev, info.st_ino)
        self._sweeper = asyncio.create_task(self._sweep())

    async def _sweep(self) -> None:
        while True:
            try:
                await self._bridge.sweep()
            except Exception:
                logger.exception("Native approval expiry sweep failed")
            await asyncio.sleep(1)

    async def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        self._connections.add(task)
        try:
            sock = writer.get_extra_info("socket")
            pid, uid, _gid = struct.unpack(
                "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            raw = await asyncio.wait_for(reader.readline(), timeout=2)
            if not raw.endswith(b"\n") or len(raw) > _LIMIT:
                raise ValueError("Invalid frame")
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise ValueError("Invalid request")
            profile = request.get("profile")
            if not isinstance(profile, str):
                raise ValueError("Missing profile")
            policy = authorize_peer(self._config, pid=pid, uid=uid, profile=profile)
            result = await self._bridge.handle(policy, profile, request)
        except asyncio.CancelledError:
            raise
        except Exception:
            result = {"ok": False, "error": "Native approval request refused"}
        finally:
            if not task.cancelled() and "result" in locals():
                with contextlib.suppress(Exception):
                    writer.write(json.dumps(result).encode() + b"\n")
                    await asyncio.wait_for(writer.drain(), timeout=2)
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            self._connections.discard(task)

    async def close(self) -> None:
        """Close this listener and only unlink the socket inode it created."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._sweeper:
            self._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sweeper
        for task in list(self._connections):
            task.cancel()
        if self._connections:
            await asyncio.gather(*self._connections, return_exceptions=True)
        path = Path(self._config["socket_path"])
        if self._socket_identity and path.exists():
            info = path.stat()
            if (info.st_dev, info.st_ino) == self._socket_identity:
                path.unlink()
