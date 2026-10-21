#!/usr/bin/python3 -I
"""Refresh Intaris identity for the trusted Hermes systemd user service.

This authenticates the service process, not its source code. No caller-supplied
PID, gateway secret, profile setting, or Hermes code is executed as root.
"""

from __future__ import annotations

import argparse
import fcntl
import logging
import os
import pwd
import signal
import stat
import subprocess
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

UNIT = "hermes-gateway.service"
TARGET = Path("/run/intaris-native/hermes-gateway.pid")
INTERVAL = 2.0
Identity = tuple[int, int]


def identity_from_state(
    state: dict[str, str], uid: int, proc: Path = Path("/proc")
) -> Identity | None:
    """Validate systemd's main PID against the kernel, including birth time."""
    try:
        if (
            state["LoadState"] != "loaded"
            or state["ActiveState"] not in {"active", "reloading"}
            or state["Type"] not in {"simple", "exec", "notify", "notify-reload"}
            or state["NotifyAccess"] not in {"none", "main"}
        ):
            return None
        pid = int(state["MainPID"])
        group = state["ControlGroup"]
        prefix = f"/user.slice/user-{uid}.slice/user@{uid}.service/"
        if pid <= 1 or not group.startswith(prefix) or not group.endswith("/" + UNIT):
            return None
        task = proc / str(pid)
        fields = (task / "stat").read_text().rsplit(")", 1)[1].split()
        start = int(fields[19])
        if start <= 0 or fields[0] in {"Z", "X", "x"}:
            return None
        identities = [
            line.split()[1:]
            for line in (task / "status").read_text().splitlines()
            if line.startswith("Uid:")
        ]
        if identities != [[str(uid)] * 4]:
            return None
        if "0::" + group not in (task / "cgroup").read_text().splitlines():
            return None
        return pid, start
    except (OSError, ValueError, IndexError, KeyError):
        return None


def current_gateway(uid: int, gid: int) -> Identity | None:
    """Query only the fixed unit; run the D-Bus client without root privileges."""
    properties = "LoadState,ActiveState,SubState,MainPID,ControlGroup,Type,NotifyAccess"
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "--user",
            "--no-pager",
            "show",
            "--all",
            "--property=" + properties,
            UNIT,
        ],
        user=uid,
        group=gid,
        extra_groups=[],
        cwd="/",
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=3,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "XDG_RUNTIME_DIR": f"/run/user/{uid}",
        },
    )
    if result.returncode or len(result.stdout) > 8192:
        raise OSError("Gateway user manager unavailable")
    entries = [line.split("=", 1) for line in result.stdout.splitlines()]
    if any(len(entry) != 2 for entry in entries) or len(dict(entries)) != len(entries):
        raise ValueError("Malformed systemd response")
    return identity_from_state(dict(entries), uid)


class Attester:
    """Serialize atomic identity updates and invalidate unavailable gateways."""

    def __init__(
        self,
        target: Path,
        intaris_uid: int,
        intaris_gid: int,
        observe: Callable[[], Identity | None],
    ):
        self.target = target
        self.intaris_uid = intaris_uid
        self.intaris_gid = intaris_gid
        self.observe = observe

    def _check_parent(self) -> None:
        info = self.target.parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, self.intaris_uid}
            or info.st_mode & 0o022
        ):
            raise PermissionError("Attestation directory is not protected")

    def _existing(self) -> tuple[bytes, os.stat_result] | None:
        try:
            fd = os.open(self.target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise PermissionError("Attestation path must be a regular file") from error
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in {
                0,
                self.intaris_uid,
            }:
                raise PermissionError("Unexpected attestation owner/type")
            return os.read(fd, 129), info
        finally:
            os.close(fd)

    def refresh(self) -> Identity | None:
        """Refresh known state; preserve kernel-bound identity on query failure."""
        self._check_parent()
        fd = os.open(
            self.target.with_name(".attestation.lock"),
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise PermissionError("Untrusted attestation lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._check_parent()
            existing = self._existing()
            # A query failure is unknown, not proof that the gateway stopped.
            # Propagate it without changing the existing PID/start-time record;
            # Intaris still checks that exact process identity on every request.
            identity = self.observe()
            if identity is not None:
                content = f"{identity[0]} {identity[1]}\n".encode()
                if existing is not None:
                    raw, metadata = existing
                    if raw == content and (
                        metadata.st_uid,
                        metadata.st_gid,
                        metadata.st_mode & 0o777,
                    ) == (os.geteuid(), self.intaris_gid, 0o640):
                        return identity
                if self.observe() != identity:
                    identity = None
            if identity is None:
                if existing is not None:
                    self.target.unlink()
                return None
            temporary_fd, temporary = tempfile.mkstemp(
                prefix=".attest-", dir=self.target.parent
            )
            try:
                os.fchown(temporary_fd, os.geteuid(), self.intaris_gid)
                os.fchmod(temporary_fd, 0o640)
                with os.fdopen(temporary_fd, "wb") as output:
                    temporary_fd = -1
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, self.target)
            finally:
                if temporary_fd >= 0:
                    os.close(temporary_fd)
                Path(temporary).unlink(missing_ok=True)
            return identity
        finally:
            os.close(fd)


def main() -> int:
    """Run continuously under systemd, or perform an optional root check."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--watch", action="store_true")
    mode.add_argument("--once", "--confirm-current", action="store_true", dest="once")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root; ordinary tool processes cannot refresh attestation")
    gateway = pwd.getpwnam("hermes")
    intaris = pwd.getpwnam("intaris")
    if gateway.pw_uid <= 0 or gateway.pw_uid == intaris.pw_uid:
        parser.error("Hermes and Intaris require separate service users")
    helper = Attester(
        TARGET,
        intaris.pw_uid,
        intaris.pw_gid,
        lambda: current_gateway(gateway.pw_uid, gateway.pw_gid),
    )
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if args.once:
        identity = helper.refresh()
        logging.info("Gateway attestation: %s", identity or "unavailable")
        return 0 if identity else 1
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    previous: object = object()
    while not stopped.is_set():
        try:
            identity = helper.refresh()
            status = (
                f"Attested gateway PID={identity[0]} start={identity[1]}"
                if identity
                else "Gateway unavailable; native attestation cleared"
            )
        except Exception as error:
            status = f"Attestation refresh failed: {type(error).__name__}"
        if status != previous:
            logging.info("%s", status)
            previous = status
        stopped.wait(INTERVAL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
