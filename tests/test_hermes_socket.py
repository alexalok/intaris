"""Native listener startup and admission fail safely before reading frames."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import socket
import stat
import struct
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from intaris.notifications import hermes_peer as peer

from .test_hermes_peer import config


@pytest.fixture
def socket_config(monkeypatch):
    # Short paths stay inside sockaddr_un on Linux and macOS test hosts.
    with tempfile.TemporaryDirectory(prefix="intaris-peer-", dir="/tmp") as directory:
        cfg = config()
        cfg["socket_path"] = str(Path(directory) / "approval.sock")
        monkeypatch.setattr(peer.socket, "SO_PEERCRED", 17, raising=False)
        monkeypatch.setattr(peer, "_protected_path", lambda *args, **kwargs: None)
        yield peer.parse_config(cfg)


class Bridge:
    async def sweep(self):
        pass

    async def handle(self, policy, profile, request):
        return {"ok": True, "agent_id": policy["agent_id"]}


@pytest.mark.parametrize("failure", ["chmod", "stat"])
def test_partial_start_failure_leaves_public_path_free(
    socket_config, monkeypatch, failure
):
    path = Path(socket_config["socket_path"])
    server = peer.HermesApprovalSocket(socket_config, Bridge())

    async def exercise():
        try:
            with monkeypatch.context() as patch:
                if failure == "chmod":

                    def fail_chmod(*args, **kwargs):
                        raise PermissionError("chmod denied")

                    patch.setattr(peer.os, "chmod", fail_chmod)
                else:
                    original_stat = peer.os.stat
                    original_lstat = peer.os.lstat

                    def fail_socket_stat(original, target, *args, **kwargs):
                        info = original(target, *args, **kwargs)
                        if stat.S_ISSOCK(info.st_mode):
                            raise OSError("socket metadata unavailable")
                        return info

                    patch.setattr(
                        peer.os,
                        "stat",
                        lambda *args, **kwargs: fail_socket_stat(
                            original_stat, *args, **kwargs
                        ),
                    )
                    patch.setattr(
                        peer.os,
                        "lstat",
                        lambda *args, **kwargs: fail_socket_stat(
                            original_lstat, *args, **kwargs
                        ),
                    )
                with pytest.raises(OSError):
                    await server.start()
            await server.close()
            assert not os.path.lexists(path)
            replacement = peer.HermesApprovalSocket(socket_config, Bridge())
            try:
                await replacement.start()
            finally:
                await replacement.close()
            assert not os.path.lexists(path)
        finally:
            await server.close()

    asyncio.run(exercise())


def test_close_preserves_replacement_socket(socket_config):
    path = Path(socket_config["socket_path"])
    server = peer.HermesApprovalSocket(socket_config, Bridge())

    async def exercise():
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            await server.start()
            path.unlink()
            replacement.bind(str(path))
            identity = path.lstat()
            await server.close()
            assert path.lstat().st_ino == identity.st_ino
        finally:
            replacement.close()
            await server.close()

    asyncio.run(exercise())


def test_close_preserves_symlink_to_original_socket(socket_config):
    path = Path(socket_config["socket_path"])
    original = path.with_name("original.sock")
    server = peer.HermesApprovalSocket(socket_config, Bridge())

    async def exercise():
        try:
            await server.start()
            path.rename(original)
            path.symlink_to(original)
            await server.close()
            assert path.is_symlink()
            assert original.exists()
        finally:
            await server.close()

    asyncio.run(exercise())


class Writer:
    def __init__(self, pid=100, uid=12345):
        self.pid = pid
        self.uid = uid
        self.output = b""
        self.closed = False

    def get_extra_info(self, name):
        return SimpleNamespace(
            getsockopt=lambda *args: struct.pack("3i", self.pid, self.uid, self.uid)
        )

    def write(self, data):
        self.output += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def accept(server, reader, writer):
    result = server._accept(reader, writer)
    # Exercise both the old async callback and synchronous bounded admission.
    return asyncio.create_task(result) if inspect.iscoroutine(result) else result


@pytest.mark.parametrize(
    "pid,uid,start", [(101, 12345, "500"), (100, 12346, "500"), (100, 12345, "501")]
)
def test_unattested_peer_is_closed_without_waiting_for_a_frame(
    monkeypatch, pid, uid, start
):
    monkeypatch.setattr(peer.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(peer, "read_attestation", lambda *args: (100, "500"))
    monkeypatch.setattr(peer, "process_start_time", lambda peer_pid: start)
    server = peer.HermesApprovalSocket(peer.parse_config(config()), Bridge())

    async def exercise():
        writers = [Writer(pid, uid) for _ in range(128)]
        tasks = [accept(server, asyncio.StreamReader(), writer) for writer in writers]
        try:
            # No newline is sent. Rejection must not retain a frame-reader task.
            await asyncio.sleep(0)
            assert all(writer.closed for writer in writers)
            assert not server._connections
        finally:
            for task in tasks:
                if task:
                    task.cancel()
            await asyncio.gather(
                *(task for task in tasks if task), return_exceptions=True
            )
            await server.close()

    asyncio.run(exercise())


def test_admission_bounds_pending_frames_and_recovers_capacity(monkeypatch):
    monkeypatch.setattr(peer.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(peer, "_MAX_CONNECTIONS", 2, raising=False)
    monkeypatch.setattr(peer, "read_attestation", lambda *args: (100, "500"))
    monkeypatch.setattr(peer, "process_start_time", lambda pid: "500")
    server = peer.HermesApprovalSocket(peer.parse_config(config()), Bridge())

    async def exercise():
        readers = [asyncio.StreamReader() for _ in range(12)]
        writers = [Writer() for _ in readers]
        tasks = [
            accept(server, reader, writer) for reader, writer in zip(readers, writers)
        ]
        try:
            await asyncio.sleep(0)
            assert sum(not writer.closed for writer in writers) == 2
            assert len(server._connections) == 2
            readers[0].feed_data(b'{"profile":"/home/hermes/.hermes"}\n')
            await tasks[0]
            await asyncio.sleep(0)
            reader, writer = asyncio.StreamReader(), Writer()
            reader.feed_data(b'{"profile":"/home/hermes/.hermes"}\n')
            task = accept(server, reader, writer)
            assert task is not None
            await task
            assert json.loads(writer.output) == {"ok": True, "agent_id": "hermes"}
        finally:
            for task in tasks:
                if task:
                    task.cancel()
            await asyncio.gather(
                *(task for task in tasks if task), return_exceptions=True
            )
            await server.close()
        assert all(writer.closed for writer in writers)
        assert not server._connections

    asyncio.run(exercise())


def test_admission_does_not_authorize_another_gateways_profile(monkeypatch):
    monkeypatch.setattr(peer.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(
        peer,
        "read_attestation",
        lambda path, uid: (100 if path.endswith("gateway.pid") else 200, "500"),
    )
    monkeypatch.setattr(peer, "process_start_time", lambda pid: "500")
    cfg = config()
    cfg["gateways"].append(
        {
            "uid": 12345,
            "pid_file": "/run/intaris/other.pid",
            "profiles": {
                "/home/other": {
                    "user_id": "other",
                    "agent_id": "other",
                    "approver_ids": ["43"],
                }
            },
        }
    )
    server = peer.HermesApprovalSocket(peer.parse_config(cfg), Bridge())

    async def exercise():
        reader, writer = asyncio.StreamReader(), Writer()
        reader.feed_data(b'{"profile":"/home/other"}\n')
        task = accept(server, reader, writer)
        if task:
            await task
        assert json.loads(writer.output)["ok"] is False
        await server.close()

    asyncio.run(exercise())


def test_failed_metadata_cannot_accumulate_unbounded_staging_sockets(
    socket_config, monkeypatch
):
    path = Path(socket_config["socket_path"])
    original_stat = peer.os.stat
    original_lstat = peer.os.lstat

    def fail_socket_stat(original, target, *args, **kwargs):
        info = original(target, *args, **kwargs)
        if stat.S_ISSOCK(info.st_mode):
            raise OSError("socket metadata unavailable")
        return info

    async def exercise():
        with monkeypatch.context() as patch:
            patch.setattr(
                peer.os,
                "stat",
                lambda *args, **kwargs: fail_socket_stat(
                    original_stat, *args, **kwargs
                ),
            )
            patch.setattr(
                peer.os,
                "lstat",
                lambda *args, **kwargs: fail_socket_stat(
                    original_lstat, *args, **kwargs
                ),
            )
            for _ in range(12):
                server = peer.HermesApprovalSocket(socket_config, Bridge())
                with pytest.raises(OSError):
                    await server.start()
                await server.close()
        assert not os.path.lexists(path)
        leftovers = list(path.parent.iterdir())
        assert len(leftovers) <= 4
        assert all(stat.S_ISSOCK(item.lstat().st_mode) for item in leftovers)

    asyncio.run(exercise())


def test_published_socket_accepts_connections_and_removes_staging(socket_config):
    path = Path(socket_config["socket_path"])
    server = peer.HermesApprovalSocket(socket_config, Bridge())

    async def exercise():
        try:
            await server.start()
            assert stat.S_IMODE(path.lstat().st_mode) == 0o660
            assert list(path.parent.iterdir()) == [path]
            reader, writer = await asyncio.open_unix_connection(str(path))
            try:
                # This test process is not an attested gateway. A response proves
                # the published hard link reaches the actual Unix listener.
                result = await asyncio.wait_for(reader.readline(), timeout=1)
                assert json.loads(result)["ok"] is False
                assert await reader.read() == b""
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            await server.close()
        assert not list(path.parent.iterdir())

    asyncio.run(exercise())


@pytest.mark.parametrize("failure", [OSError, asyncio.CancelledError])
def test_async_listener_setup_failure_cleans_published_socket(
    socket_config, monkeypatch, failure
):
    path = Path(socket_config["socket_path"])
    server = peer.HermesApprovalSocket(socket_config, Bridge())

    async def fail_setup(*args, **kwargs):
        raise failure("listener setup failed")

    async def exercise():
        with monkeypatch.context() as patch:
            patch.setattr(peer.asyncio, "start_unix_server", fail_setup)
            with pytest.raises(failure, match="listener setup failed"):
                await server.start()
        assert not list(path.parent.iterdir())
        replacement = peer.HermesApprovalSocket(socket_config, Bridge())
        try:
            await replacement.start()
        finally:
            await replacement.close()

    asyncio.run(exercise())


def test_start_failure_preserves_foreign_replacement(socket_config, monkeypatch):
    path = Path(socket_config["socket_path"])
    server = peer.HermesApprovalSocket(socket_config, Bridge())
    foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    async def replace_then_fail(*args, **kwargs):
        path.unlink()
        foreign.bind(str(path))
        raise OSError("setup failed after replacement")

    async def exercise():
        try:
            with monkeypatch.context() as patch:
                patch.setattr(peer.asyncio, "start_unix_server", replace_then_fail)
                with pytest.raises(OSError, match="setup failed after replacement"):
                    await server.start()
            identity = path.lstat()
            await server.close()
            assert path.lstat().st_ino == identity.st_ino
            assert list(path.parent.iterdir()) == [path]
        finally:
            foreign.close()
            await server.close()

    asyncio.run(exercise())


def test_close_cancels_admitted_task_before_handler_starts(monkeypatch):
    monkeypatch.setattr(peer.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(peer, "read_attestation", lambda *args: (100, "500"))
    monkeypatch.setattr(peer, "process_start_time", lambda pid: "500")
    server = peer.HermesApprovalSocket(peer.parse_config(config()), Bridge())

    async def exercise():
        writer = Writer()
        task = accept(server, asyncio.StreamReader(), writer)
        await server.close()
        assert task.cancelled()
        assert writer.closed
        assert not server._connections
        late_writer = Writer()
        assert accept(server, asyncio.StreamReader(), late_writer) is None
        assert late_writer.closed

    asyncio.run(exercise())


def test_profile_authorization_rechecks_attestation_after_frame(monkeypatch):
    monkeypatch.setattr(peer.socket, "SO_PEERCRED", 17, raising=False)
    attestation = SimpleNamespace(pid=100)
    monkeypatch.setattr(
        peer, "read_attestation", lambda *args: (attestation.pid, "500")
    )
    monkeypatch.setattr(peer, "process_start_time", lambda pid: "500")
    server = peer.HermesApprovalSocket(peer.parse_config(config()), Bridge())

    async def exercise():
        reader, writer = asyncio.StreamReader(), Writer()
        task = accept(server, reader, writer)
        attestation.pid = 200
        reader.feed_data(b'{"profile":"/home/hermes/.hermes"}\n')
        await task
        assert json.loads(writer.output)["ok"] is False
        await server.close()

    asyncio.run(exercise())
