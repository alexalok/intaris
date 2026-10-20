"""The native socket authenticates the gateway process, never its tool children."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import stat
import struct
from types import SimpleNamespace

import pytest

from . import test_hermes_bridge

bridge = test_hermes_bridge.bridge


def config():
    return {
        "socket_path": "/run/intaris/telegram.sock",
        "gateways": [
            {
                "uid": 12345,
                "pid_file": "/run/intaris/gateway.pid",
                "profiles": {
                    "/home/hermes/.hermes": {
                        "user_id": "owner",
                        "agent_id": "hermes",
                        "approver_ids": ["42"],
                        "fallback_chat_id": "-999",
                        "fallback_thread_id": "9",
                    }
                },
            }
        ],
    }


def test_explicit_profile_and_process_identity_required(monkeypatch):
    from intaris.notifications import hermes_peer as peer

    cfg = peer.parse_config(config())
    monkeypatch.setattr(peer, "read_attestation", lambda path, uid: (100, "500"))
    monkeypatch.setattr(peer, "process_start_time", lambda pid: "500")
    expected = config()["gateways"][0]["profiles"]["/home/hermes/.hermes"]
    assert (
        peer.authorize_peer(cfg, pid=100, uid=12345, profile="/home/hermes/.hermes")
        == expected
    )
    for pid, uid, profile in [
        (101, 12345, "/home/hermes/.hermes"),
        (100, 12346, "/home/hermes/.hermes"),
        (100, 12345, "/home/hermes/.hermes/profiles/other"),
    ]:
        with pytest.raises(PermissionError):
            peer.authorize_peer(cfg, pid=pid, uid=uid, profile=profile)
    monkeypatch.setattr(peer, "process_start_time", lambda pid: "501")
    with pytest.raises(PermissionError):
        peer.authorize_peer(cfg, pid=100, uid=12345, profile="/home/hermes/.hermes")


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c.update(socket_path="relative.sock"),
        lambda c: c.update(fallback_thread_id="7"),
        lambda c: c.update(fallback_chat_id="@bad"),
        lambda c: c.update(fallback_chat_id="-111", fallback_thread_id=True),
        lambda c: c["gateways"][0].update(uid=os.getuid()),
        lambda c: c["gateways"][0].update(uid=True),
        lambda c: c["gateways"][0].update(pid_file="relative.pid"),
        lambda c: c["gateways"][0]["profiles"]["/home/hermes/.hermes"].update(
            user_id="*"
        ),
        lambda c: c["gateways"][0]["profiles"]["/home/hermes/.hermes"].update(
            approver_ids=[]
        ),
        lambda c: c["gateways"][0]["profiles"]["/home/hermes/.hermes"].update(
            approver_ids=[True]
        ),
        lambda c: c["gateways"][0]["profiles"]["/home/hermes/.hermes"].update(
            fallback_thread_id="bad"
        ),
        lambda c: c["gateways"][0]["profiles"]["/home/hermes/.hermes"].update(
            fallback_chat_id="@anyone"
        ),
    ],
)
def test_bad_security_configuration_fails_closed(change):
    from intaris.notifications.hermes_peer import parse_config

    raw = copy.deepcopy(config())
    change(raw)
    with pytest.raises(ValueError):
        parse_config(raw)


@pytest.mark.parametrize(
    "owner,mode", [(12345, 0o600), (0, 0o666), (0, 0o620), (0, stat.S_IFLNK | 0o777)]
)
def test_agent_owned_writable_or_symlink_attestation_rejected(monkeypatch, owner, mode):
    from intaris.notifications import hermes_peer as peer

    def lstat(path):
        if str(path) == "/run/intaris/gateway.pid":
            return SimpleNamespace(
                st_uid=owner,
                st_mode=mode | (stat.S_IFREG if not stat.S_ISLNK(mode) else 0),
            )
        return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)

    monkeypatch.setattr(peer.os, "lstat", lstat)
    with pytest.raises(PermissionError):
        peer.read_attestation("/run/intaris/gateway.pid", 12345)


def test_bridge_config_is_operator_environment_only(monkeypatch):
    from intaris.config import NotificationConfig

    monkeypatch.setenv("INTARIS_TELEGRAM_BRIDGE", json.dumps(config()))
    assert NotificationConfig().hermes_bridge == config()


def test_process_start_time_handles_spaces_and_parentheses(monkeypatch):
    from pathlib import Path

    from intaris.notifications.hermes_peer import process_start_time

    fields = ["S"] + ["0"] * 18 + ["98765"] + ["0"] * 5
    monkeypatch.setattr(
        Path, "read_text", lambda *a, **kw: "100 (python (gateway)) " + " ".join(fields)
    )
    assert process_start_time(100) == "98765"


def test_two_profiles_cannot_share_same_tenant_agent_binding():
    from intaris.notifications.hermes_peer import parse_config

    raw = config()
    profiles = raw["gateways"][0]["profiles"]
    profiles["/home/hermes/other"] = dict(profiles["/home/hermes/.hermes"])
    with pytest.raises(ValueError, match="distinct"):
        parse_config(raw)


def test_shared_fallback_transport_keeps_runtime_profile_policy():
    from intaris.notifications.hermes_peer import parse_config

    raw = config()
    profiles = raw["gateways"][0]["profiles"]
    profiles["/home/hermes/research"] = {
        "user_id": "owner",
        "agent_id": "research",
        "approver_ids": ["43"],
        "fallback_chat_id": "-888",
        "fallback_transport_profile": "/home/hermes/.hermes",
    }
    parsed = parse_config(raw)["gateways"][0]["profiles"]["/home/hermes/research"]
    assert parsed == profiles["/home/hermes/research"]


@pytest.mark.parametrize(
    "target", [None, True, "default", "/home/../hermes", "/unknown"]
)
def test_invalid_fallback_transport_profile_rejected(target):
    from intaris.notifications.hermes_peer import parse_config

    raw = config()
    raw["gateways"][0]["profiles"]["/home/hermes/.hermes"][
        "fallback_transport_profile"
    ] = target
    with pytest.raises(ValueError):
        parse_config(raw)


def test_fallback_transport_cannot_reference_another_gateway():
    from intaris.notifications.hermes_peer import parse_config

    raw = config()
    raw["gateways"][0]["profiles"]["/home/hermes/.hermes"][
        "fallback_transport_profile"
    ] = "/home/other"
    raw["gateways"].append(
        {
            "uid": 12346,
            "pid_file": "/run/intaris/other.pid",
            "profiles": {
                "/home/other": {
                    "user_id": "other",
                    "agent_id": "other",
                    "approver_ids": ["44"],
                }
            },
        }
    )
    with pytest.raises(ValueError):
        parse_config(raw)


def test_global_fallback_inherited_without_merging_topics_between_chats():
    from intaris.notifications.hermes_peer import parse_config

    raw = config()
    raw.update(fallback_chat_id="-555", fallback_thread_id="21")
    profiles = raw["gateways"][0]["profiles"]
    policy = profiles["/home/hermes/.hermes"]
    policy.pop("fallback_chat_id")
    policy.pop("fallback_thread_id")
    cfg = parse_config(raw)
    assert (
        cfg["gateways"][0]["profiles"]["/home/hermes/.hermes"]["fallback_chat_id"]
        == "-555"
    )
    assert (
        cfg["gateways"][0]["profiles"]["/home/hermes/.hermes"]["fallback_thread_id"]
        == "21"
    )
    policy["fallback_chat_id"] = "-777"
    cfg = parse_config(raw)
    assert (
        cfg["gateways"][0]["profiles"]["/home/hermes/.hermes"].get("fallback_thread_id")
        is None
    )
    policy["fallback_chat_id"] = None
    cfg = parse_config(raw)
    assert (
        cfg["gateways"][0]["profiles"]["/home/hermes/.hermes"].get("fallback_chat_id")
        is None
    )
    assert (
        cfg["gateways"][0]["profiles"]["/home/hermes/.hermes"].get("fallback_thread_id")
        is None
    )


def test_socket_protocol_rejects_agent_child_and_accepts_exact_gateway(
    bridge, monkeypatch
):
    from intaris.notifications import hermes_peer as peer

    cfg = peer.parse_config(config())
    monkeypatch.setattr(peer.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(peer, "read_attestation", lambda *args: (100, "500"))
    monkeypatch.setattr(peer, "process_start_time", lambda pid: "500")
    server = peer.HermesApprovalSocket(cfg, bridge.service)

    class Writer:
        def __init__(self, pid):
            self.pid = pid
            self.output = b""
            self.closed = False

        def get_extra_info(self, name):
            return SimpleNamespace(
                getsockopt=lambda *args: struct.pack("3i", self.pid, 12345, 12345)
            )

        def write(self, data):
            self.output += data

        async def drain(self):
            pass

        def close(self):
            self.closed = True

        async def wait_closed(self):
            pass

    async def request(pid, body):
        reader = asyncio.StreamReader()
        reader.feed_data(
            json.dumps({"profile": "/home/hermes/.hermes", **body}).encode() + b"\n"
        )
        reader.feed_eof()
        writer = Writer(pid)
        await server._accept(reader, writer)
        assert writer.closed
        return json.loads(writer.output)

    async def exercise():
        transport_request = {
            "op": "fallback_transport",
            "fallback_transport_profile": "/attacker-controlled",
        }
        assert not (await request(101, transport_request))["ok"]
        assert await request(100, transport_request) == {
            "ok": True,
            "transport_profile": "/home/hermes/.hermes",
        }
        body = {
            "op": "open",
            "session_id": "s",
            "call_id": "call-owner",
            "remaining_seconds": 60,
            "pid": 100,
            "uid": 12345,
        }
        assert not (await request(101, body))["ok"]
        lease = await request(100, body)
        assert lease["new"] is True
        common = {
            "lease_id": lease["lease_id"],
            "chat_id": "-999",
            "thread_id": "9",
            "message_id": "100",
        }
        assert (await request(100, {"op": "bind", **common}))["ok"]
        action = {"op": "resolve", **common, "decision": "approve", "actor_id": "42"}
        assert not (await request(101, action))["ok"]
        assert (
            bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
            is None
        )
        assert (await request(100, action))["status"] == "approve"
        assert not (await request(100, action))["ok"]

    asyncio.run(exercise())
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        == "approve"
    )
