"""Readonly annotations must never bypass Intaris policy or change destinations."""

from __future__ import annotations

import asyncio
import json
import threading
from contextlib import AsyncExitStack
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import pytest_asyncio
from mcp.types import (
    CallToolResult,
    ListToolsResult,
    TextContent,
    Tool,
    ToolAnnotations,
)

from intaris.audit import AuditStore
from intaris.config import DBConfig, MCPConfig
from intaris.db import Database
from intaris.evaluator import Evaluator
from intaris.mcp.client import MCPConnectionManager, _Connection
from intaris.mcp.proxy import MCPProxy
from intaris.mcp.store import MCPServerStore
from intaris.session import SessionStore


class Upstream:
    def __init__(self):
        self.hint = True
        self.calls = []
        self.on_list = None

    async def send_request(self, request, result_type):
        assert request.root.method == "tools/list"
        params = request.root.params
        result = await self.list_tools(**({"cursor": params.cursor} if params else {}))
        payload = result.model_dump()
        # Simulate raw JSON at the SDK send_request boundary, before bool
        # coercion. list_tools remains the normal permissive discovery view.
        for tool in payload["tools"]:
            if tool.get("annotations") is not None:
                tool["annotations"]["readOnlyHint"] = self.hint
        return result_type.model_validate(payload)

    async def list_tools(self, **kwargs):
        if self.on_list:
            await self.on_list()
        annotations = (
            ToolAnnotations(readOnlyHint=self.hint) if self.hint is not None else None
        )
        return ListToolsResult(
            tools=[Tool(name="inspect", inputSchema={}, annotations=annotations)]
        )

    async def call_tool(self, **kwargs):
        self.calls.append(kwargs)
        return CallToolResult(content=[TextContent(type="text", text="read result")])


class Connections(MCPConnectionManager):
    """Exercise the real connection cache, replacing only network establishment."""

    def __init__(self):
        super().__init__()
        self.upstreams = {}

    async def _connect(self, server_config, *, user_id=""):
        from intaris.mcp.client import config_fingerprint

        client = self.upstreams.setdefault((user_id, server_config["url"]), Upstream())
        return _Connection(
            session=client,
            exit_stack=AsyncExitStack(),
            server_name=server_config["name"],
            user_id=user_id,
            config_fingerprint=config_fingerprint(server_config),
        )


@pytest_asyncio.fixture
async def harness(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "readonly.db")))
    servers = MCPServerStore(db)
    sessions = SessionStore(db)
    audit = AuditStore(db)
    sessions.create(
        user_id="alice",
        session_id="s",
        intention="Inspect project",
        details={"working_directory": "/project"},
    )
    servers.upsert_server(
        user_id="alice",
        name="files",
        transport="streamable-http",
        url="https://old.test/mcp",
        trust_readonly_annotations=True,
    )
    llm = Mock()
    llm.generate.return_value = json.dumps(
        {
            "aligned": False,
            "risk": "high",
            "decision": "deny",
            "reasoning": "LLM denied",
        }
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    connections = Connections()
    upstream = connections.upstreams[("alice", "https://old.test/mcp")] = Upstream()
    proxy = MCPProxy(
        connection_manager=connections,
        evaluator=evaluator,
        session_store=sessions,
        audit_store=audit,
        server_store=servers,
    )

    async def call(**kwargs):
        return await proxy.call_tool_rest(
            **{
                "user_id": "alice",
                "agent_id": "agent",
                "session_id": "s",
                "server_name": "files",
                "tool_name": "inspect",
                "arguments": {},
                **kwargs,
            }
        )

    yield SimpleNamespace(**locals())
    await connections.shutdown()
    db.close()


def test_defaults_and_environment(monkeypatch):
    monkeypatch.delenv("MCP_AUTO_APPROVE_READONLY", raising=False)
    assert MCPConfig().auto_approve_readonly is True
    monkeypatch.setenv("MCP_AUTO_APPROVE_READONLY", "false")
    assert MCPConfig().auto_approve_readonly is False


@pytest.mark.asyncio
async def test_explicit_trusted_hint_approves_and_audits(harness):
    h = harness
    result = await h.call(arguments={"path": "/project/readme"})
    assert result["decision"] == "approve"
    assert not result["isError"]
    assert len(h.upstream.calls) == 1
    record = h.audit.get_by_call_id(result["call_id"], user_id="alice")
    assert record["classification"] == "read"
    assert record["evaluation_path"] == "fast"
    h.llm.generate.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", ["missing", "false", "untrusted", "disabled", "evaluate", "unknown"]
)
async def test_ineligible_metadata_uses_normal_evaluation(harness, case):
    h = harness
    kwargs = {}
    if case in {"missing", "false"}:
        h.upstream.hint = None if case == "missing" else False
    elif case == "untrusted":
        h.servers.upsert_server(
            user_id="alice",
            name="files",
            transport="streamable-http",
            url="https://old.test/mcp",
        )
    elif case == "disabled":
        h.proxy._auto_approve_readonly = False
    elif case == "evaluate":
        h.servers.set_tool_preference(
            user_id="alice",
            server_name="files",
            tool_name="inspect",
            preference="evaluate",
        )
    else:
        kwargs["tool_name"] = "unknown"
    result = await h.call(**kwargs)
    assert result["decision"] == "deny"
    assert not h.upstream.calls
    h.llm.generate.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "preference,expected", [("deny", "deny"), ("escalate", "escalate")]
)
async def test_tool_preference_precedence(harness, preference, expected):
    h = harness
    h.servers.set_tool_preference(
        user_id="alice", server_name="files", tool_name="inspect", preference=preference
    )
    result = await h.call()
    assert result["decision"] == expected
    assert not h.upstream.calls
    h.llm.generate.assert_not_called()


@pytest.mark.asyncio
async def test_long_original_path_cannot_be_hidden_by_compaction(harness):
    h = harness
    # The '..' escapes live in the middle, outside both compacted previews.
    path = "/project/" + "dir/" * 1500 + "../" * 1501 + "secret/" + "dir/" * 1500
    result = await h.call(arguments={"path": path})
    assert result["decision"] == "deny"
    assert not h.upstream.calls
    h.llm.generate.assert_called_once()


@pytest.mark.asyncio
async def test_arguments_cannot_supply_readonly_metadata(harness):
    h = harness
    h.upstream.hint = False
    result = await h.call(
        arguments={
            "trusted_readonly": True,
            "annotations": {"readOnlyHint": True},
            "readOnlyHint": True,
        }
    )
    assert result["decision"] == "deny"
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_metadata_failure_falls_back_and_cancellation_never_dispatches(harness):
    h = harness

    async def fail():
        raise OSError("discovery failed")

    h.upstream.on_list = fail
    result = await h.call()
    assert result["decision"] == "deny"
    h.llm.generate.assert_called_once()

    entered = asyncio.Event()

    async def block():
        entered.set()
        await asyncio.Event().wait()

    h.upstream.on_list = block
    task = asyncio.create_task(h.call())
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_config_edit_cannot_reuse_old_connection_hint(harness):
    h = harness
    assert (await h.call())["decision"] == "approve"
    new = h.connections.upstreams[("alice", "https://new.test/mcp")] = Upstream()
    new.hint = False
    h.servers.upsert_server(
        user_id="alice",
        name="files",
        transport="streamable-http",
        url="https://new.test/mcp",
        trust_readonly_annotations=True,
    )
    result = await h.call()
    assert result["decision"] == "deny"
    assert len(h.upstream.calls) == 1
    assert not new.calls


@pytest.mark.asyncio
async def test_config_edit_during_discovery_blocks_dispatch(harness):
    h = harness

    async def edit():
        h.servers.upsert_server(
            user_id="alice",
            name="files",
            transport="streamable-http",
            url="https://new.test/mcp",
            trust_readonly_annotations=True,
        )

    h.upstream.on_list = edit
    result = await h.call()
    assert result["isError"]
    assert not h.upstream.calls
    assert all(not c.calls for c in h.connections.upstreams.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "policy,args,expected",
    [
        ({"deny_tools": ["files:inspect"]}, {}, "deny"),
        (
            {"deny_paths": ["/project/private/*"]},
            {"path": "/project/private/key"},
            "deny",
        ),
        ({}, {"path": "/outside/key"}, "deny"),
        ({"allow_paths": ["/outside/*"]}, {"path": "/outside/readme"}, "approve"),
    ],
)
async def test_session_and_path_policy_precede_hint(harness, policy, args, expected):
    h = harness
    h.sessions.update_session("s", user_id="alice", policy=policy)
    result = await h.call(arguments=args)
    assert result["decision"] == expected
    assert bool(h.upstream.calls) == (expected == "approve")


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["completed", "suspended", "terminated"])
async def test_inactive_session_precedes_hint(harness, status):
    h = harness
    h.sessions.update_status("s", status, user_id="alice")
    assert (await h.call())["decision"] == "deny"
    assert not h.upstream.calls
    h.llm.generate.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["parent_lifecycle", "alignment"])
async def test_parent_guards_precede_hint(harness, reason):
    from intaris.alignment import AlignmentBarrier

    h = harness
    h.sessions.create(
        user_id="alice", session_id="child", intention="Inspect", parent_session_id="s"
    )
    if reason == "parent_lifecycle":
        h.sessions.update_status("s", "suspended", user_id="alice")
        expected = "deny"
    else:
        barrier = AlignmentBarrier(db=h.db, llm=h.llm)
        barrier._misaligned[("alice", "child")] = "Conflicting intention"
        h.evaluator._alignment_barrier = barrier
        expected = "escalate"
    assert (await h.call(session_id="child"))["decision"] == expected
    assert not h.upstream.calls
    h.llm.generate.assert_not_called()


@pytest.mark.asyncio
async def test_tenants_do_not_share_trust_or_connections(harness):
    h = harness
    assert (await h.call())["decision"] == "approve"
    h.sessions.create(user_id="bob", session_id="s", intention="Inspect")
    h.servers.upsert_server(
        user_id="bob",
        name="files",
        transport="streamable-http",
        url="https://old.test/mcp",
    )
    assert (await h.call(user_id="bob"))["decision"] == "deny"
    h.servers.upsert_server(
        user_id="bob",
        name="files",
        transport="streamable-http",
        url="https://old.test/mcp",
        trust_readonly_annotations=True,
    )
    bob = h.connections.upstreams[("bob", "https://old.test/mcp")] = Upstream()
    bob.hint = False
    assert (await h.call(user_id="bob"))["decision"] == "deny"
    assert not bob.calls
    assert len(h.upstream.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "edit",
    [
        {"trust_readonly_annotations": False},
        {"enabled": False},
        {"agent_pattern": "different-agent"},
    ],
)
async def test_revocation_during_discovery_cannot_grant_approval(harness, edit):
    h = harness

    async def revoke():
        h.servers.upsert_server(
            **{
                "user_id": "alice",
                "name": "files",
                "transport": "streamable-http",
                "url": "https://old.test/mcp",
                "trust_readonly_annotations": True,
                **edit,
            }
        )

    h.upstream.on_list = revoke
    assert (await h.call())["isError"]
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_persistent_cache_is_not_approval_evidence(harness):
    h = harness
    h.upstream.hint = False
    h.servers.update_tools_cache(
        user_id="alice",
        name="files",
        tools=[
            {
                "name": "inspect",
                "inputSchema": {},
                "annotations": {"readOnlyHint": True},
            }
        ],
    )
    assert (await h.call())["decision"] == "deny"
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_replacement_connection_requires_its_own_metadata(harness, monkeypatch):
    h = harness
    original = h.proxy._dispatch_client

    async def replace(**kwargs):
        # Same configuration, different live session after metadata was read.
        h.connections._connections[("alice", "files")].session = Upstream()
        return await original(**kwargs)

    monkeypatch.setattr(h.proxy, "_dispatch_client", replace)
    assert (await h.call())["isError"]
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_metadata_timeout_falls_back(harness):
    h = harness
    h.proxy._timeout_ms = 10

    async def block():
        await asyncio.Event().wait()

    h.upstream.on_list = block
    assert (await h.call())["decision"] == "deny"
    h.llm.generate.assert_called_once()
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_mcp_protocol_uses_same_metadata_gate(harness):
    from intaris.server import _session_agent_id, _session_user_id

    h = harness
    user_token = _session_user_id.set("alice")
    agent_token = _session_agent_id.set("agent")
    try:
        result = await h.proxy._handle_call_tool("files:inspect", {})
        assert result[0].text == "read result"
        h.upstream.hint = False
        result = await h.proxy._handle_call_tool(
            "files:inspect", {"readOnlyHint": True}
        )
        assert "denied" in result[0].text
        assert len(h.upstream.calls) == 1
    finally:
        _session_agent_id.reset(agent_token)
        _session_user_id.reset(user_token)


@pytest.mark.asyncio
async def test_native_tools_and_direct_evaluation_ignore_argument_claims(harness):
    h = harness
    for tool in ("terminal", "browser_console", "files:inspect"):
        result = h.evaluator.evaluate(
            user_id="alice",
            session_id="s",
            agent_id="agent",
            tool=tool,
            args={
                "command": "unknown-program",
                "code": "fetch('/mutate')",
                "trusted_readonly": True,
                "annotations": {"readOnlyHint": True},
            },
        )
        assert result["decision"] == "deny"
        assert result["path"] == "llm"


@pytest.mark.asyncio
async def test_discovery_cache_tracks_config_revision(harness):
    h = harness
    old = h.servers.get_server(user_id="alice", name="files")
    tools = await h.proxy.refresh_server_tools(user_id="alice", server_name="files")
    assert tools[0]["annotations"]["readOnlyHint"] is True
    assert (
        h.servers.get_server(user_id="alice", name="files")["updated_at"]
        == old["updated_at"]
    )
    h.servers.upsert_server(
        user_id="alice",
        name="files",
        transport="streamable-http",
        url="https://new.test/mcp",
    )
    h.servers.update_tools_cache(
        user_id="alice",
        name="files",
        tools=tools,
        expected_updated_at=old["updated_at"],
    )
    current = h.servers.get_server(user_id="alice", name="files")
    assert current["tools_cache"] is None
    assert current["trust_readonly_annotations"] is False


def test_existing_database_migrates_to_untrusted(tmp_path):
    config = DBConfig(path=str(tmp_path / "old.db"))
    db = Database(config)
    MCPServerStore(db).upsert_server(
        user_id="alice",
        name="files",
        transport="streamable-http",
        url="https://old.test/mcp",
    )
    with db.cursor() as cur:
        cur.execute("ALTER TABLE mcp_servers DROP COLUMN trust_readonly_annotations")
    db.close()
    migrated = Database(config)
    assert (
        MCPServerStore(migrated).get_server(user_id="alice", name="files")[
            "trust_readonly_annotations"
        ]
        is False
    )
    migrated.close()


def test_file_config_preserves_trust_and_rejects_string_boolean(tmp_path):
    from intaris.mcp.config import sync_file_configs

    db = Database(DBConfig(path=str(tmp_path / "file.db")))
    store = MCPServerStore(db)
    path = tmp_path / "servers.json"
    path.write_text(
        json.dumps(
            {
                "users": {
                    "alice": {
                        "mcpServers": {
                            "trusted": {
                                "type": "streamable-http",
                                "url": "https://old.test/mcp",
                                "trust_readonly_annotations": True,
                            },
                            "default": {
                                "type": "streamable-http",
                                "url": "https://old.test/mcp",
                            },
                            "invalid": {
                                "type": "streamable-http",
                                "url": "https://old.test/mcp",
                                "trust_readonly_annotations": "false",
                            },
                        }
                    }
                }
            }
        )
    )
    sync_file_configs(store=store, path=str(path))
    assert (
        store.get_server(user_id="alice", name="trusted")["trust_readonly_annotations"]
        is True
    )
    assert (
        store.get_server(user_id="alice", name="default")["trust_readonly_annotations"]
        is False
    )
    with pytest.raises(ValueError):
        store.get_server(user_id="alice", name="invalid")
    db.close()


@pytest.mark.asyncio
async def test_long_denied_path_is_checked_before_compaction(harness):
    h = harness
    h.sessions.update_session(
        "s", user_id="alice", policy={"deny_paths": ["/project/private/*"]}
    )
    path = "/project/" + "dir/" * 1500 + "../" * 1500 + "private/key"
    assert (await h.call(arguments={"path": path}))["decision"] == "deny"
    h.llm.generate.assert_not_called()
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_cancellation_during_evaluation_never_dispatches(harness, monkeypatch):
    h = harness
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    evaluate = h.evaluator.evaluate

    def blocking_evaluate(**kwargs):
        result = evaluate(**kwargs)
        entered.set()
        try:
            assert release.wait(5)
            return result
        finally:
            finished.set()

    monkeypatch.setattr(h.evaluator, "evaluate", blocking_evaluate)
    task = asyncio.create_task(h.call())
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_paginated_metadata_is_used_and_duplicates_are_ambiguous(
    harness, monkeypatch
):
    h = harness
    tool = Tool(
        name="inspect", inputSchema={}, annotations=ToolAnnotations(readOnlyHint=True)
    )

    async def pages(cursor=None):
        if cursor is None:
            return ListToolsResult(tools=[], nextCursor="second")
        return ListToolsResult(tools=[tool])

    monkeypatch.setattr(h.upstream, "list_tools", pages)
    assert (await h.call())["decision"] == "approve"

    async def duplicate(cursor=None):
        return ListToolsResult(
            tools=[tool], nextCursor="second" if cursor is None else None
        )

    monkeypatch.setattr(h.upstream, "list_tools", duplicate)
    assert (await h.call())["decision"] == "deny"
    assert len(h.upstream.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "args,cwd,expected",
    [
        ({"path": "/private/key"}, None, "deny"),
        ({"paths": ["/private/key"]}, "/project", "deny"),
        ({"items": [{"path": "/private/key"}]}, "/project", "deny"),
        ({"paths": ["/outside/file"]}, "/project", "deny"),
        ({"path": "relative/file"}, None, "deny"),
        ({"paths": ["/project/file"]}, "/project", "approve"),
    ],
)
async def test_review_metadata_path_boundaries(harness, args, cwd, expected):
    h = harness
    h.sessions.update_session(
        "s",
        user_id="alice",
        details={"working_directory": cwd},
        policy={"deny_paths": ["/private/*"]},
    )
    result = await h.call(arguments=args)
    assert result["decision"] == expected
    if "/private/" in json.dumps(args):
        h.llm.generate.assert_not_called()
    assert bool(h.upstream.calls) == (expected == "approve")


@pytest.mark.asyncio
async def test_review_late_connection_is_closed_on_owner_task(harness, monkeypatch):
    h = harness
    started = asyncio.Event()
    release = asyncio.Event()
    closed = []
    owners = []
    h.proxy._timeout_ms = 10
    connect = h.connections._connect

    async def slow_connect(config, *, user_id=""):
        conn = await connect(config, user_id=user_id)
        owners.append(asyncio.current_task())
        conn.exit_stack.callback(lambda: closed.append(asyncio.current_task()))
        started.set()
        await release.wait()
        return conn

    monkeypatch.setattr(h.connections, "_connect", slow_connect)
    task = asyncio.create_task(h.call())
    await asyncio.wait_for(started.wait(), 2)
    assert (await task)["decision"] == "deny"
    release.set()

    async def drained():
        return None

    await h.connections._run_in_lifecycle_task(("alice", "files"), drained)
    assert closed == owners
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_review_preference_revocation_during_final_config_read(
    harness, monkeypatch
):
    h = harness
    get_server = h.servers.get_server
    reads = 0

    def revoke_on_final_read(**kwargs):
        nonlocal reads
        reads += 1
        if reads == 3:
            h.servers.set_tool_preference(
                user_id="alice",
                server_name="files",
                tool_name="inspect",
                preference="deny",
            )
        return get_server(**kwargs)

    monkeypatch.setattr(h.servers, "get_server", revoke_on_final_read)
    result = await h.call()
    assert result["isError"]
    assert not h.upstream.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("hint", ["true", "yes", 1])
async def test_review_coerced_metadata_never_grants_approval(harness, hint):
    h = harness
    h.upstream.hint = hint
    assert (await h.call())["decision"] == "deny"
    assert not h.upstream.calls


@pytest.mark.asyncio
async def test_connection_timeout_before_cache_registration_closes_result(
    harness, monkeypatch
):
    h = harness
    closed = []
    connect = h.connections._connect
    h.proxy._timeout_ms = 10

    async def lock_before_delivery(config, *, user_id=""):
        conn = await connect(config, user_id=user_id)
        conn.exit_stack.callback(lambda: closed.append(True))
        await h.connections._lock.acquire()
        return conn

    monkeypatch.setattr(h.connections, "_connect", lock_before_delivery)
    try:
        assert (await h.call())["decision"] == "deny"
    finally:
        h.connections._lock.release()
    assert closed == [True]
    assert not h.upstream.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("during_call", [False, True])
async def test_round2_stale_call_preserves_replacement_connection(
    harness, monkeypatch, during_call
):
    h = harness
    closed = []
    replacement = None

    async def install_replacement():
        nonlocal replacement
        h.servers.upsert_server(
            user_id="alice",
            name="files",
            transport="streamable-http",
            url="https://new.test/mcp",
            trust_readonly_annotations=True,
        )
        config = h.servers.get_server(
            user_id="alice", name="files", decrypt_secrets=True
        )
        replacement = await h.connections.get_or_connect(
            server_config=config, user_id="alice"
        )
        h.connections._connections[("alice", "files")].exit_stack.callback(
            lambda: closed.append(True)
        )

    if during_call:

        async def fail_old_call(**kwargs):
            await install_replacement()
            raise OSError("old connection closed")

        monkeypatch.setattr(h.upstream, "call_tool", fail_old_call)
    else:
        dispatch = h.proxy._dispatch_client

        async def reject_old_binding(**kwargs):
            await install_replacement()
            return await dispatch(**kwargs)

        monkeypatch.setattr(h.proxy, "_dispatch_client", reject_old_binding)
    result = await h.call()
    assert result["isError"]
    assert not closed
    assert h.connections._connections[("alice", "files")].session is replacement


@pytest.mark.asyncio
async def test_round2_pending_alignment_is_awaited(harness):
    from intaris.alignment import AlignmentBarrier

    h = harness
    h.sessions.create(
        user_id="alice", session_id="child", intention="Inspect", parent_session_id="s"
    )
    barrier = AlignmentBarrier(db=h.db, llm=h.llm)
    h.evaluator._alignment_barrier = barrier
    event = asyncio.Event()

    async def finish_check():
        await asyncio.sleep(0.03)
        barrier._misaligned[("alice", "child")] = "Contradicts parent"
        event.set()

    pending = asyncio.create_task(finish_check())
    barrier._pending[("alice", "child")] = (event, pending)
    try:
        result = await h.call(session_id="child")
        assert result["decision"] == "escalate"
        assert barrier.wait_count == 1
        assert not h.upstream.calls
    finally:
        await pending


@pytest.mark.asyncio
async def test_round2_relative_path_with_different_upstream_cwd_uses_llm(harness):
    h = harness
    h.servers.upsert_server(
        user_id="alice",
        name="files",
        transport="stdio",
        command="test-server",
        cwd="/private",
        url="https://old.test/mcp",
        trust_readonly_annotations=True,
    )
    h.sessions.update_session(
        "s", user_id="alice", policy={"deny_paths": ["/private/*"]}
    )
    result = await h.call(arguments={"path": "key"})
    assert result["decision"] == "deny"
    h.llm.generate.assert_called_once()
    assert not h.upstream.calls


@pytest.mark.asyncio
@pytest.mark.parametrize("pending", [False, True])
async def test_child_sessions_keep_per_call_alignment_review(harness, pending):
    from intaris.alignment import AlignmentBarrier

    h = harness
    h.sessions.create(
        user_id="alice", session_id="child", intention="Inspect", parent_session_id="s"
    )
    barrier = AlignmentBarrier(db=h.db, llm=h.llm, timeout_ms=10)
    h.evaluator._alignment_barrier = barrier
    never = None
    if pending:
        never = asyncio.create_task(asyncio.Event().wait())
        barrier._pending[("alice", "child")] = (asyncio.Event(), never)
    try:
        result = await h.call(session_id="child")
        assert result["decision"] == "deny"
        h.llm.generate.assert_called_once()
        assert not h.upstream.calls
    finally:
        if never is not None:
            never.cancel()
            with pytest.raises(asyncio.CancelledError):
                await never


@pytest.mark.asyncio
async def test_cancellation_while_waiting_for_alignment_never_dispatches(harness):
    from intaris.alignment import AlignmentBarrier

    h = harness
    h.sessions.create(
        user_id="alice", session_id="child", intention="Inspect", parent_session_id="s"
    )
    barrier = AlignmentBarrier(db=h.db, llm=h.llm)
    h.evaluator._alignment_barrier = barrier
    never = asyncio.create_task(asyncio.Event().wait())
    barrier._pending[("alice", "child")] = (asyncio.Event(), never)
    task = asyncio.create_task(h.call(session_id="child"))
    try:
        async with asyncio.timeout(2):
            while barrier.wait_count == 0:
                await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not h.upstream.calls
        h.llm.generate.assert_not_called()
    finally:
        never.cancel()
        with pytest.raises(asyncio.CancelledError):
            await never
