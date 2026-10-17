"""Upstream MCP connection manager for intaris.

Manages connections to upstream MCP servers with eager startup,
per-user connection sharing, idle timeout, and graceful cleanup.

Connection lifecycle:
- Connections are established eagerly at startup for all configured servers.
- Servers added after startup are connected lazily on first tool call.
- Each connection is keyed by (user_id, server_name) for per-user isolation.
- Upstream connections are shared across agents for the same user.
  This assumes upstream servers are stateless across tool calls.
  If a server maintains session-scoped state, configure separate
  server entries per agent.
- Idle connections are cleaned up after 30 minutes.
- All connections are closed on shutdown.

Cache isolation:
- npx-based servers get isolated NPM_CONFIG_CACHE per server.
- uvx-based servers get isolated UV_CACHE_DIR per server.
- Cache dirs are persistent across restarts (under MCP_CACHE_DIR).
- On connection failure, the cache dir is wiped and retried once.

Transport support:
- stdio: subprocess via mcp.client.stdio.stdio_client
- streamable-http: via mcp.client.streamable_http.streamablehttp_client
- sse: via mcp.client.sse.sse_client
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import os
import shutil
import threading
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, TextIO, cast
from urllib.parse import quote

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import (
    ClientRequest,
    Implementation,
    ListToolsRequest,
    ListToolsResult,
    PaginatedRequestParams,
    Tool,
    ToolAnnotations,
)
from pydantic import StrictBool

try:
    from mcp.client.streamable_http import streamablehttp_client

    _STREAMABLE_HTTP_LEGACY = True
except ImportError:  # MCP SDK >= 1.26 renamed this client helper.
    from mcp.client.streamable_http import streamable_http_client

    _STREAMABLE_HTTP_LEGACY = False

logger = logging.getLogger(__name__)


class _ApprovalAnnotations(ToolAnnotations):
    """Validate the wire boolean before MCP SDK's permissive bool coercion."""

    readOnlyHint: StrictBool | None = None


class _ApprovalTool(Tool):
    annotations: _ApprovalAnnotations | None = None


class _ApprovalToolsResult(ListToolsResult):
    tools: list[_ApprovalTool]


async def list_tools_for_approval(
    session: ClientSession, *, cursor: str | None = None
) -> ListToolsResult:
    """Read approval evidence with strict parsing at the SDK response boundary.

    Checking ``is True`` after ClientSession.list_tools() is insufficient:
    the SDK otherwise converts strings and numbers into boolean hints. Use
    send_request's public response-model parameter on the raw JSON result.
    Normal discovery and execution retain the SDK's standard behavior.
    """
    return await session.send_request(
        ClientRequest(
            ListToolsRequest(
                params=PaginatedRequestParams(cursor=cursor) if cursor else None,
            )
        ),
        _ApprovalToolsResult,
    )


def _unwrap_exception_group(exc: BaseException) -> BaseException:
    """Extract the most meaningful exception from an ExceptionGroup.

    MCP SDK + anyio often wrap real errors (HTTPStatusError,
    ConnectionRefusedError) inside BaseExceptionGroup with cleanup
    noise (RuntimeError about cancel scopes). This walks the group
    and returns the first non-RuntimeError sub-exception, or the
    first sub-exception if all are RuntimeErrors.
    """
    if not isinstance(exc, BaseExceptionGroup):
        return exc

    # Flatten all leaf exceptions from potentially nested groups.
    leaves: list[BaseException] = []
    stack: list[BaseException] = [exc]
    while stack:
        e = stack.pop()
        if isinstance(e, BaseExceptionGroup):
            stack.extend(e.exceptions)
        else:
            leaves.append(e)

    if not leaves:
        return exc

    # Prefer non-RuntimeError (the actual connection/HTTP error).
    for leaf in leaves:
        if not isinstance(leaf, RuntimeError):
            return leaf

    # All RuntimeErrors — return the first one.
    return leaves[0]


# Idle timeout: close connections unused for this long.
_IDLE_TIMEOUT_SECONDS = 30 * 60  # 30 minutes

# Max connections per user across all sessions.
_MAX_CONNECTIONS_PER_USER = 10

# Background sweep interval for idle connection cleanup.
_SWEEP_INTERVAL_SECONDS = 60


def config_fingerprint(server_config: dict[str, Any]) -> str:
    """Bind a connection to its upstream configuration and config revision.

    Discovery caches are excluded. Secrets participate in the digest but are
    never returned or logged. Tenant isolation is enforced by the cache key.
    """
    fields = (
        "name",
        "transport",
        "command",
        "args",
        "env",
        "cwd",
        "url",
        "headers",
        "agent_pattern",
        "enabled",
        "trust_readonly_annotations",
        "created_at",
        "updated_at",
    )
    payload = {key: server_config.get(key) for key in fields}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()


@dataclass
class _Connection:
    """A live connection to an upstream MCP server."""

    session: ClientSession
    exit_stack: AsyncExitStack
    server_name: str
    user_id: str
    transport: str = ""
    config_fingerprint: str = ""
    owner_task_id: int | None = None
    server_instructions: str | None = None
    last_used: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        """Update last-used timestamp."""
        self.last_used = time.monotonic()


class MCPConnectionManager:
    """Manages upstream MCP server connections.

    Thread-safe for concurrent async access. Each connection is keyed
    by (user_id, server_name) for per-user isolation. Upstream
    connections are shared across agents under the same user — the
    MCP SDK's ResponseRouter handles concurrent call_tool() dispatch.

    Args:
        upstream_timeout_ms: Timeout for upstream MCP calls in milliseconds.
        allow_stdio: Whether stdio transport is allowed.
        cache_dir: Base directory for per-server package caches (npx, uvx).
        server_store: MCPServerStore for eager startup (optional).
    """

    def __init__(
        self,
        *,
        upstream_timeout_ms: int = 30000,
        allow_stdio: bool = True,
        cache_dir: str = "",
        server_store: Any | None = None,
    ):
        self._timeout_ms = upstream_timeout_ms
        self._allow_stdio = allow_stdio
        self._cache_dir = cache_dir
        self._server_store = server_store
        # Key: (user_id, server_name) → _Connection
        self._connections: dict[tuple[str, str], _Connection] = {}
        self._lock = asyncio.Lock()
        # Per-server connect locks to prevent concurrent subprocess spawns.
        self._connect_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._sweep_task: asyncio.Task[None] | None = None
        self._lifecycle_queues: dict[tuple[str, str], asyncio.Queue[Any]] = {}
        self._lifecycle_tasks: dict[tuple[str, str], asyncio.Task[None]] = {}

    async def start(self) -> None:
        """Start the background idle sweep and eagerly connect configured servers.

        Servers are connected sequentially to avoid concurrent npx/uvx
        installs. Failed connections are logged as warnings and retried
        lazily on first tool call.
        """
        if self._sweep_task is None:
            self._sweep_task = asyncio.create_task(self._sweep_loop())
            logger.info(
                "MCPConnectionManager started (sweep interval=%ds)",
                _SWEEP_INTERVAL_SECONDS,
            )
        # Eager startup: pre-connect all enabled servers.
        if self._server_store is not None:
            try:
                servers = await asyncio.to_thread(
                    self._server_store.list_all_enabled_servers,
                )
            except Exception:
                logger.exception("Failed to list MCP servers for eager startup")
                return

            connected = 0
            for server_summary in servers:
                user_id = server_summary["user_id"]
                server_name = server_summary["name"]
                transport = server_summary.get("transport", "")

                try:
                    # Decrypt secrets per-server (not batch) to limit
                    # the window where secrets are in memory.
                    server_cfg = await asyncio.to_thread(
                        self._server_store.get_server,
                        user_id=user_id,
                        name=server_name,
                        decrypt_secrets=True,
                    )

                    key = (user_id, server_name)
                    conn = await self._run_in_lifecycle_task(
                        key,
                        lambda server_cfg=server_cfg, user_id=user_id: self._connect(
                            server_cfg, user_id=user_id
                        ),
                    )

                    async with self._lock:
                        self._connections[key] = conn

                    connected += 1
                    logger.info(
                        "Pre-connected to MCP server '%s' (%s) for user '%s'",
                        server_name,
                        transport,
                        user_id,
                    )
                except Exception:
                    logger.warning(
                        "Failed to pre-connect to MCP server '%s' for user '%s', "
                        "will retry on first tool call",
                        server_name,
                        user_id,
                        exc_info=True,
                    )
                    await self._stop_lifecycle_task((user_id, server_name))

            if connected:
                logger.info(
                    "Eager startup: connected %d/%d MCP servers",
                    connected,
                    len(servers),
                )

    async def shutdown(self) -> None:
        """Close all connections and stop the sweep task.

        Uses per-connection timeouts to prevent hanging on unresponsive
        upstream MCP servers.
        """
        if self._sweep_task is not None:
            self._sweep_task.cancel()
            try:
                await self._sweep_task
            except asyncio.CancelledError:
                pass
            self._sweep_task = None

        async with self._lock:
            keys = list(self._connections.keys())
            for key in keys:
                try:
                    await self._run_in_lifecycle_task(
                        key,
                        lambda key=key: self._close_connection(key),
                        timeout=3.0,
                    )
                except (asyncio.TimeoutError, Exception):
                    logger.warning("MCP connection %s close timed out or failed", key)
            self._connect_locks.clear()
            logger.info(
                "MCPConnectionManager shutdown: closed %d connections", len(keys)
            )

        for key in keys:
            await self._stop_lifecycle_task(key)

        stale_keys = list(self._lifecycle_tasks.keys())
        for key in stale_keys:
            await self._stop_lifecycle_task(key)

    async def get_or_connect(
        self,
        *,
        server_config: dict[str, Any],
        user_id: str = "",
    ) -> ClientSession:
        """Get an existing connection or create a new one.

        Args:
            server_config: Server config dict from MCPServerStore.get_server()
                with decrypt_secrets=True. Must include: name, transport,
                and transport-specific fields.
            user_id: User who owns this connection (for per-user limits).

        Returns:
            An initialized ClientSession ready for tool calls.

        Raises:
            ValueError: If transport is not supported, stdio is disabled,
                or the per-user connection limit is exceeded.
            ConnectionError: If upstream connection fails.
        """
        server_name = server_config["name"]
        key = (user_id, server_name)
        fingerprint = config_fingerprint(server_config)

        # Fast path: check cache under lock.
        async with self._lock:
            conn = self._connections.get(key)
            if conn is not None and conn.config_fingerprint == fingerprint:
                conn.touch()
                return conn.session

            # Enforce per-user connection limit.
            if user_id and conn is None:
                user_count = sum(
                    1 for c in self._connections.values() if c.user_id == user_id
                )
                if user_count >= _MAX_CONNECTIONS_PER_USER:
                    raise ValueError(
                        f"Connection limit exceeded: user '{user_id}' has "
                        f"{user_count}/{_MAX_CONNECTIONS_PER_USER} connections. "
                        f"Close unused connections or increase the limit."
                    )

        # Per-server lock: prevent concurrent subprocess spawns for the
        # same (user_id, server_name). This avoids npx/uvx cache races.
        if key not in self._connect_locks:
            self._connect_locks[key] = asyncio.Lock()

        async with self._connect_locks[key]:
            # Re-check cache: another coroutine may have connected while
            # we waited for the per-server lock.
            async with self._lock:
                conn = self._connections.get(key)
                if conn is not None and conn.config_fingerprint == fingerprint:
                    conn.touch()
                    return conn.session

            # Config edits must not reuse an old endpoint, credentials or trust
            # decision. Serialize reconnects with other connects for this key.
            if conn is not None:
                await self.evict(user_id, server_name)

            # Connect outside the main lock.
            try:
                new_conn = await self._run_in_lifecycle_task(
                    key,
                    lambda: self._connect(server_config, user_id=user_id),
                )
            except Exception:
                await self._stop_lifecycle_task(key)
                raise

            try:
                async with self._lock:
                    self._connections[key] = new_conn
                    logger.info(
                        "Connected to upstream MCP server '%s' (user=%s)",
                        server_name,
                        user_id,
                    )
                    return new_conn.session
            except asyncio.CancelledError:
                await self._close_unclaimed_connection(key, new_conn)
                raise

    async def _close_unclaimed_connection(
        self, key: tuple[str, str], conn: _Connection
    ) -> None:
        """Dispose of an unregistered result on its owning lifecycle task."""
        try:
            await asyncio.shield(
                self._run_in_lifecycle_task(
                    key,
                    conn.exit_stack.aclose,
                    timeout=3.0,
                )
            )
        except Exception:
            logger.exception("Failed to close abandoned MCP connection")

    def connection_matches(
        self, *, user_id: str, server_config: dict[str, Any], session: ClientSession
    ) -> bool:
        """Check that metadata and execution still refer to the same connection.

        Called on the manager's event loop without an intervening await before
        dispatch. A replacement connection must rediscover its own metadata.
        """
        conn = self._connections.get((user_id, server_config["name"]))
        return (
            conn is not None
            and conn.session is session
            and conn.config_fingerprint == config_fingerprint(server_config)
        )

    async def evict(
        self,
        user_id: str,
        server_name: str,
        *,
        expected_session: ClientSession | None = None,
    ) -> None:
        """Remove a dead connection from the cache and close it.

        Called by the proxy when an upstream call fails, so the next
        call creates a fresh connection instead of reusing the dead one.
        """
        key = (user_id, server_name)
        async with self._lock:
            if expected_session is not None:
                current = self._connections.get(key)
                if current is None or current.session is not expected_session:
                    return
            if key in self._connections:
                try:
                    await self._run_in_lifecycle_task(
                        key,
                        lambda: self._close_connection(key),
                        timeout=3.0,
                    )
                except (asyncio.TimeoutError, Exception):
                    # Force-remove on timeout or error to avoid stale entries.
                    self._connections.pop(key, None)
                    logger.warning(
                        "Eviction of '%s' (user=%s) timed out or failed",
                        server_name,
                        user_id,
                    )
                else:
                    logger.info(
                        "Evicted dead connection to '%s' (user=%s)",
                        server_name,
                        user_id,
                    )
                finally:
                    await self._stop_lifecycle_task(key)

    def get_server_instructions(self, user_id: str, server_name: str) -> str | None:
        """Get cached server instructions for a connection."""
        conn = self._connections.get((user_id, server_name))
        return conn.server_instructions if conn else None

    def connection_count(self, *, user_id: str | None = None) -> int:
        """Count active connections, optionally filtered by user_id."""
        if user_id is None:
            return len(self._connections)
        return sum(1 for c in self._connections.values() if c.user_id == user_id)

    async def _connect(
        self, server_config: dict[str, Any], *, user_id: str = ""
    ) -> _Connection:
        """Establish a new connection to an upstream MCP server.

        For stdio servers using npx/uvx, injects per-server cache
        isolation env vars and retries once on failure after clearing
        the cache directory.

        Raises:
            ValueError: If transport is unsupported or stdio is disabled.
            ConnectionError: If the upstream server is unreachable.
        """
        transport = server_config["transport"]

        if transport == "stdio":
            return await self._connect_with_retry(server_config, user_id=user_id)

        # Non-stdio transports: no retry needed.
        return await self._do_connect(server_config, user_id=user_id)

    async def _connect_with_retry(
        self, server_config: dict[str, Any], *, user_id: str = ""
    ) -> _Connection:
        """Connect a stdio server with retry-on-failure for npx/uvx.

        On first failure, clears the per-server cache directory and
        retries once. Only catches Exception (not BaseException) to
        preserve shutdown cancellation semantics.
        """
        server_name = server_config["name"]

        try:
            return await self._do_connect(server_config, user_id=user_id)
        except Exception as exc:
            cache_dir = self._get_server_cache_dir(
                server_config.get("command", ""), user_id, server_name
            )
            if cache_dir and os.path.isdir(cache_dir):
                logger.warning(
                    "Stdio connection to '%s' failed, clearing cache at %s "
                    "and retrying: %s",
                    server_name,
                    cache_dir,
                    exc,
                )
                shutil.rmtree(cache_dir, ignore_errors=True)
                try:
                    return await self._do_connect(server_config, user_id=user_id)
                except Exception:
                    logger.warning(
                        "Retry also failed for '%s' after cache cleanup",
                        server_name,
                    )
                    raise
            raise

    async def _do_connect(
        self, server_config: dict[str, Any], *, user_id: str = ""
    ) -> _Connection:
        """Establish a single connection attempt to an upstream MCP server."""
        transport = server_config["transport"]
        server_name = server_config["name"]
        timeout_seconds = self._timeout_ms / 1000.0

        exit_stack = AsyncExitStack()
        try:
            if transport == "stdio":
                if not self._allow_stdio:
                    raise ValueError(
                        f"stdio transport is disabled (MCP_ALLOW_STDIO=false). "
                        f"Cannot connect to server '{server_name}'."
                    )
                read_stream, write_stream = await self._connect_stdio(
                    exit_stack, server_config, user_id=user_id
                )
            elif transport == "streamable-http":
                read_stream, write_stream = await self._connect_streamable_http(
                    exit_stack, server_config, timeout_seconds
                )
            elif transport == "sse":
                read_stream, write_stream = await self._connect_sse(
                    exit_stack, server_config, timeout_seconds
                )
            else:
                raise ValueError(
                    f"Unsupported transport '{transport}' for server '{server_name}'"
                )

            # Create and initialize the MCP client session.
            session = await exit_stack.enter_async_context(
                ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=timeout_seconds),
                    client_info=Implementation(
                        name="intaris-proxy",
                        version="0.11.0",
                    ),
                )
            )

            init_result = await session.initialize()
            server_instructions = getattr(init_result, "instructions", None)

            logger.debug(
                "Initialized upstream '%s' (%s): instructions=%s",
                server_name,
                transport,
                bool(server_instructions),
            )

            return _Connection(
                session=session,
                exit_stack=exit_stack,
                server_name=server_name,
                user_id=user_id,
                transport=transport,
                config_fingerprint=config_fingerprint(server_config),
                owner_task_id=(
                    id(asyncio.current_task())
                    if asyncio.current_task() is not None
                    else None
                ),
                server_instructions=server_instructions,
            )

        except BaseException as exc:
            # Clean up the exit stack on any failure.
            await exit_stack.aclose()
            # Unwrap ExceptionGroups (common with anyio/MCP SDK) to
            # surface the actual root cause instead of opaque errors.
            root = _unwrap_exception_group(exc)
            if root is not exc:
                raise ConnectionError(
                    f"Failed to connect to '{server_name}' ({transport}): {root}"
                ) from root
            raise

    async def _connect_stdio(
        self,
        exit_stack: AsyncExitStack,
        server_config: dict[str, Any],
        *,
        user_id: str = "",
    ) -> tuple[Any, Any]:
        """Connect via stdio transport (subprocess).

        Injects per-server cache isolation env vars for npx/uvx
        commands to prevent cache corruption from concurrent installs.
        """
        command = server_config["command"]
        user_env = server_config.get("env")

        # Build env with cache isolation for npx/uvx.
        cache_env = self._cache_env_for_stdio(command, user_id, server_config["name"])
        if cache_env:
            # Merge: cache env (lowest) → user env (wins on conflict).
            # MCP SDK merges get_default_environment() underneath.
            env = {**cache_env, **(user_env or {})}
        else:
            env = user_env

        params = StdioServerParameters(
            command=command,
            args=server_config.get("args") or [],
            env=env,
            cwd=server_config.get("cwd"),
        )

        # Capture stderr to logging.
        stderr_log = cast(TextIO, _StderrLogger(server_config["name"]))

        read_stream, write_stream = await exit_stack.enter_async_context(
            stdio_client(params, errlog=stderr_log)
        )
        return read_stream, write_stream

    async def _connect_streamable_http(
        self,
        exit_stack: AsyncExitStack,
        server_config: dict[str, Any],
        timeout_seconds: float,
    ) -> tuple[Any, Any]:
        """Connect via streamable HTTP transport."""
        url = server_config["url"]
        headers = server_config.get("headers")

        if _STREAMABLE_HTTP_LEGACY:
            context = streamablehttp_client(
                url=url,
                headers=headers,
                timeout=timedelta(seconds=timeout_seconds),
            )
        else:
            import httpx

            http_client = await exit_stack.enter_async_context(
                httpx.AsyncClient(
                    headers=headers,
                    timeout=timeout_seconds,
                )
            )
            context = streamable_http_client(url=url, http_client=http_client)

        streams = await exit_stack.enter_async_context(context)
        read_stream, write_stream = streams[:2]
        return read_stream, write_stream

    async def _connect_sse(
        self,
        exit_stack: AsyncExitStack,
        server_config: dict[str, Any],
        timeout_seconds: float,
    ) -> tuple[Any, Any]:
        """Connect via SSE transport."""
        url = server_config["url"]
        headers = server_config.get("headers")

        read_stream, write_stream = await exit_stack.enter_async_context(
            sse_client(
                url=url,
                headers=headers,
                timeout=timeout_seconds,
            )
        )
        return read_stream, write_stream

    # ── Cache isolation helpers ───────────────────────────────────

    def _cache_env_for_stdio(
        self, command: str, user_id: str, server_name: str
    ) -> dict[str, str]:
        """Compute cache isolation env vars for npx/uvx commands.

        Returns env vars to inject, or empty dict if not applicable.
        User-configured env vars take precedence over these.
        """
        if not self._cache_dir:
            return {}

        basename = os.path.basename(command)

        if basename in ("npx", "npx.cmd"):
            cache_dir = self._get_server_cache_dir(command, user_id, server_name)
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
                return {"NPM_CONFIG_CACHE": cache_dir}
        elif basename == "uvx":
            cache_dir = self._get_server_cache_dir(command, user_id, server_name)
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
                return {"UV_CACHE_DIR": cache_dir}

        return {}

    def _get_server_cache_dir(
        self, command: str, user_id: str, server_name: str
    ) -> str:
        """Compute the per-server cache directory path.

        Returns empty string if cache_dir is not configured or if
        user_id/server_name contain unsafe characters.
        """
        if not self._cache_dir:
            return ""

        basename = os.path.basename(command)
        if basename not in ("npx", "npx.cmd", "uvx"):
            return ""

        # Encode user_id to prevent path traversal while supporting full email
        # local-part syntax and other identifier characters.
        encoded_user_id = self._encode_cache_component(user_id)
        if not encoded_user_id:
            logger.warning(
                "Skipping cache isolation for server '%s': "
                "user_id %r contains unsafe characters",
                server_name,
                user_id,
            )
            return ""

        encoded_server_name = self._encode_cache_component(server_name)
        if not encoded_server_name:
            return ""

        subdir = "npm" if basename in ("npx", "npx.cmd") else "uv"
        return os.path.join(
            self._cache_dir, encoded_user_id, encoded_server_name, subdir
        )

    @staticmethod
    def _is_safe_path_component(value: str) -> bool:
        """Return True when a value can be encoded into a cache path component."""
        if not value or len(value) > 256:
            return False
        if ".." in value:
            return False
        if "\x00" in value:
            return False
        return True

    @staticmethod
    def _encode_cache_component(value: str) -> str:
        """Encode an identifier into a safe single cache path component."""
        if not MCPConnectionManager._is_safe_path_component(value):
            return ""
        return quote(value, safe="")

    # ── Connection lifecycle ──────────────────────────────────────

    async def _close_connection(self, key: tuple[str, str]) -> None:
        """Close and remove a connection by key. Must be called under lock."""
        conn = self._connections.pop(key, None)
        if conn is None:
            return
        current_task = asyncio.current_task()
        current_task_id = id(current_task) if current_task is not None else None
        if conn.owner_task_id is not None and conn.owner_task_id != current_task_id:
            logger.debug(
                "Skipping explicit close for '%s' (user=%s, transport=%s): "
                "connection was opened in task %s and cannot be safely "
                "closed from task %s; evicting from cache only",
                key[1],
                key[0],
                conn.transport,
                conn.owner_task_id,
                current_task_id,
            )
            return
        try:
            await conn.exit_stack.aclose()
            logger.debug("Closed connection to '%s' (user=%s)", key[1], key[0])
        except Exception:
            logger.exception("Error closing connection to '%s'", key[1])

    async def _sweep_loop(self) -> None:
        """Background task: close idle connections periodically."""
        while True:
            try:
                await asyncio.sleep(_SWEEP_INTERVAL_SECONDS)
                await self._sweep_idle()
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("Error in connection sweep")

    async def _sweep_idle(self) -> None:
        """Close connections that have been idle beyond the timeout."""
        now = time.monotonic()
        async with self._lock:
            idle_keys = [
                key
                for key, conn in self._connections.items()
                if (now - conn.last_used) > _IDLE_TIMEOUT_SECONDS
            ]
            for key in idle_keys:
                logger.info(
                    "Closing idle connection to '%s' (user=%s, idle %.0fs)",
                    key[1],
                    key[0],
                    now - self._connections[key].last_used,
                )
                try:
                    await self._run_in_lifecycle_task(
                        key,
                        lambda key=key: self._close_connection(key),
                        timeout=3.0,
                    )
                except (asyncio.TimeoutError, Exception):
                    self._connections.pop(key, None)
                    logger.warning("Idle close of '%s' timed out or failed", key[1])
                finally:
                    await self._stop_lifecycle_task(key)

            # Clean up per-server locks for connections that no longer exist
            # and are not currently being established.
            stale_locks = [k for k in self._connect_locks if k not in self._connections]
            for k in stale_locks:
                # Only remove if the lock is not currently held (not acquired).
                lock = self._connect_locks[k]
                if not lock.locked():
                    del self._connect_locks[k]

    async def _ensure_lifecycle_task(self, key: tuple[str, str]) -> None:
        """Start the task-affine lifecycle runner for a connection key."""

        queue = self._lifecycle_queues.get(key)
        if queue is None:
            queue = asyncio.Queue()
            self._lifecycle_queues[key] = queue
        task = self._lifecycle_tasks.get(key)
        if task is None or task.done():
            self._lifecycle_tasks[key] = asyncio.create_task(
                self._lifecycle_loop(key, queue)
            )

    async def _run_in_lifecycle_task(
        self,
        key: tuple[str, str],
        operation,
        *,
        timeout: float | None = None,
    ) -> Any:
        """Execute connect/close work on the key-scoped lifecycle task.

        Some MCP SDK async context managers require __aexit__ to run on the same
        task that entered them. Routing both open and close for the same
        connection key through one dedicated task keeps that invariant without
        globally serializing unrelated upstream servers.
        """

        await self._ensure_lifecycle_task(key)
        lifecycle_task = self._lifecycle_tasks[key]
        if asyncio.current_task() is lifecycle_task:
            if timeout is None:
                return await operation()
            async with asyncio.timeout(timeout):
                return await operation()

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        queue = self._lifecycle_queues[key]
        await queue.put((operation, fut, timeout))
        try:
            return await fut
        except asyncio.CancelledError:
            # The worker may have delivered a connection just before the
            # caller was cancelled, but before it could register ownership.
            if not fut.cancelled() and fut.done() and fut.exception() is None:
                result = fut.result()
                if isinstance(result, _Connection):
                    await self._close_unclaimed_connection(key, result)
            raise

    async def _lifecycle_loop(
        self, key: tuple[str, str], queue: asyncio.Queue[Any]
    ) -> None:
        """Run queued connection lifecycle operations serially for one key."""

        while True:
            item = await queue.get()
            if item is None:
                return
            operation, fut, timeout = item
            if fut.cancelled():
                continue
            try:
                if timeout is None:
                    result = await operation()
                else:
                    async with asyncio.timeout(timeout):
                        result = await operation()
            except asyncio.CancelledError as exc:
                if (
                    asyncio.current_task() is not None
                    and asyncio.current_task().cancelled()
                ):
                    raise
                if not fut.cancelled():
                    fut.set_exception(exc)
            except Exception as exc:
                if not fut.cancelled():
                    fut.set_exception(exc)
            else:
                if not fut.cancelled():
                    fut.set_result(result)
                elif isinstance(result, _Connection):
                    # Discovery timeout/cancellation does not stop the task
                    # that owns MCP's async contexts. Close its late result
                    # here, on that same task, rather than leaking transport
                    # resources or reusing an unevaluated connection.
                    try:
                        await result.exit_stack.aclose()
                    except Exception:
                        logger.exception("Failed to close late MCP connection")

    async def _stop_lifecycle_task(self, key: tuple[str, str]) -> None:
        """Stop the task-affine lifecycle runner for a connection key."""

        task = self._lifecycle_tasks.get(key)
        if task is None:
            return
        queue = self._lifecycle_queues.get(key)
        if queue is not None:
            await queue.put(None)
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        self._lifecycle_tasks.pop(key, None)
        self._lifecycle_queues.pop(key, None)


class _StderrLogger(io.RawIOBase):
    """Routes subprocess stderr to Python logging via an OS pipe.

    Used as the errlog parameter for stdio_client to capture upstream
    server error output with proper server name prefixing.

    Uses a real OS pipe so that subprocess.Popen can wire up the child
    process's stderr via fileno(). A background daemon thread reads
    from the pipe and routes complete lines through Python logging.
    """

    def __init__(self, server_name: str):
        super().__init__()
        self._server_name = server_name
        self._read_fd, self._write_fd = os.pipe()
        self._thread = threading.Thread(
            target=self._reader_loop, daemon=True, name=f"stderr-{server_name}"
        )
        self._thread.start()

    def _reader_loop(self) -> None:
        """Read lines from the pipe and log them."""
        try:
            with os.fdopen(self._read_fd, "r", errors="replace") as f:
                for line in f:
                    stripped = line.rstrip()
                    if stripped:
                        logger.warning(
                            "[%s stderr] %s", self._server_name, stripped[:200]
                        )
        except Exception:
            pass  # Pipe closed — subprocess exited.

    def fileno(self) -> int:
        """Return the write end of the pipe for subprocess stderr."""
        return self._write_fd

    def writable(self) -> bool:
        return True

    def write(self, b: bytes | bytearray) -> int:
        """Write bytes to the pipe (used if called directly)."""
        return os.write(self._write_fd, b)

    def close(self) -> None:
        """Close the write end of the pipe."""
        try:
            os.close(self._write_fd)
        except OSError:
            pass  # Already closed.
        super().close()
