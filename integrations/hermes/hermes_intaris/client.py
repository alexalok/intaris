"""HTTP client for the Intaris REST API.

Provides typed wrappers around urllib.request with retry logic, exponential
backoff, and proper error handling.  Uses only Python stdlib — no external
HTTP library dependencies.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

# Best-effort cleanup must not park Hermes workers or grow an unbounded queue.
_expiration_pending: deque[tuple[str, Callable[[], None]]] = deque()
_expiration_lock = threading.Lock()
_expiration_workers = 0


def _deliver_expirations() -> None:
    """Drain queued reports, retiring idle workers without an enqueue/exit race."""
    global _expiration_workers
    while True:
        with _expiration_lock:
            if not _expiration_pending:
                _expiration_workers -= 1
                return
            call_id, deliver = _expiration_pending.popleft()
        try:
            deliver()
        except BaseException:
            # A detached worker cannot propagate to an invocation; keep draining.
            logger.exception(
                "[intaris] Approval expiration not confirmed for %s", call_id
            )


def _queue_expiration(call_id: str, deliver: Callable[[], None]) -> None:
    """Queue normal parallel batches while bounding memory and HTTP concurrency."""
    global _expiration_workers
    with _expiration_lock:
        if len(_expiration_pending) >= 128:
            logger.warning(
                "[intaris] Approval expiration not confirmed for %s: cleanup queue capacity exhausted",
                call_id,
            )
            return
        _expiration_pending.append((call_id, deliver))
        if _expiration_workers >= 4:
            return
        _expiration_workers += 1
        try:
            threading.Thread(
                target=_deliver_expirations, name="intaris-expire", daemon=True
            ).start()
        except Exception:
            _expiration_workers -= 1
            if not _expiration_workers:
                _expiration_pending.pop()
                logger.exception(
                    "[intaris] Approval expiration not confirmed for %s: worker could not start",
                    call_id,
                )
            else:
                logger.exception(
                    "[intaris] Could not start extra expiration worker; report remains queued"
                )


def _reject_json_constant(value: str) -> None:
    """Reject non-JSON numeric constants accepted by the stdlib decoder."""
    raise ValueError(f"Invalid JSON constant: {value}")


class ApiResult:
    """Result of an API call."""

    __slots__ = ("data", "error", "status", "protocol_error")

    def __init__(
        self,
        data: dict[str, Any] | None = None,
        error: str | None = None,
        status: int | None = None,
        protocol_error: bool = False,
    ):
        self.data = data
        self.error = error
        self.status = status
        self.protocol_error = protocol_error


class IntarisClient:
    """HTTP client for the Intaris REST API."""

    def __init__(
        self,
        url: str,
        api_key: str,
        user_id: str = "",
        agent_id: str = "",
    ):
        self._base_url = url.rstrip("/")
        self._api_key = api_key
        self._user_id = user_id
        self._agent_id = agent_id

    # -- Low-level API -------------------------------------------------------

    def call_api(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | list[Any] | None = None,
        timeout_s: float = 5.0,
        extra_headers: dict[str, str] | None = None,
        agent_id: str | None = None,
    ) -> ApiResult:
        """Make an HTTP request to the Intaris API."""
        url = f"{self._base_url}{path}"
        headers: dict[str, str] = {}
        if extra_headers:
            headers.update(extra_headers)

        aid = agent_id or self._agent_id
        if aid:
            headers["X-Agent-Id"] = aid
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if self._user_id:
            headers["X-User-Id"] = self._user_id

        body: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read()
                try:
                    data = json.loads(
                        raw.decode("utf-8"), parse_constant=_reject_json_constant
                    )
                except (ValueError, RecursionError):
                    # Invalid JSON/UTF-8 is a protocol failure, not an outage.
                    # Preserve that distinction for retry and fail-open callers.
                    return ApiResult(
                        error="Invalid API response: expected a JSON object",
                        status=resp.status,
                        protocol_error=True,
                    )
                if not isinstance(data, dict):
                    return ApiResult(
                        error="Invalid API response: expected a JSON object",
                        status=resp.status,
                        protocol_error=True,
                    )
                return ApiResult(data=data, status=resp.status)
        except urllib.error.HTTPError as exc:
            raw = ""
            try:
                raw = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            detail = f"HTTP {exc.code}"
            try:
                parsed = json.loads(raw)
                detail = str(parsed.get("detail") or parsed.get("error") or detail)
            except Exception:
                if raw:
                    detail = raw[:200]
            logger.warning("API %s %s returned %s: %s", method, path, exc.code, detail)
            return ApiResult(error=detail, status=exc.code)
        except Exception as exc:
            logger.warning("API %s %s failed: %s", method, path, exc)
            return ApiResult(error=str(exc))

    def call_api_with_retry(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | list[Any] | None = None,
        timeout_s: float = 30.0,
        max_retries: int = 3,
        agent_id: str | None = None,
    ) -> ApiResult:
        """Call API with retries and exponential backoff.

        Retries on network errors and 5xx responses. Does not retry 4xx
        or invalid protocol responses.
        """
        backoff = [1.0, 2.0, 4.0]
        last: ApiResult = ApiResult(error="no attempts")

        for attempt in range(max_retries + 1):
            last = self.call_api(method, path, payload, timeout_s, agent_id=agent_id)

            # Success
            if last.data is not None:
                return last

            # Invalid replies and 4xx client errors are not transient outages.
            if last.protocol_error or (
                last.status is not None and 400 <= last.status < 500
            ):
                return last

            # 5xx or network error — retry with backoff (unless last attempt)
            if attempt < max_retries:
                delay = backoff[min(attempt, len(backoff) - 1)]
                logger.warning(
                    "API %s %s failed (attempt %d/%d), retrying in %.0fs",
                    method,
                    path,
                    attempt + 1,
                    max_retries + 1,
                    delay,
                )
                time.sleep(delay)

        return last

    # -- High-level API ------------------------------------------------------

    def create_intention(
        self,
        session_id: str,
        intention: str,
        details: dict[str, Any],
        policy: dict[str, Any] | None = None,
        parent_session_id: str | None = None,
        agent_id: str | None = None,
    ) -> ApiResult:
        body: dict[str, Any] = {
            "session_id": session_id,
            "intention": intention,
            "details": details,
        }
        if policy:
            body["policy"] = policy
        if parent_session_id:
            body["parent_session_id"] = parent_session_id
        return self.call_api_with_retry(
            "POST",
            "/api/v1/intention",
            body,
            timeout_s=5.0,
            max_retries=2,
            agent_id=agent_id,
        )

    def evaluate(
        self,
        session_id: str,
        tool: str,
        args: dict[str, Any],
        intention_pending: bool = False,
        agent_id: str | None = None,
    ) -> ApiResult:
        body: dict[str, Any] = {
            "session_id": session_id,
            "tool": tool,
            "args": args,
        }
        if intention_pending:
            body["intention_pending"] = True
        return self.call_api(
            "POST",
            "/api/v1/evaluate",
            body,
            timeout_s=60.0,
            agent_id=agent_id,
        )

    def update_status(
        self,
        session_id: str,
        status: str,
        agent_id: str | None = None,
        *,
        timeout_s: float = 2.0,
    ) -> ApiResult:
        return self.call_api(
            "PATCH",
            f"/api/v1/session/{urllib.parse.quote(session_id, safe='')}/status",
            {"status": status},
            timeout_s=timeout_s,
            agent_id=agent_id,
        )

    def update_session(
        self,
        session_id: str,
        intention: str,
        details: dict[str, Any],
        agent_id: str | None = None,
    ) -> ApiResult:
        return self.call_api(
            "PATCH",
            f"/api/v1/session/{urllib.parse.quote(session_id, safe='')}",
            {"intention": intention, "details": details},
            timeout_s=2.0,
            agent_id=agent_id,
        )

    def get_session(self, session_id: str, agent_id: str | None = None) -> ApiResult:
        return self.call_api(
            "GET",
            f"/api/v1/session/{urllib.parse.quote(session_id, safe='')}",
            timeout_s=5.0,
            agent_id=agent_id,
        )

    def get_audit(self, call_id: str, agent_id: str | None = None) -> ApiResult:
        return self.call_api(
            "GET",
            f"/api/v1/audit/{urllib.parse.quote(call_id, safe='')}",
            timeout_s=5.0,
            agent_id=agent_id,
        )

    def report_expiration(self, call_id: str, session_id: str, reason: str) -> None:
        """Best-effort retirement of an undispatched native escalation.

        Capture this client and identity, even across profile unload/replacement.
        Up to 128 reports wait behind four daemon workers. Each delivery gets
        three attempts with a two-second socket timeout. No delivery outcome
        authorizes execution; queued work is not durable across process exit.
        """

        def deliver() -> None:
            try:
                path = f"/api/v1/audit/{urllib.parse.quote(call_id, safe='')}/expire"
                body = {"session_id": session_id, "reason": reason}
                result = ApiResult(error="no attempts")
                for attempt in range(3):
                    if attempt:
                        threading.Event().wait(0.25 * attempt)
                    result = self.call_api("POST", path, body, timeout_s=2.0)
                    if result.data is not None:
                        data = result.data
                        expired_at = data.get("expired_at")
                        if (
                            data.get("call_id") == call_id
                            and data.get("session_id") == session_id
                            and isinstance(expired_at, str)
                            and expired_at.strip()
                            and data.get("expiration_reason")
                            in ("timeout", "cancelled", "abandoned")
                        ):
                            return
                        result = ApiResult(
                            error="invalid expiration acknowledgment",
                            protocol_error=True,
                        )
                    if result.status == 404:
                        logger.warning(
                            "[intaris] Approval expiration not confirmed for %s: HTTP 404; "
                            "server compatibility limitation (endpoint unsupported or audit unavailable)",
                            call_id,
                        )
                        return
                    if result.protocol_error or (
                        result.status is not None and 400 <= result.status < 500
                    ):
                        break
                logger.warning(
                    "[intaris] Approval expiration not confirmed for %s: %s",
                    call_id,
                    result.error or "server unreachable",
                )
            except Exception:
                logger.exception(
                    "[intaris] Approval expiration not confirmed for %s", call_id
                )

        _queue_expiration(call_id, deliver)

    def submit_agent_summary(
        self,
        session_id: str,
        summary: str,
        agent_id: str | None = None,
        *,
        timeout_s: float = 2.0,
    ) -> ApiResult:
        return self.call_api(
            "POST",
            f"/api/v1/session/{urllib.parse.quote(session_id, safe='')}/agent-summary",
            {"summary": summary},
            timeout_s=timeout_s,
            agent_id=agent_id,
        )

    def submit_checkpoint(
        self, session_id: str, content: str, agent_id: str | None = None
    ) -> ApiResult:
        return self.call_api(
            "POST",
            "/api/v1/checkpoint",
            {"session_id": session_id, "content": content},
            timeout_s=2.0,
            agent_id=agent_id,
        )

    def submit_reasoning(
        self,
        session_id: str,
        content: str,
        agent_id: str | None = None,
        context: str | None = None,
        from_events: bool = False,
    ) -> ApiResult:
        body: dict[str, Any] = {"session_id": session_id, "content": content}
        if context:
            body["context"] = context
        if from_events:
            body["from_events"] = True
        return self.call_api(
            "POST", "/api/v1/reasoning", body, timeout_s=2.0, agent_id=agent_id
        )

    def append_events(
        self,
        session_id: str,
        events: list[dict[str, Any]],
        agent_id: str | None = None,
        *,
        timeout_s: float = 5.0,
    ) -> ApiResult:
        return self.call_api(
            "POST",
            f"/api/v1/session/{urllib.parse.quote(session_id, safe='')}/events",
            events,
            timeout_s=timeout_s,
            extra_headers={"X-Intaris-Source": "hermes"},
            agent_id=agent_id,
        )

    # -- MCP API -------------------------------------------------------------

    def list_mcp_tools(self, agent_id: str | None = None) -> list[dict[str, Any]]:
        """Fetch available MCP tools.  Returns empty list on failure."""
        result = self.call_api(
            "GET", "/api/v1/mcp/tools", timeout_s=10.0, agent_id=agent_id
        )
        if not result.data:
            return []
        tools = result.data.get("tools")
        if not isinstance(tools, list):
            logger.warning("MCP tools response missing 'tools' array")
            return []
        return tools

    def call_mcp_tool(
        self,
        session_id: str,
        server: str,
        tool: str,
        args: dict[str, Any],
        agent_id: str | None = None,
    ) -> ApiResult:
        """Proxy a tool call to an MCP server via Intaris."""
        return self.call_api_with_retry(
            "POST",
            "/api/v1/mcp/call",
            {
                "session_id": session_id,
                "server": server,
                "tool": tool,
                "arguments": args,
            },
            timeout_s=60.0,
            max_retries=2,
            agent_id=agent_id,
        )
