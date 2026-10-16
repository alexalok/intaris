"""Hermes Agent plugin for Intaris guardrails.

Intercepts every tool call and evaluates it through Intaris's safety
pipeline before allowing execution.  Tool calls that are denied or
escalated are blocked with an error message returned to the LLM.

The plugin works by **wrapping** every tool handler in the Hermes tool
registry with an evaluation guard.  Since plugins load after built-in
tools, we capture the original handler and re-register with a wrapper
that calls ``POST /api/v1/evaluate`` before dispatching.

Flow:
  1. on_session_start: Creates an Intaris session via POST /api/v1/intention
  2. pre_llm_call: Forwards user message as reasoning context, returns
     context injection for behavioral alerts
  3. Tool wrapper: Evaluates every tool call via POST /api/v1/evaluate
     - approve: calls original handler, returns result
     - deny: returns {"error": "BLOCKED by Intaris: ..."} to the LLM
     - escalate: polls for user decision, blocks until resolved
  4. pre_tool_call: Records tool call events (recording only)
  5. post_tool_call: Records tool results, sends periodic checkpoints
  6. post_llm_call: Captures assistant response for reasoning context
  7. on_session_end: Signals session completion to Intaris

Configuration via environment variables:
  INTARIS_URL                      - Intaris server URL (default: http://localhost:8060)
  INTARIS_API_KEY                  - API key for authentication (required)
  INTARIS_USER_ID                  - User ID (optional if API key maps to user)
  INTARIS_FAIL_OPEN                - Allow tool calls if Intaris is unreachable (default: false)
  INTARIS_ALLOW_PATHS              - Comma-separated parent directories for policy allow_paths
  INTARIS_ESCALATION_TIMEOUT       - Max seconds to wait for escalation (default: 0 = no timeout)
  INTARIS_CHECKPOINT_INTERVAL      - Evaluate calls between checkpoints (default: 25, 0 = disabled)
  INTARIS_SESSION_RECORDING        - Enable session recording (default: false)
  INTARIS_MCP_TOOLS                - Enable MCP tool proxy (default: true)
  INTARIS_MCP_TOOLS_CACHE_TTL_S    - MCP tool list cache TTL in seconds (default: 900 = 15 min)
  INTARIS_RECORDING_FLUSH_SIZE     - Events per recording batch (default: 50)
  INTARIS_RECORDING_FLUSH_INTERVAL - Recording flush interval in seconds (default: 10)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from .client import ApiResult, IntarisClient

logger = logging.getLogger(__name__)

# ============================================================================
# Constants
# ============================================================================

MAX_SESSIONS = 100
MAX_RECENT_TOOLS = 10

# ============================================================================
# Configuration
# ============================================================================


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


@dataclass
class Config:
    url: str = ""
    api_key: str = ""
    user_id: str = ""
    fail_open: bool = False
    allow_paths: str = ""
    escalation_timeout_s: float = 0.0
    checkpoint_interval: int = 25
    recording: bool = False
    recording_flush_size: int = 50
    recording_flush_interval_s: float = 10.0
    mcp_tools: bool = True
    mcp_tools_cache_ttl_s: float = 900.0


def _resolve_config() -> Config:
    return Config(
        url=os.environ.get("INTARIS_URL", "http://localhost:8060"),
        api_key=os.environ.get("INTARIS_API_KEY", ""),
        user_id=os.environ.get("INTARIS_USER_ID", ""),
        fail_open=_env_bool("INTARIS_FAIL_OPEN"),
        allow_paths=os.environ.get("INTARIS_ALLOW_PATHS", ""),
        escalation_timeout_s=_env_float("INTARIS_ESCALATION_TIMEOUT", 0.0),
        checkpoint_interval=_env_int("INTARIS_CHECKPOINT_INTERVAL", 25),
        recording=_env_bool("INTARIS_SESSION_RECORDING"),
        recording_flush_size=_env_int("INTARIS_RECORDING_FLUSH_SIZE", 50),
        recording_flush_interval_s=_env_float("INTARIS_RECORDING_FLUSH_INTERVAL", 10.0),
        mcp_tools=_env_bool("INTARIS_MCP_TOOLS", True),
        mcp_tools_cache_ttl_s=_env_float("INTARIS_MCP_TOOLS_CACHE_TTL_S", 900.0),
    )


# ============================================================================
# Session State
# ============================================================================


@dataclass
class SessionState:
    intaris_session_id: str | None = None
    session_created: bool = False
    call_count: int = 0
    approved_count: int = 0
    denied_count: int = 0
    escalated_count: int = 0
    recent_tools: list[str] = field(default_factory=list)
    last_error: str | None = None
    intention_pending: bool = False
    intention_updated: bool = False
    is_idle: bool = False
    recording_buffer: list[dict[str, Any]] = field(default_factory=list)
    last_assistant_text: str = ""
    pending_tool_results: list[dict[str, str]] = field(default_factory=list)
    # Lock for session creation dedup
    _creating: bool = False


# ============================================================================
# Module-level shared state
# ============================================================================

_sessions: dict[str, SessionState] = {}
_sessions_lock = threading.Lock()
_mcp_tool_cache: list[dict[str, Any]] | None = None
_mcp_tool_cache_at: float = 0.0
_mcp_tool_cache_lock = threading.Lock()
_flush_timer: threading.Timer | None = None
_cfg: Config | None = None
_client: IntarisClient | None = None


def _get_or_create_state(session_id: str) -> SessionState:
    with _sessions_lock:
        state = _sessions.get(session_id)
        if state is None:
            state = SessionState()
            _sessions[session_id] = state
            # Evict oldest entries if over limit
            if len(_sessions) > MAX_SESSIONS:
                excess = len(_sessions) - MAX_SESSIONS
                keys = list(_sessions.keys())[:excess]
                for k in keys:
                    _sessions.pop(k, None)
        return state


def _resolve_invocation_session(session_id: Any) -> SessionState:
    """Resolve only the authoritative Hermes invocation session identity.

    Hermes passes session_id and task_id separately to handlers and hooks.
    task_id identifies tool resources, not the session used by lifecycle hooks.
    Missing or unknown identity must never borrow another session, even when
    fail-open is enabled. Idle state and insertion order are not identity.
    """
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("Missing or invalid Hermes session_id.")
    with _sessions_lock:
        state = _sessions.get(session_id)
        if state is None or not state.intaris_session_id:
            raise ValueError("No active Intaris session for this Hermes session_id.")
        return state


def _args_fingerprint(args: dict[str, Any] | None) -> str:
    """Return a stable string fingerprint for a tool args payload."""
    try:
        return json.dumps(
            args or {}, sort_keys=True, separators=(",", ":"), default=str
        )
    except Exception:
        return repr(args or {})


def _queue_pending_tool_result(
    state: SessionState, tool_name: str, args: dict[str, Any] | None, call_id: str
) -> None:
    """Remember the audit call id for the next executed post_tool_call hook."""
    if not call_id:
        return
    state.pending_tool_results.append(
        {
            "tool": tool_name,
            "args": _args_fingerprint(args),
            "call_id": str(call_id),
        }
    )


# ============================================================================
# Helpers
# ============================================================================


def _build_policy(allow_paths: str) -> dict[str, Any]:
    """Build session policy from allow_paths config."""
    default_paths = ["/tmp/*", "/var/tmp/*"]
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        default_paths.append(f"{tmpdir.rstrip('/')}/*")

    home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or ""
    user_paths: list[str] = []
    if allow_paths:
        for p in allow_paths.split(","):
            p = p.strip()
            if not p:
                continue
            if p.startswith("~/") or p == "~":
                p = home + p[1:]
            if not p.endswith("*"):
                p = p + "/*" if not p.endswith("/") else p + "*"
            user_paths.append(p)

    return {"allow_paths": default_paths + user_paths}


def _build_intention(platform: str = "", model: str = "") -> str:
    parts = ["Hermes Agent"]
    if platform:
        parts.append(f"({platform})")
    parts.append("session")
    cwd = os.getcwd()
    if cwd:
        parts.append(f"in {cwd}")
    return " ".join(parts)


def _build_details(
    platform: str = "", model: str = "", session_id: str = ""
) -> dict[str, Any]:
    details: dict[str, Any] = {"source": "hermes"}
    cwd = os.getcwd()
    if cwd:
        details["working_directory"] = cwd
    if platform:
        details["platform"] = platform
    if model:
        details["model"] = model
    if session_id:
        details["session_key"] = session_id
    return details


def _build_checkpoint_content(state: SessionState) -> str:
    assert _cfg is not None
    interval = (
        state.call_count // _cfg.checkpoint_interval
        if _cfg.checkpoint_interval > 0
        else 0
    )
    tools = ", ".join(state.recent_tools) or "none"
    return (
        f"Checkpoint #{interval}: {state.call_count} calls "
        f"({state.approved_count} approved, {state.denied_count} denied, "
        f"{state.escalated_count} escalated). Recent tools: {tools}"
    )


def _build_agent_summary(state: SessionState) -> str:
    return (
        f"Hermes session completed. {state.call_count} tool calls "
        f"({state.approved_count} approved, {state.denied_count} denied, "
        f"{state.escalated_count} escalated). "
        f"Working directory: {os.getcwd() or 'unknown'}"
    )


# ============================================================================
# Session Management
# ============================================================================


def _ensure_session(
    task_id: str,
    state: SessionState,
    platform: str = "",
    model: str = "",
) -> str | None:
    """Ensure an Intaris session exists.  Returns the session ID or None."""
    assert _cfg is not None and _client is not None

    if state.intaris_session_id:
        return state.intaris_session_id

    # Simple dedup — only one creation at a time per state
    if state._creating:
        return state.intaris_session_id

    state._creating = True
    try:
        intaris_id = f"hm-{uuid.uuid4()}"
        intention = _build_intention(platform, model)
        details = _build_details(platform, model, task_id)
        policy = _build_policy(_cfg.allow_paths)

        result = _client.create_intention(intaris_id, intention, details, policy)

        if result.data:
            state.intaris_session_id = intaris_id
            state.session_created = True
            logger.info("[intaris] Session created: %s", intaris_id)
        elif result.status == 409:
            # Session already exists — reuse
            state.intaris_session_id = intaris_id
            logger.info("[intaris] Session already exists, reusing: %s", intaris_id)
            _client.update_status(intaris_id, "active")
        elif result.status is not None and 400 <= result.status < 500:
            state.last_error = result.error or f"HTTP {result.status}"
            return None
        else:
            # Server error or network issue — try using it anyway
            state.intaris_session_id = intaris_id

        return state.intaris_session_id
    finally:
        state._creating = False


# ============================================================================
# Recording
# ============================================================================


def _record_event(task_id: str, event: dict[str, Any]) -> None:
    """Buffer a recording event."""
    assert _cfg is not None
    if not _cfg.recording:
        return
    state = _sessions.get(task_id)
    if not state or not state.intaris_session_id:
        return
    state.recording_buffer.append(event)
    if len(state.recording_buffer) >= _cfg.recording_flush_size:
        _flush_recording_buffer(task_id)


def _flush_recording_buffer(task_id: str) -> None:
    """Flush buffered recording events to Intaris."""
    assert _client is not None
    state = _sessions.get(task_id)
    if not state or not state.intaris_session_id:
        return
    if not state.recording_buffer:
        return
    events = state.recording_buffer[:]
    state.recording_buffer.clear()
    try:
        _client.append_events(state.intaris_session_id, events)
    except Exception as exc:
        logger.warning(
            "[intaris] Recording flush failed for %s: %s (%d events)",
            state.intaris_session_id,
            exc,
            len(events),
        )


def _periodic_flush() -> None:
    """Flush all recording buffers periodically."""
    assert _cfg is not None
    for task_id in list(_sessions.keys()):
        try:
            _flush_recording_buffer(task_id)
        except Exception:
            pass
    # Re-schedule
    global _flush_timer
    if _cfg.recording:
        _flush_timer = threading.Timer(_cfg.recording_flush_interval_s, _periodic_flush)
        _flush_timer.daemon = True
        _flush_timer.start()


# ============================================================================
# Completion
# ============================================================================


def _signal_completion(task_id: str, state: SessionState) -> None:
    """Signal session completion to Intaris."""
    assert _client is not None
    if not state.intaris_session_id:
        return

    _flush_recording_buffer(task_id)

    sid = state.intaris_session_id
    try:
        _client.update_status(sid, "completed")
    except Exception:
        pass
    try:
        _client.submit_agent_summary(sid, _build_agent_summary(state))
    except Exception:
        pass


def _send_checkpoint(state: SessionState) -> None:
    """Send a periodic checkpoint if interval reached."""
    assert _cfg is not None and _client is not None
    if _cfg.checkpoint_interval <= 0:
        return
    if state.call_count % _cfg.checkpoint_interval != 0:
        return
    if not state.intaris_session_id:
        return
    try:
        _client.submit_checkpoint(
            state.intaris_session_id, _build_checkpoint_content(state)
        )
    except Exception:
        pass


# ============================================================================
# MCP Tool Proxy
# ============================================================================


def _refresh_mcp_tool_cache() -> list[dict[str, Any]]:
    """Refresh the MCP tool cache from Intaris."""
    global _mcp_tool_cache, _mcp_tool_cache_at
    assert _client is not None

    with _mcp_tool_cache_lock:
        try:
            tools = _client.list_mcp_tools()
            _mcp_tool_cache = tools
            _mcp_tool_cache_at = time.monotonic()
            if tools:
                servers = {t.get("server", "?") for t in tools}
                logger.info(
                    "[intaris] MCP tool cache refreshed: %d tools from %d server(s)",
                    len(tools),
                    len(servers),
                )
            return tools
        except Exception as exc:
            logger.warning("[intaris] MCP tool cache refresh failed: %s", exc)
            return _mcp_tool_cache or []


def _is_mcp_cache_stale() -> bool:
    assert _cfg is not None
    if _mcp_tool_cache is None:
        return True
    return (time.monotonic() - _mcp_tool_cache_at) > _cfg.mcp_tools_cache_ttl_s


def _get_mcp_tool_names() -> set[str]:
    """Return the set of registered MCP tool names (server_tool format)."""
    if not _mcp_tool_cache:
        return set()
    return {f"{t['server']}_{t['name']}" for t in _mcp_tool_cache}


# ============================================================================
# Escalation Polling
# ============================================================================


def _decision_response_error(result: ApiResult) -> str | None:
    """Reject invalid decision replies without conflating them with outages."""
    if result.protocol_error:
        return result.error or "Invalid API response"
    if result.data is None and (result.status is None or result.status >= 400):
        return None  # Transport/HTTP failure, handled by the caller.
    if not isinstance(result.data, dict):
        return "Invalid API response: expected a JSON object"
    decision = result.data.get("decision")
    if not isinstance(decision, str) or decision not in ("approve", "deny", "escalate"):
        return (
            "Invalid API response: expected decision 'approve', 'deny', or 'escalate'"
        )
    if decision == "escalate":
        call_id = result.data.get("call_id")
        if not isinstance(call_id, str) or not call_id.strip():
            return "Invalid API response: escalation requires a non-empty call_id"
    return None


def _poll_escalation(call_id: str, tool_name: str) -> str:
    """Return 'approve', 'deny', 'timeout', or 'invalid_response'."""
    assert _cfg is not None and _client is not None

    backoff = [2.0, 4.0, 8.0, 16.0, 30.0]
    start = time.monotonic()
    attempt = 0
    last_reminder = start

    while True:
        # Check timeout
        elapsed = time.monotonic() - start
        if _cfg.escalation_timeout_s > 0 and elapsed > _cfg.escalation_timeout_s:
            return "timeout"

        # Periodic reminder every 60s
        now = time.monotonic()
        if now - last_reminder >= 60.0:
            logger.warning(
                "[intaris] Still waiting for escalation approval for %s (%s)... %.0fs elapsed",
                tool_name,
                call_id,
                elapsed,
            )
            last_reminder = now

        # Wait with exponential backoff
        delay = backoff[min(attempt, len(backoff) - 1)]
        time.sleep(delay)
        attempt += 1

        # Check resolution
        result = _client.get_audit(call_id)
        if result.protocol_error:
            return "invalid_response"
        if result.data is None:
            continue  # Server unreachable — keep polling
        if not isinstance(result.data, dict) or "user_decision" not in result.data:
            return "invalid_response"

        user_decision = result.data.get("user_decision")
        if user_decision is None:
            continue  # A pending audit record is not an approval.
        if user_decision == "approve":
            logger.info("[intaris] Escalation approved: %s (%s)", tool_name, call_id)
            return "approve"
        if user_decision == "deny":
            user_note = result.data.get("user_note", "")
            note_suffix = f" -- {user_note}" if user_note else ""
            logger.info(
                "[intaris] Escalation denied: %s (%s)%s",
                tool_name,
                call_id,
                note_suffix,
            )
            return "deny"
        return "invalid_response"


def _poll_session_status(session_id: str, tool_name: str) -> str:
    """Poll for session reactivation.  Returns 'active', 'terminated', or 'timeout'."""
    assert _cfg is not None and _client is not None

    backoff = [2.0, 4.0, 8.0, 16.0, 30.0]
    start = time.monotonic()
    attempt = 0
    last_reminder = start

    while True:
        elapsed = time.monotonic() - start
        if _cfg.escalation_timeout_s > 0 and elapsed > _cfg.escalation_timeout_s:
            return "timeout"

        now = time.monotonic()
        if now - last_reminder >= 60.0:
            logger.warning(
                "[intaris] Still waiting for session approval... %.0fs elapsed",
                elapsed,
            )
            last_reminder = now

        delay = backoff[min(attempt, len(backoff) - 1)]
        time.sleep(delay)
        attempt += 1

        result = _client.get_session(session_id)
        if not result.data:
            continue

        status = result.data.get("status")
        if status == "active":
            return "active"
        if status == "terminated":
            return "terminated"
        # Still suspended — continue polling


# ============================================================================
# Tool Wrapper Factory
# ============================================================================


def _make_guarded_handler(
    original_handler: Callable,
    tool_name: str,
    toolset: str,
    is_async: bool,
) -> Callable:
    """Create a wrapper handler that evaluates via Intaris before dispatching."""

    def guarded_handler(args: dict, **kwargs: Any) -> str:
        assert _cfg is not None and _client is not None

        session_id = kwargs.get("session_id")
        try:
            state = _resolve_invocation_session(session_id)
        except ValueError as exc:
            return json.dumps(
                {"error": f"[intaris] {exc} Cannot evaluate {tool_name}."}
            )

        # Evaluate the tool call
        intention_pending = state.intention_pending
        result = _client.evaluate(
            state.intaris_session_id,
            tool_name,
            args,
            intention_pending=intention_pending,
        )

        # Clear intention_pending after first evaluate
        if intention_pending:
            state.intention_pending = False

        response_error = _decision_response_error(result)
        if response_error:
            return json.dumps({"error": f"[intaris] {tool_name}: {response_error}"})

        if not result.data:
            # Distinguish config errors (4xx) from transient failures
            if result.status is not None and 400 <= result.status < 500:
                return json.dumps(
                    {
                        "error": f"[intaris] Evaluation rejected for {tool_name}: {result.error}"
                    }
                )
            if _cfg.fail_open:
                logger.warning(
                    "[intaris] Evaluate failed for %s — allowing (fail-open)", tool_name
                )
                return original_handler(args, **kwargs)
            return json.dumps(
                {
                    "error": (
                        f"[intaris] Evaluation failed for {tool_name}: "
                        f"{result.error or 'server unreachable'} (INTARIS_FAIL_OPEN=false)"
                    )
                }
            )

        data = result.data
        decision = data["decision"]
        reasoning = data.get("reasoning", "")
        call_id = data.get("call_id", "")
        risk = data.get("risk", "")
        path = data.get("path", "")
        latency_ms = data.get("latency_ms", 0)
        session_status = data.get("session_status")
        status_reason = data.get("status_reason", "")

        # Track statistics
        state.call_count += 1
        if decision == "approve":
            state.approved_count += 1
        elif decision == "deny":
            state.denied_count += 1
        elif decision == "escalate":
            state.escalated_count += 1

        state.recent_tools = (state.recent_tools + [tool_name])[-MAX_RECENT_TOOLS:]

        logger.info(
            "[intaris] %s: %s (%s, %dms, risk=%s)",
            tool_name,
            decision,
            path,
            latency_ms,
            risk,
        )

        # Send periodic checkpoint
        _send_checkpoint(state)

        # Update intention after gathering enough context
        if not state.intention_updated and state.call_count >= 3:
            state.intention_updated = True
            try:
                _client.update_session(
                    state.intaris_session_id,
                    _build_intention(),
                    _build_details(session_id=session_id),
                )
            except Exception:
                pass

        # -- Handle DENY -------------------------------------------------------
        if decision == "deny":
            # Session suspended — wait for user action
            if session_status == "suspended":
                logger.warning(
                    "[intaris] Session suspended: %s. Waiting for approval...",
                    status_reason,
                )
                poll_result = _poll_session_status(state.intaris_session_id, tool_name)
                if poll_result == "active":
                    # Re-evaluate after reactivation
                    logger.info(
                        "[intaris] Session reactivated — re-evaluating %s",
                        tool_name,
                    )
                    re_result = _client.evaluate(
                        state.intaris_session_id, tool_name, args
                    )
                    response_error = _decision_response_error(re_result)
                    if response_error:
                        return json.dumps(
                            {"error": f"[intaris] {tool_name}: {response_error}"}
                        )
                    if re_result.data and re_result.data.get("decision") == "approve":
                        _queue_pending_tool_result(
                            state,
                            tool_name,
                            args,
                            str(re_result.data.get("call_id") or ""),
                        )
                        return original_handler(args, **kwargs)
                    if re_result.data and re_result.data.get("decision") == "escalate":
                        re_call_id = str(re_result.data.get("call_id") or "")
                        re_reason = str(
                            re_result.data.get(
                                "reasoning", "Tool call requires human approval"
                            )
                        )
                        poll_result = _poll_escalation(re_call_id, tool_name)
                        if poll_result == "invalid_response":
                            return json.dumps(
                                {
                                    "error": f"[intaris] Invalid escalation response ({re_call_id})"
                                }
                            )
                        if poll_result == "approve":
                            _queue_pending_tool_result(
                                state, tool_name, args, re_call_id
                            )
                            return original_handler(args, **kwargs)
                        if poll_result == "deny":
                            return json.dumps(
                                {
                                    "error": f"[intaris] DENIED by user ({re_call_id}): {re_reason}"
                                }
                            )
                        return json.dumps(
                            {
                                "error": (
                                    f"[intaris] ESCALATION TIMEOUT ({re_call_id}): {re_reason}\n"
                                    f"No response within {_cfg.escalation_timeout_s:.0f}s. "
                                    f"Approve or deny in the Intaris UI."
                                )
                            }
                        )
                    re_reason = (
                        re_result.data.get("reasoning", "denied after reactivation")
                        if re_result.data
                        else "re-evaluation failed"
                    )
                    return json.dumps({"error": f"[intaris] DENIED: {re_reason}"})
                if poll_result == "terminated":
                    return json.dumps(
                        {
                            "error": f"[intaris] Session terminated: {status_reason or 'terminated by user'}"
                        }
                    )
                # Timeout
                return json.dumps(
                    {
                        "error": (
                            f"[intaris] SESSION SUSPENSION TIMEOUT: {status_reason}\n"
                            f"No response within {_cfg.escalation_timeout_s:.0f}s."
                        )
                    }
                )

            # Session terminated
            if session_status == "terminated":
                return json.dumps(
                    {
                        "error": f"[intaris] Session terminated: {status_reason or 'terminated by user'}"
                    }
                )

            # Regular deny
            return json.dumps(
                {
                    "error": f"[intaris] DENIED: {reasoning or 'Tool call denied by safety evaluation'}"
                }
            )

        # -- Handle ESCALATE ---------------------------------------------------
        if decision == "escalate":
            logger.warning(
                "[intaris] ESCALATED %s (%s): %s. Waiting for approval...",
                tool_name,
                call_id,
                reasoning,
            )
            poll_result = _poll_escalation(call_id, tool_name)
            if poll_result == "invalid_response":
                return json.dumps(
                    {"error": f"[intaris] Invalid escalation response ({call_id})"}
                )
            if poll_result == "approve":
                _queue_pending_tool_result(state, tool_name, args, call_id)
                return original_handler(args, **kwargs)
            if poll_result == "deny":
                return json.dumps(
                    {"error": f"[intaris] DENIED by user ({call_id}): {reasoning}"}
                )
            # Timeout
            return json.dumps(
                {
                    "error": (
                        f"[intaris] ESCALATION TIMEOUT ({call_id}): {reasoning}\n"
                        f"No response within {_cfg.escalation_timeout_s:.0f}s. "
                        f"Approve or deny in the Intaris UI."
                    )
                }
            )

        # -- APPROVE -----------------------------------------------------------
        if decision == "approve":
            _queue_pending_tool_result(state, tool_name, args, call_id)
            return original_handler(args, **kwargs)
        return json.dumps({"error": "[intaris] Invalid evaluation response"})

    return guarded_handler


# ============================================================================
# MCP Tool Registration
# ============================================================================


def _register_mcp_tools(ctx: Any) -> None:
    """Register MCP tools from Intaris as Hermes agent tools."""
    assert _cfg is not None and _client is not None

    tools = _refresh_mcp_tool_cache()
    if not tools:
        return

    for mcp_tool in tools:
        server = mcp_tool.get("server", "")
        name = mcp_tool.get("name", "")
        description = mcp_tool.get("description", name)
        input_schema = mcp_tool.get("inputSchema", {"type": "object", "properties": {}})
        tool_name = f"{server}_{name}"

        schema = {
            "name": tool_name,
            "description": f"[MCP: {server}] {description}",
            "parameters": input_schema,
        }

        def _make_mcp_handler(srv: str, tn: str) -> Callable:
            def mcp_handler(args: dict, **kwargs: Any) -> str:
                assert _client is not None

                try:
                    state = _resolve_invocation_session(kwargs.get("session_id"))
                except ValueError as exc:
                    return json.dumps(
                        {"error": f"[intaris] {exc} Cannot call MCP tool {srv}:{tn}."}
                    )

                result = _client.call_mcp_tool(state.intaris_session_id, srv, tn, args)

                response_error = _decision_response_error(result)
                if response_error:
                    # The server may already have executed the tool. Report the
                    # invalid reply; do not claim success or retry it here.
                    return json.dumps(
                        {"error": f"[intaris] MCP tool call: {response_error}"}
                    )

                if not result.data:
                    return json.dumps(
                        {
                            "error": f"[intaris] MCP tool call failed: {result.error or 'unknown error'}"
                        }
                    )

                data = result.data
                decision = data.get("decision")
                content = data.get("content")

                if decision == "deny":
                    reason = data.get(
                        "reasoning", "Tool call denied by safety evaluation"
                    )
                    return json.dumps({"error": f"[intaris] DENIED: {reason}"})

                if decision == "escalate":
                    call_id = data.get("call_id", "")
                    reason = data.get("reasoning", "Tool call requires human approval")
                    return json.dumps(
                        {
                            "error": (
                                f"[intaris] ESCALATED ({call_id}): {reason}\n"
                                f"Approve or deny in the Intaris UI, then retry."
                            )
                        }
                    )

                # The REST proxy normalizes MCP results to text blocks.
                if (
                    not isinstance(content, list)
                    or any(
                        not isinstance(c, dict)
                        or c.get("type") != "text"
                        or not isinstance(c.get("text"), str)
                        for c in content
                    )
                    or not isinstance(data.get("isError", False), bool)
                ):
                    return json.dumps(
                        {
                            "error": "[intaris] Invalid MCP response: malformed tool result"
                        }
                    )

                if data.get("isError"):
                    error_text = (
                        "\n".join(c.get("text", json.dumps(c)) for c in content)
                        or "MCP tool returned an error"
                    )
                    return json.dumps({"error": f"[MCP error] {error_text}"})

                # Success — return text content
                text_parts = [c.get("text", json.dumps(c)) for c in content]
                return json.dumps({"result": "\n".join(text_parts) or "(empty result)"})

            return mcp_handler

        ctx.register_tool(
            name=tool_name,
            toolset="intaris-mcp",
            schema=schema,
            handler=_make_mcp_handler(server, name),
            description=f"[MCP: {server}] {description}",
        )

    logger.info("[intaris] Registered %d MCP tools from Intaris", len(tools))


# ============================================================================
# Hook Implementations
# ============================================================================


def _on_session_start(
    session_id: str, model: str = "", platform: str = "", **kwargs: Any
) -> None:
    """on_session_start: Create Intaris session."""
    state = _get_or_create_state(session_id)
    _ensure_session(session_id, state, platform, model)

    # Refresh MCP tool cache on session start
    if _cfg and _cfg.mcp_tools and _is_mcp_cache_stale():
        try:
            _refresh_mcp_tool_cache()
        except Exception:
            pass


def _on_session_end(
    session_id: str,
    completed: bool = True,
    interrupted: bool = False,
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> None:
    """on_session_end: Signal completion or idle."""
    state = _sessions.get(session_id)
    if not state:
        return

    if completed or interrupted:
        _signal_completion(session_id, state)
        with _sessions_lock:
            _sessions.pop(session_id, None)
    else:
        # Not completed — transition to idle
        if not state.is_idle and state.intaris_session_id and _client:
            state.is_idle = True
            try:
                _client.update_status(state.intaris_session_id, "idle")
            except Exception:
                pass


def _on_pre_llm_call(
    session_id: str = "",
    user_message: str = "",
    conversation_history: Any = None,
    is_first_turn: bool = False,
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> dict[str, str] | None:
    """pre_llm_call: Forward user message as reasoning context.

    Returns ``{"context": "..."}`` to inject behavioral alerts into the
    system prompt when there are cached warnings from recent evaluations.
    """
    assert _cfg is not None and _client is not None

    state = _sessions.get(session_id)
    if not state:
        state = _get_or_create_state(session_id)
        _ensure_session(session_id, state, platform, model)

    if not state.intaris_session_id:
        return None

    # Resume from idle when user provides new input
    if state.is_idle and user_message:
        state.is_idle = False
        try:
            _client.update_status(state.intaris_session_id, "active")
        except Exception:
            pass

    # Forward user message as reasoning context
    if user_message and user_message.strip():
        clean_text = user_message.strip()

        # Consume last assistant text as context
        assistant_context = state.last_assistant_text or None
        state.last_assistant_text = ""

        if _cfg.recording:
            # Record user message event, then call /reasoning with from_events
            _record_event(
                session_id,
                {
                    "type": "message",
                    "data": {
                        "role": "user",
                        "text": clean_text,
                        "session_key": session_id,
                    },
                },
            )
            _flush_recording_buffer(session_id)
            try:
                _client.submit_reasoning(state.intaris_session_id, "", from_events=True)
            except Exception:
                pass
        else:
            try:
                _client.submit_reasoning(
                    state.intaris_session_id,
                    f"User message: {clean_text}",
                    context=assistant_context,
                )
            except Exception:
                pass

        # Signal intention update in flight
        state.intention_pending = True

    return None


def _on_pre_tool_call(
    tool_name: str = "",
    args: dict | None = None,
    task_id: str = "",
    session_id: str = "",
    **kwargs: Any,
) -> None:
    """pre_tool_call: Record tool call event (evaluation happens in wrapper)."""
    try:
        _resolve_invocation_session(session_id)
    except ValueError:
        return
    _record_event(
        session_id,
        {
            "type": "tool_call",
            "data": {
                "tool": tool_name,
                "args": args or {},
                "call_id": str(
                    kwargs.get("call_id")
                    or kwargs.get("tool_call_id")
                    or kwargs.get("toolCallId")
                    or ""
                )
                or None,
                "session_key": session_id,
            },
        },
    )


def _on_post_tool_call(
    tool_name: str = "",
    args: dict | None = None,
    result: Any = "",
    task_id: str = "",
    session_id: str = "",
    **kwargs: Any,
) -> None:
    """post_tool_call: Record tool result."""
    try:
        state = _resolve_invocation_session(session_id)
    except ValueError:
        return
    args_key = _args_fingerprint(args)
    mapped_call_id: str | None = None
    if state:
        # Oldest-match first keeps correlation stable for repeated identical calls.
        for i, candidate in enumerate(state.pending_tool_results):
            if candidate.get("tool") == tool_name and candidate.get("args") == args_key:
                mapped_call_id = candidate.get("call_id")
                del state.pending_tool_results[i]
                break
    _record_event(
        session_id,
        {
            "type": "tool_result",
            "data": {
                "tool": tool_name,
                "args": args or {},
                "call_id": mapped_call_id
                or str(
                    kwargs.get("call_id")
                    or kwargs.get("tool_call_id")
                    or kwargs.get("toolCallId")
                    or ""
                )
                or None,
                "output": result,
                "is_error": bool(
                    kwargs.get("is_error")
                    or kwargs.get("isError")
                    or kwargs.get("error")
                ),
                "isError": bool(
                    kwargs.get("is_error")
                    or kwargs.get("isError")
                    or kwargs.get("error")
                ),
                "error": kwargs.get("error"),
                "session_key": session_id,
            },
        },
    )


def _on_post_llm_call(
    session_id: str = "",
    user_message: str = "",
    assistant_response: str = "",
    conversation_history: Any = None,
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> None:
    """post_llm_call: Capture assistant response for reasoning context."""
    state = _sessions.get(session_id)
    if not state:
        return

    if assistant_response:
        state.last_assistant_text = assistant_response

        # Record assistant message
        _record_event(
            session_id,
            {
                "type": "message",
                "data": {
                    "role": "assistant",
                    "text": assistant_response,
                    "session_key": session_id,
                },
            },
        )


# ============================================================================
# Plugin Entry Point
# ============================================================================


def register(ctx: Any) -> None:
    """Hermes plugin entry point.

    Called by the Hermes plugin manager after discovery.  Registers hooks,
    wraps all existing tool handlers with Intaris evaluation guards, and
    optionally registers MCP tools.
    """
    global _cfg, _client, _flush_timer

    _cfg = _resolve_config()
    _client = IntarisClient(
        url=_cfg.url,
        api_key=_cfg.api_key,
        user_id=_cfg.user_id,
    )

    # Validation warnings
    if not _cfg.api_key:
        logger.warning(
            "[intaris] API key not configured — plugin will fail to authenticate. "
            "Set INTARIS_API_KEY."
        )
    if _cfg.fail_open:
        logger.warning(
            "[intaris] Fail-open mode enabled — tool calls will proceed unchecked "
            "if Intaris is unreachable."
        )

    logger.info(
        "[intaris] Plugin initialized (url=%s, fail_open=%s, checkpoint=%d, "
        "recording=%s, mcp_tools=%s)",
        _cfg.url,
        _cfg.fail_open,
        _cfg.checkpoint_interval,
        _cfg.recording,
        _cfg.mcp_tools,
    )

    # -- Wrap all existing tool handlers with Intaris evaluation guards --------
    try:
        from tools.registry import registry  # type: ignore[import-not-found]

        mcp_tool_names = set()
        if _cfg.mcp_tools:
            # Pre-fetch MCP tools so we know which names to skip wrapping
            # (MCP tools have their own evaluation via POST /mcp/call)
            try:
                cache = _refresh_mcp_tool_cache()
                mcp_tool_names = {f"{t['server']}_{t['name']}" for t in cache}
            except Exception:
                pass

        wrapped_count = 0
        for name in list(registry._tools.keys()):
            entry = registry._tools[name]

            # Skip MCP tools — they have their own evaluation path
            if name in mcp_tool_names:
                continue

            original_handler = entry.handler
            guarded = _make_guarded_handler(
                original_handler, name, entry.toolset, entry.is_async
            )

            # Re-register with same toolset to avoid collision warning
            registry.register(
                name=name,
                toolset=entry.toolset,
                schema=entry.schema,
                handler=guarded,
                check_fn=entry.check_fn,
                requires_env=entry.requires_env,
                is_async=False,  # Our wrapper is synchronous
                description=entry.description,
                emoji=entry.emoji,
            )
            wrapped_count += 1

        logger.info(
            "[intaris] Wrapped %d tool handlers with evaluation guards", wrapped_count
        )
    except ImportError:
        logger.warning(
            "[intaris] Could not import tools.registry — tool wrapping disabled. "
            "Tool calls will not be evaluated."
        )

    # -- Register MCP tools ---------------------------------------------------
    if _cfg.mcp_tools:
        try:
            _register_mcp_tools(ctx)
        except Exception as exc:
            logger.warning("[intaris] MCP tool registration failed: %s", exc)

    # -- Register hooks -------------------------------------------------------
    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", _on_session_end)
    ctx.register_hook("pre_llm_call", _on_pre_llm_call)
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    ctx.register_hook("post_llm_call", _on_post_llm_call)

    # -- Start recording flush timer -----------------------------------------
    if _cfg.recording:
        _flush_timer = threading.Timer(_cfg.recording_flush_interval_s, _periodic_flush)
        _flush_timer.daemon = True
        _flush_timer.start()
