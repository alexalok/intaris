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

Configuration via profile-scoped Hermes env/credentials and plugin settings:
  INTARIS_URL                      - Intaris server URL (default: http://localhost:8060)
  INTARIS_API_KEY                  - API key for authentication (required)
  INTARIS_USER_ID                  - User ID (optional if API key maps to user)
  INTARIS_AGENT_ID                 - Agent metadata (optional)
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

import hashlib
import inspect
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, fields, replace
from functools import partial, wraps
from pathlib import Path
from typing import Any, Callable

from .client import IntarisClient

logger = logging.getLogger(__name__)

# ============================================================================
# Constants
# ============================================================================

MAX_SESSIONS = 100
MAX_RETIRED_PROFILES = 100
MAX_RECENT_TOOLS = 10
TEARDOWN_FLUSH_TIMEOUT_S = 5.0

# ============================================================================
# Configuration
# ============================================================================


def _profile_env(name: str, default: str) -> str:
    """Read Hermes' installed secret/env scope without opening credential files."""
    try:
        from agent.secret_scope import get_secret
    except ModuleNotFoundError as exc:
        if exc.name not in ("agent", "agent.secret_scope"):
            raise
        # Older Hermes and standalone env-only installations.
        return os.environ.get(name, default)
    return get_secret(name, default)


def _env_bool(name: str, default: bool = False) -> bool:
    return _profile_env(name, str(default)).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _env_int(name: str, default: int) -> int:
    try:
        return int(_profile_env(name, str(default)))
    except (ValueError, TypeError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_profile_env(name, str(default)))
    except (ValueError, TypeError):
        return default


@dataclass(frozen=True)
class Config:
    url: str = ""
    api_key: str = field(default="", repr=False)
    user_id: str = ""
    agent_id: str = ""
    fail_open: bool = False
    allow_paths: str = ""
    escalation_timeout_s: float = 0.0
    checkpoint_interval: int = 25
    recording: bool = False
    recording_flush_size: int = 50
    recording_flush_interval_s: float = 10.0
    mcp_tools: bool = True
    mcp_tools_cache_ttl_s: float = 900.0


def _resolve_config(ctx: Any = None) -> Config:
    """Snapshot scoped environment defaults and this profile's plugin settings.

    PluginContext.get_config reads plugins.entries.intaris.settings (with
    Hermes' legacy config subtree fallback). Explicit settings, including
    false/zero/empty values, take precedence over scoped environment. Credentials
    come only from Hermes' secret API (process env on older, single-profile hosts).
    """
    cfg = Config(
        url=_profile_env("INTARIS_URL", "http://localhost:8060"),
        api_key=_profile_env("INTARIS_API_KEY", ""),
        user_id=_profile_env("INTARIS_USER_ID", ""),
        agent_id=_profile_env("INTARIS_AGENT_ID", ""),
        fail_open=_env_bool("INTARIS_FAIL_OPEN"),
        allow_paths=_profile_env("INTARIS_ALLOW_PATHS", ""),
        escalation_timeout_s=_env_float("INTARIS_ESCALATION_TIMEOUT", 0.0),
        checkpoint_interval=_env_int("INTARIS_CHECKPOINT_INTERVAL", 25),
        recording=_env_bool("INTARIS_SESSION_RECORDING"),
        recording_flush_size=_env_int("INTARIS_RECORDING_FLUSH_SIZE", 50),
        recording_flush_interval_s=_env_float("INTARIS_RECORDING_FLUSH_INTERVAL", 10.0),
        mcp_tools=_env_bool("INTARIS_MCP_TOOLS", True),
        mcp_tools_cache_ttl_s=_env_float("INTARIS_MCP_TOOLS_CACHE_TTL_S", 900.0),
    )
    get_config = getattr(ctx, "get_config", None)
    if not callable(get_config):
        return cfg
    setting_names = {
        "recording": "session_recording",
        "escalation_timeout_s": "escalation_timeout",
        "recording_flush_interval_s": "recording_flush_interval",
    }
    missing = object()
    overrides = {}
    for item in fields(cfg):
        if item.name == "api_key":
            continue  # Hermes stores secret fields outside config.yaml.
        name = setting_names.get(item.name, item.name)
        value = get_config(name, missing)
        if value is missing:
            continue
        default = getattr(cfg, item.name)
        if isinstance(default, bool):
            value = str(value).strip().lower() in ("1", "true", "yes", "on")
        elif isinstance(default, (int, float)):
            try:
                value = type(default)(value)
            except (TypeError, ValueError):
                value = default
        elif not isinstance(value, str):
            # Do not include the value: settings can contain credentials.
            raise ValueError(f"Intaris setting {name} must be a string")
        overrides[item.name] = value
    return replace(cfg, **overrides)


# ============================================================================
# Session State
# ============================================================================


@dataclass
class SessionState:
    working_directory: str = field(default_factory=os.getcwd)
    intention: str = ""
    details: dict[str, Any] = field(default_factory=dict)
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
# Profile-owned runtime state
# ============================================================================


@dataclass
class ProfileRuntime:
    """One registration generation; callbacks retain this owner for life."""

    home: str
    cfg: Config
    client: IntarisClient
    context: Any = field(default=None, repr=False)
    policy: dict[str, Any] = field(default_factory=dict)
    sessions: dict[str, SessionState] = field(default_factory=dict)
    sessions_lock: Any = field(default_factory=threading.Lock, repr=False)
    mcp_tool_cache: list[dict[str, Any]] | None = None
    mcp_tool_cache_at: float = 0.0
    mcp_tool_cache_lock: Any = field(default_factory=threading.Lock, repr=False)
    recording_lock: Any = field(default_factory=threading.RLock, repr=False)
    lifecycle_lock: Any = field(default_factory=threading.RLock, repr=False)
    flush_timer: threading.Timer | None = field(default=None, repr=False)
    registrations: list[Any] = field(default_factory=list, repr=False)
    closed: threading.Event = field(default_factory=threading.Event, repr=False)
    session_start_required: threading.Event = field(
        default_factory=threading.Event, repr=False
    )
    active: bool = True
    ready: bool = True
    registered: bool = False
    predecessor: ProfileRuntime | None = field(default=None, repr=False)


@dataclass
class _SessionContinuity:
    """Session data retained across unload, without runtime resources or secrets."""

    fingerprint: str
    sessions: dict[str, SessionState]
    sessions_lock: Any
    recording_lock: Any
    session_start_required: threading.Event


def _session_fingerprint(profile: ProfileRuntime) -> str:
    """Bind retained sessions to the same remote identity and effective policy."""
    cfg = profile.cfg
    identity = [cfg.url, cfg.api_key, cfg.user_id, cfg.agent_id, profile.policy]
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


# Used only to coordinate registration/unload. Calls never resolve a client
# from a mutable "current profile" pointer.
_profiles: dict[str, ProfileRuntime] = {}
_retired_sessions: dict[str, _SessionContinuity] = {}
_profiles_lock = threading.RLock()
_registration_locks: dict[str, Any] = {}
_registered_homes: set[str] = set()


def _profile_key() -> str:
    """Use Hermes' context-local home, including worker-thread overrides."""
    try:
        from hermes_constants import get_hermes_home
    except ImportError:
        home = Path(os.environ.get("HERMES_HOME", "~/.hermes"))
    else:
        home = get_hermes_home()
    return str(home.expanduser().resolve())


def _get_or_create_state(profile: ProfileRuntime, task_id: str) -> SessionState:
    with profile.sessions_lock:
        state = profile.sessions.get(task_id)
        if state is None:
            state = SessionState()
            profile.sessions[task_id] = state
            # Evict oldest entries if over limit
            if len(profile.sessions) > MAX_SESSIONS:
                excess = len(profile.sessions) - MAX_SESSIONS
                keys = list(profile.sessions.keys())[:excess]
                for k in keys:
                    profile.sessions.pop(k, None)
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


def _build_intention(
    platform: str = "", model: str = "", working_directory: str | None = None
) -> str:
    parts = ["Hermes Agent"]
    if platform:
        parts.append(f"({platform})")
    parts.append("session")
    cwd = os.getcwd() if working_directory is None else working_directory
    if cwd:
        parts.append(f"in {cwd}")
    return " ".join(parts)


def _build_details(
    platform: str = "",
    model: str = "",
    session_id: str = "",
    working_directory: str | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {"source": "hermes"}
    cwd = os.getcwd() if working_directory is None else working_directory
    if cwd:
        details["working_directory"] = cwd
    if platform:
        details["platform"] = platform
    if model:
        details["model"] = model
    if session_id:
        details["session_key"] = session_id
    return details


def _build_checkpoint_content(profile: ProfileRuntime, state: SessionState) -> str:
    interval = (
        state.call_count // profile.cfg.checkpoint_interval
        if profile.cfg.checkpoint_interval > 0
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
        f"Working directory: {state.working_directory or 'unknown'}"
    )


# ============================================================================
# Session Management
# ============================================================================


def _ensure_session(
    profile: ProfileRuntime,
    task_id: str,
    state: SessionState,
    platform: str = "",
    model: str = "",
) -> str | None:
    """Ensure an Intaris session exists.  Returns the session ID or None."""

    if state.intaris_session_id:
        return state.intaris_session_id

    # Simple dedup — only one creation at a time per state
    if state._creating:
        return state.intaris_session_id

    state._creating = True
    try:
        intaris_id = f"hm-{uuid.uuid4()}"
        state.intention = _build_intention(platform, model, state.working_directory)
        state.details = _build_details(
            platform, model, task_id, state.working_directory
        )
        result = profile.client.create_intention(
            intaris_id, state.intention, state.details, profile.policy
        )

        if result.data:
            state.intaris_session_id = intaris_id
            state.session_created = True
            logger.info("[intaris] Session created: %s", intaris_id)
        elif result.status == 409:
            # Session already exists — reuse
            state.intaris_session_id = intaris_id
            logger.info("[intaris] Session already exists, reusing: %s", intaris_id)
            profile.client.update_status(intaris_id, "active")
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


def _record_event(profile: ProfileRuntime, task_id: str, event: dict[str, Any]) -> None:
    """Buffer a recording event."""
    if not profile.cfg.recording:
        return
    state = profile.sessions.get(task_id)
    if not state or not state.intaris_session_id:
        return
    with profile.recording_lock:
        state.recording_buffer.append(event)
        # A hook admitted before unload may reach this point after the final
        # flush. Send its event through the original client immediately; no
        # timer remains to drain an inactive generation's buffer.
        should_flush = (
            not profile.ready
            or len(state.recording_buffer) >= profile.cfg.recording_flush_size
        )
    if should_flush:
        _flush_recording_buffer(profile, task_id)


def _flush_recording_buffer(
    profile: ProfileRuntime, task_id: str, *, timeout_s: float = 5.0
) -> None:
    """Flush buffered recording events to Intaris."""
    state = profile.sessions.get(task_id)
    if not state or not state.intaris_session_id:
        return
    with profile.recording_lock:
        if not state.recording_buffer:
            return
        events = state.recording_buffer[:]
        state.recording_buffer.clear()
    try:
        profile.client.append_events(
            state.intaris_session_id, events, timeout_s=timeout_s
        )
    except Exception as exc:
        logger.warning(
            "[intaris] Recording flush failed for %s: %s (%d events)",
            state.intaris_session_id,
            exc,
            len(events),
        )


def _periodic_flush(profile: ProfileRuntime) -> None:
    """Flush all recording buffers periodically."""
    if not profile.active or not profile.ready:
        return
    with profile.sessions_lock:
        task_ids = list(profile.sessions)
    for task_id in task_ids:
        try:
            _flush_recording_buffer(profile, task_id)
        except Exception:
            pass
    _schedule_flush(profile)


def _schedule_flush(profile: ProfileRuntime) -> None:
    """Bind even context-free timer threads to the originating runtime."""
    with profile.lifecycle_lock:
        if profile.active and profile.ready and profile.cfg.recording:
            profile.flush_timer = threading.Timer(
                profile.cfg.recording_flush_interval_s,
                partial(_periodic_flush, profile),
            )
            profile.flush_timer.daemon = True
            profile.flush_timer.start()


# ============================================================================
# Completion
# ============================================================================


def _signal_completion(
    profile: ProfileRuntime, task_id: str, state: SessionState
) -> None:
    """Signal session completion to Intaris."""
    if not state.intaris_session_id:
        return

    _flush_recording_buffer(profile, task_id)

    sid = state.intaris_session_id
    try:
        profile.client.update_status(sid, "completed")
    except Exception:
        pass
    try:
        profile.client.submit_agent_summary(sid, _build_agent_summary(state))
    except Exception:
        pass


def _send_checkpoint(profile: ProfileRuntime, state: SessionState) -> None:
    """Send a periodic checkpoint if interval reached."""
    if profile.cfg.checkpoint_interval <= 0:
        return
    if state.call_count % profile.cfg.checkpoint_interval != 0:
        return
    if not state.intaris_session_id:
        return
    try:
        profile.client.submit_checkpoint(
            state.intaris_session_id, _build_checkpoint_content(profile, state)
        )
    except Exception:
        pass


# ============================================================================
# MCP Tool Proxy
# ============================================================================


def _refresh_mcp_tool_cache(profile: ProfileRuntime) -> list[dict[str, Any]]:
    """Refresh the MCP tool cache from Intaris."""

    with profile.mcp_tool_cache_lock:
        try:
            tools = profile.client.list_mcp_tools()
            profile.mcp_tool_cache = tools
            profile.mcp_tool_cache_at = time.monotonic()
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
            return profile.mcp_tool_cache or []


def _is_mcp_cache_stale(profile: ProfileRuntime) -> bool:
    if profile.mcp_tool_cache is None:
        return True
    return (
        time.monotonic() - profile.mcp_tool_cache_at
    ) > profile.cfg.mcp_tools_cache_ttl_s


def _get_mcp_tool_names(profile: ProfileRuntime) -> set[str]:
    """Return the set of registered MCP tool names (server_tool format)."""
    if not profile.mcp_tool_cache:
        return set()
    return {f"{t['server']}_{t['name']}" for t in profile.mcp_tool_cache}


# ============================================================================
# Escalation Polling
# ============================================================================


def _poll_escalation(profile: ProfileRuntime, call_id: str, tool_name: str) -> str:
    """Poll for escalation resolution.  Returns 'approve' or 'deny'."""

    backoff = [2.0, 4.0, 8.0, 16.0, 30.0]
    start = time.monotonic()
    attempt = 0
    last_reminder = start

    while True:
        # Check timeout
        elapsed = time.monotonic() - start
        if (
            profile.cfg.escalation_timeout_s > 0
            and elapsed > profile.cfg.escalation_timeout_s
        ):
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
        result = profile.client.get_audit(call_id)
        if not result.data:
            continue  # Server unreachable — keep polling

        user_decision = result.data.get("user_decision")
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
        # No decision yet — continue polling


def _poll_session_status(
    profile: ProfileRuntime, session_id: str, tool_name: str
) -> str:
    """Poll for session reactivation.  Returns 'active', 'terminated', or 'timeout'."""

    backoff = [2.0, 4.0, 8.0, 16.0, 30.0]
    start = time.monotonic()
    attempt = 0
    last_reminder = start

    while True:
        elapsed = time.monotonic() - start
        if (
            profile.cfg.escalation_timeout_s > 0
            and elapsed > profile.cfg.escalation_timeout_s
        ):
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

        result = profile.client.get_session(session_id)
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
    profile: ProfileRuntime,
    original_handler: Callable,
    tool_name: str,
    toolset: str,
    is_async: bool,
) -> Callable:
    """Create a wrapper handler that evaluates via Intaris before dispatching."""
    try:
        parameters = inspect.signature(original_handler).parameters
    except (TypeError, ValueError):
        accepted_kwargs = None
    else:
        accepted_kwargs = (
            None
            if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values())
            else {
                name
                for name, p in parameters.items()
                if p.kind
                in (
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                )
            }
        )

    def invoke_original(args: dict, **kwargs: Any) -> Any:
        # Keep all Hermes context available to the guard, but honor the original
        # handler's narrow signature just as registry.dispatch() does.
        if accepted_kwargs is not None:
            kwargs = {
                name: value for name, value in kwargs.items() if name in accepted_kwargs
            }
        return original_handler(args, **kwargs)

    def guarded_handler(args: dict, **kwargs: Any) -> Any:
        if not profile.active or not profile.ready or _profile_key() != profile.home:
            return json.dumps(
                {"error": "[intaris] Tool belongs to a different or unloaded profile"}
            )
        if profile.session_start_required.is_set():
            return json.dumps(
                {"error": "[intaris] Profile changed; start a fresh Hermes session"}
            )

        # Find the active session — use the most recent non-idle session
        state: SessionState | None = None
        with profile.sessions_lock:
            for s in reversed(list(profile.sessions.values())):
                if s.intaris_session_id:
                    state = s
                    if not s.is_idle:
                        break

        if not state or not state.intaris_session_id:
            if profile.cfg.fail_open:
                logger.warning(
                    "[intaris] No active session for %s — allowing (fail-open)",
                    tool_name,
                )
                return invoke_original(args, **kwargs)
            return json.dumps(
                {
                    "error": f"[intaris] No active Intaris session. Cannot evaluate {tool_name}."
                }
            )

        # Evaluate the tool call
        intention_pending = state.intention_pending
        result = profile.client.evaluate(
            state.intaris_session_id,
            tool_name,
            args,
            intention_pending=intention_pending,
        )

        # Clear intention_pending after first evaluate
        if intention_pending:
            state.intention_pending = False

        if not result.data:
            # Distinguish config errors (4xx) from transient failures
            if result.status is not None and 400 <= result.status < 500:
                return json.dumps(
                    {
                        "error": f"[intaris] Evaluation rejected for {tool_name}: {result.error}"
                    }
                )
            if profile.cfg.fail_open:
                logger.warning(
                    "[intaris] Evaluate failed for %s — allowing (fail-open)", tool_name
                )
                return invoke_original(args, **kwargs)
            return json.dumps(
                {
                    "error": (
                        f"[intaris] Evaluation failed for {tool_name}: "
                        f"{result.error or 'server unreachable'} (INTARIS_FAIL_OPEN=false)"
                    )
                }
            )

        data = result.data
        decision = data.get("decision", "deny")
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
        _send_checkpoint(profile, state)

        # Update intention after gathering enough context
        if not state.intention_updated and state.call_count >= 3:
            state.intention_updated = True
            try:
                profile.client.update_session(
                    state.intaris_session_id,
                    state.intention,
                    state.details,
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
                poll_result = _poll_session_status(
                    profile, state.intaris_session_id, tool_name
                )
                if poll_result == "active":
                    # Re-evaluate after reactivation
                    logger.info(
                        "[intaris] Session reactivated — re-evaluating %s",
                        tool_name,
                    )
                    re_result = profile.client.evaluate(
                        state.intaris_session_id, tool_name, args
                    )
                    if re_result.data and re_result.data.get("decision") == "approve":
                        _queue_pending_tool_result(
                            state,
                            tool_name,
                            args,
                            str(re_result.data.get("call_id") or ""),
                        )
                        return invoke_original(args, **kwargs)
                    if re_result.data and re_result.data.get("decision") == "escalate":
                        re_call_id = str(re_result.data.get("call_id") or "")
                        re_reason = str(
                            re_result.data.get(
                                "reasoning", "Tool call requires human approval"
                            )
                        )
                        poll_result = _poll_escalation(profile, re_call_id, tool_name)
                        if poll_result == "approve":
                            _queue_pending_tool_result(
                                state, tool_name, args, re_call_id
                            )
                            return invoke_original(args, **kwargs)
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
                                    f"No response within {profile.cfg.escalation_timeout_s:.0f}s. "
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
                            f"No response within {profile.cfg.escalation_timeout_s:.0f}s."
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
            poll_result = _poll_escalation(profile, call_id, tool_name)
            if poll_result == "approve":
                _queue_pending_tool_result(state, tool_name, args, call_id)
                return invoke_original(args, **kwargs)
            if poll_result == "deny":
                return json.dumps(
                    {"error": f"[intaris] DENIED by user ({call_id}): {reasoning}"}
                )
            # Timeout
            return json.dumps(
                {
                    "error": (
                        f"[intaris] ESCALATION TIMEOUT ({call_id}): {reasoning}\n"
                        f"No response within {profile.cfg.escalation_timeout_s:.0f}s. "
                        f"Approve or deny in the Intaris UI."
                    )
                }
            )

        # -- APPROVE -----------------------------------------------------------
        _queue_pending_tool_result(state, tool_name, args, call_id)
        return invoke_original(args, **kwargs)

    guarded_handler._intaris_original_handler = original_handler
    if is_async:

        @wraps(guarded_handler)
        async def async_guarded_handler(args: dict, **kwargs: Any) -> Any:
            result = guarded_handler(args, **kwargs)
            return await result if inspect.isawaitable(result) else result

        return async_guarded_handler
    return guarded_handler


# ============================================================================
# MCP Tool Registration
# ============================================================================


def _register_mcp_tools(profile: ProfileRuntime, ctx: Any) -> None:
    """Register MCP tools from Intaris as Hermes agent tools."""

    tools = _refresh_mcp_tool_cache(profile)
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
                if (
                    not profile.active
                    or not profile.ready
                    or _profile_key() != profile.home
                ):
                    return json.dumps(
                        {
                            "error": "[intaris] MCP tool belongs to a different or unloaded profile"
                        }
                    )
                if profile.session_start_required.is_set():
                    return json.dumps(
                        {
                            "error": "[intaris] Profile changed; start a fresh Hermes session"
                        }
                    )

                # Find active session
                intaris_session_id: str | None = None
                with profile.sessions_lock:
                    for s in reversed(list(profile.sessions.values())):
                        if s.intaris_session_id:
                            intaris_session_id = s.intaris_session_id
                            if not s.is_idle:
                                break

                if not intaris_session_id:
                    return json.dumps(
                        {"error": "[intaris] No active session for MCP tool call"}
                    )

                result = profile.client.call_mcp_tool(intaris_session_id, srv, tn, args)

                if not result.data:
                    return json.dumps(
                        {
                            "error": f"[intaris] MCP tool call failed: {result.error or 'unknown error'}"
                        }
                    )

                data = result.data
                decision = data.get("decision")
                content = data.get("content", [])

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

                if data.get("isError"):
                    error_text = (
                        "\n".join(c.get("text", json.dumps(c)) for c in content)
                        or "MCP tool returned an error"
                    )
                    return json.dumps({"error": f"[MCP error] {error_text}"})

                # Success — return text content
                text_parts = [c.get("text", json.dumps(c)) for c in content]
                return json.dumps({"result": "\n".join(text_parts) or "(empty result)"})

            mcp_handler._intaris_mcp_owner = profile
            return mcp_handler

        handle = ctx.register_tool(
            name=tool_name,
            toolset="intaris-mcp",
            schema=schema,
            handler=_make_mcp_handler(server, name),
            description=f"[MCP: {server}] {description}",
        )
        _track_registration(profile, handle)

    logger.info("[intaris] Registered %d MCP tools from Intaris", len(tools))


# ============================================================================
# Hook Implementations
# ============================================================================


def _on_session_start(
    profile: ProfileRuntime,
    session_id: str,
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> None:
    """on_session_start: Create Intaris session."""
    state = _get_or_create_state(profile, session_id)
    if _ensure_session(profile, session_id, state, platform, model):
        profile.session_start_required.clear()

    # Refresh MCP tool cache on session start
    if profile.cfg and profile.cfg.mcp_tools and _is_mcp_cache_stale(profile):
        try:
            _refresh_mcp_tool_cache(profile)
        except Exception:
            pass


def _on_session_end(
    profile: ProfileRuntime,
    session_id: str,
    completed: bool = True,
    interrupted: bool = False,
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> None:
    """on_session_end: Signal completion or idle."""
    state = profile.sessions.get(session_id)
    if not state:
        return

    if completed or interrupted:
        _signal_completion(profile, session_id, state)
        with profile.sessions_lock:
            profile.sessions.pop(session_id, None)
    else:
        # Not completed — transition to idle
        if not state.is_idle and state.intaris_session_id and profile.client:
            state.is_idle = True
            try:
                profile.client.update_status(state.intaris_session_id, "idle")
            except Exception:
                pass


def _on_pre_llm_call(
    profile: ProfileRuntime,
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
    if profile.session_start_required.is_set():
        return None

    state = profile.sessions.get(session_id)
    if not state:
        state = _get_or_create_state(profile, session_id)
        _ensure_session(profile, session_id, state, platform, model)

    if not state.intaris_session_id:
        return None

    # Resume from idle when user provides new input
    if state.is_idle and user_message:
        state.is_idle = False
        try:
            profile.client.update_status(state.intaris_session_id, "active")
        except Exception:
            pass

    # Forward user message as reasoning context
    if user_message and user_message.strip():
        clean_text = user_message.strip()

        # Consume last assistant text as context
        assistant_context = state.last_assistant_text or None
        state.last_assistant_text = ""

        if profile.cfg.recording:
            # Record user message event, then call /reasoning with from_events
            _record_event(
                profile,
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
            _flush_recording_buffer(profile, session_id)
            try:
                profile.client.submit_reasoning(
                    state.intaris_session_id, "", from_events=True
                )
            except Exception:
                pass
        else:
            try:
                profile.client.submit_reasoning(
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
    profile: ProfileRuntime,
    tool_name: str = "",
    args: dict | None = None,
    task_id: str = "",
    **kwargs: Any,
) -> None:
    """pre_tool_call: Record tool call event (evaluation happens in wrapper)."""
    if not task_id:
        return
    _record_event(
        profile,
        task_id,
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
                "session_key": task_id,
            },
        },
    )


def _on_post_tool_call(
    profile: ProfileRuntime,
    tool_name: str = "",
    args: dict | None = None,
    result: Any = "",
    task_id: str = "",
    **kwargs: Any,
) -> None:
    """post_tool_call: Record tool result."""
    if not task_id:
        return
    state = profile.sessions.get(task_id)
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
        profile,
        task_id,
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
                "session_key": task_id,
            },
        },
    )


def _on_post_llm_call(
    profile: ProfileRuntime,
    session_id: str = "",
    user_message: str = "",
    assistant_response: str = "",
    conversation_history: Any = None,
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> None:
    """post_llm_call: Capture assistant response for reasoning context."""
    state = profile.sessions.get(session_id)
    if not state:
        return

    if assistant_response:
        state.last_assistant_text = assistant_response

        # Record assistant message
        _record_event(
            profile,
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


def _bind_hook(profile: ProfileRuntime, callback: Callable) -> Callable:
    """Keep manager callbacks bound to their registration, even after a turn ends."""

    @wraps(callback)
    def bound(*args: Any, **kwargs: Any) -> Any:
        if profile.active and profile.ready:
            return callback(profile, *args, **kwargs)
        return None

    return bound


def _quiesce_profile(profile: ProfileRuntime) -> bool:
    """Block new callbacks while retaining guards until replacement is ready."""
    with profile.lifecycle_lock:
        if not profile.active:
            return False
        profile.ready = False
        if profile.flush_timer is not None:
            profile.flush_timer.cancel()
            profile.flush_timer = None
        return True


def _retain_sessions(profile: ProfileRuntime) -> None:
    """Retain detached continuity while the caller holds _profiles_lock."""
    _retired_sessions.pop(profile.home, None)
    _retired_sessions[profile.home] = _SessionContinuity(
        _session_fingerprint(profile),
        profile.sessions,
        profile.sessions_lock,
        profile.recording_lock,
        profile.session_start_required,
    )
    while len(_retired_sessions) > MAX_RETIRED_PROFILES:
        _retired_sessions.pop(next(iter(_retired_sessions)))


def _close_profile(profile: ProfileRuntime) -> None:
    """Stop this generation's timer and dispose its Hermes registrations."""
    with profile.lifecycle_lock:
        if not _quiesce_profile(profile):
            return
        profile.active = False
        registrations = list(profile.registrations)
    try:
        with profile.sessions_lock:
            task_ids = list(profile.sessions)
        deadline = time.monotonic() + TEARDOWN_FLUSH_TIMEOUT_S
        for task_id in task_ids:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            _flush_recording_buffer(profile, task_id, timeout_s=remaining)
        for handle in reversed(registrations):
            try:
                handle.dispose()
            except Exception:
                logger.exception("[intaris] Failed to dispose profile registration")
    finally:
        with _profiles_lock:
            if _profiles.get(profile.home) is profile:
                # Keep shared state/locks for already-admitted callbacks, but
                # never retain the runtime's client, context, tools or timer.
                # A failed provisional load must not replace the last
                # successful owner's continuity with another identity.
                if profile.registered:
                    _retain_sessions(profile)
                previous = profile.predecessor
                if previous is not None and previous.active:
                    _profiles[profile.home] = previous
                else:
                    del _profiles[profile.home]
        profile.closed.set()


def _track_registration(profile: ProfileRuntime, handle: Any) -> None:
    """Retain host lifecycle handles when supported by the Hermes version."""
    if handle is not None:
        with profile.lifecycle_lock:
            if profile.active:
                profile.registrations.append(handle)
            else:
                handle.dispose()


@dataclass
class _LegacyToolRegistration:
    """Restore only the global registration installed by this generation."""

    registry: Any
    previous: Any
    current: Any

    def dispose(self) -> None:
        """Leave later registrations untouched, including repeated cleanup."""
        restore = getattr(self.registry, "restore_registration", None)
        if callable(restore):
            restore(self.previous.name, self.current, self.previous)
        elif self.registry._tools.get(self.previous.name) is self.current:
            # Older global-only registries expose no restoration API.
            self.registry._tools[self.previous.name] = self.previous


def register(ctx: Any) -> None:
    """Register guards and hooks in the active Hermes profile's namespace.

    The home is resolved once at registration. Each callback captures that
    runtime, so another registration cannot redirect an in-flight request.
    """
    from tools.registry import registry  # type: ignore[import-not-found]

    home = _profile_key()
    scoped = callable(getattr(registry, "get_all_entries", None)) and (
        "scope" in inspect.signature(registry.register).parameters
    )
    with _profiles_lock:
        registration_lock = _registration_locks.setdefault(home, threading.RLock())
    # Network requests and recording flushes must not hold up another home.
    with registration_lock:
        with _profiles_lock:
            previous = _profiles.get(home)
            known_home = home in _registered_homes
        if (
            previous is not None
            and previous.context is ctx
            and previous.active
            and previous.ready
        ):
            return
        if getattr(ctx, "_load_abandoned", False) is True:
            return
        cfg = _resolve_config(ctx)
        if previous is not None:
            if not _quiesce_profile(previous):
                # External unload already owns cleanup. It must not wait for
                # registration_lock when abandoning a blocked loader.
                previous.closed.wait()
            elif previous.registered:
                with _profiles_lock:
                    _retain_sessions(previous)
        profile = ProfileRuntime(
            home=home,
            cfg=cfg,
            context=ctx,
            client=IntarisClient(cfg.url, cfg.api_key, cfg.user_id, cfg.agent_id),
            policy=_build_policy(cfg.allow_paths),
            ready=False,
            predecessor=previous,
        )
        if known_home:
            profile.session_start_required.set()
        fingerprint = _session_fingerprint(profile)
        with _profiles_lock:
            if not scoped and any(key != home for key in _profiles):
                raise RuntimeError(
                    "Multiple Intaris profiles require Hermes' profile-scoped tool registry"
                )
            retained = _retired_sessions.get(home)
            if retained is not None and retained.fingerprint == fingerprint:
                profile.sessions = retained.sessions
                profile.sessions_lock = retained.sessions_lock
                profile.recording_lock = retained.recording_lock
                profile.session_start_required = retained.session_start_required
            _profiles[home] = profile
        try:
            _register_profile(profile, ctx, registry, scoped)
        except Exception:
            _close_profile(profile)
            raise
        with profile.lifecycle_lock, _profiles_lock:
            if (
                profile.active
                and getattr(ctx, "_load_abandoned", False) is not True
                and _profiles.get(home) is profile
            ):
                if previous is not None and not scoped:
                    # Rollback restores immediate guards. Once committed,
                    # final unload must restore their original entries.
                    originals = {
                        id(handle.current): handle.previous
                        for handle in previous.registrations
                        if isinstance(handle, _LegacyToolRegistration)
                    }
                    for handle in profile.registrations:
                        if isinstance(handle, _LegacyToolRegistration):
                            handle.previous = originals.get(
                                id(handle.previous), handle.previous
                            )
                profile.registered = True
                profile.ready = True
                profile.predecessor = None
                _retired_sessions.pop(home, None)
                # A lock records an attempt, not a successful load. Retain
                # successful history even after continuity-cache eviction.
                _registered_homes.add(home)
        if not profile.registered:
            _close_profile(profile)
            return
        # Replacement guards now cover the old ones. Scoped Hermes leases
        # skip disposed predecessors when the replacement is later unloaded.
        if previous is not None:
            _close_profile(previous)
        _schedule_flush(profile)


def _register_profile(
    profile: ProfileRuntime, ctx: Any, registry: Any, scoped: bool
) -> None:
    """Install one profile while only its own registration lock is held."""
    # Install cleanup before any discovery I/O: Hermes can abandon a loader
    # and roll its registrations back while that request is still running.
    on_unload = getattr(ctx, "on_unload", None)
    if callable(on_unload):
        on_unload(partial(_close_profile, profile))
    cfg = profile.cfg
    if not cfg.api_key:
        logger.warning(
            "[intaris] API key not configured — plugin will fail to authenticate. "
            "Set INTARIS_API_KEY in the profile's Hermes credentials."
        )
    if cfg.fail_open:
        logger.warning(
            "[intaris] Fail-open mode enabled — tool calls will proceed unchecked "
            "if Intaris is unreachable."
        )

    # Scoped public enumeration includes other plugins visible to this profile.
    # Legacy Hermes has only a global registry; support one profile there.
    entries = registry.get_all_entries() if scoped else list(registry._tools.values())
    for entry in entries:
        original = entry.handler
        metadata = getattr(original, "__dict__", {})
        if metadata.get("_intaris_mcp_owner") is not None:
            continue  # These handlers evaluate through /mcp/call themselves.
        original = metadata.get("_intaris_original_handler", original)
        guarded = _make_guarded_handler(
            profile, original, entry.name, entry.toolset, entry.is_async
        )
        options = dict(
            name=entry.name,
            toolset=entry.toolset,
            schema=entry.schema,
            handler=guarded,
            check_fn=entry.check_fn,
            requires_env=entry.requires_env,
            is_async=entry.is_async,
            description=entry.description,
            emoji=entry.emoji,
        )
        if scoped:
            # The host enforces tools.override / allow_tool_override permission
            # and owns teardown of this profile's overlay.
            handle = ctx.register_tool(**options, override=True)
            _track_registration(profile, handle)
            if handle is None:
                raise RuntimeError(
                    f"Hermes did not register Intaris guard: {entry.name}"
                )
        else:
            registry.register(**options)
            _track_registration(
                profile,
                _LegacyToolRegistration(registry, entry, registry._tools[entry.name]),
            )

    if profile.cfg.mcp_tools:
        try:
            _register_mcp_tools(profile, ctx)
        except Exception as exc:
            logger.warning("[intaris] MCP tool registration failed: %s", exc)

    if not profile.active or getattr(ctx, "_load_abandoned", False) is True:
        _close_profile(profile)
        return

    for name, callback in (
        ("on_session_start", _on_session_start),
        ("on_session_end", _on_session_end),
        ("pre_llm_call", _on_pre_llm_call),
        ("pre_tool_call", _on_pre_tool_call),
        ("post_tool_call", _on_post_tool_call),
        ("post_llm_call", _on_post_llm_call),
    ):
        _track_registration(
            profile, ctx.register_hook(name, _bind_hook(profile, callback))
        )
    logger.info(
        "[intaris] Registered profile %s (%d guarded tools)", profile.home, len(entries)
    )
