"""Hermes Agent plugin for Intaris guardrails.

Intercepts every tool call and evaluates it through Intaris's safety
pipeline before allowing execution.  Tool calls that are denied or
escalated are blocked with an error message returned to the LLM.

Profile-owned execution middleware covers tools registered before or after
plugin startup. Existing registry handlers are also wrapped for direct-dispatch
protection. Both paths use the same evaluation guard; already guarded handlers
and Intaris MCP proxies retain their own evaluation without a duplicate request.

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

import contextvars
import hashlib
import inspect
import json
import logging
import os
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, replace
from functools import partial, wraps
from itertools import count
from pathlib import Path
from typing import Any, Callable

from .client import ApiResult, IntarisClient
from .waits import Invocation, WaitStopped

logger = logging.getLogger(__name__)

# ============================================================================
# Constants
# ============================================================================

MAX_SESSIONS = 100
MAX_RETIRED_PROFILES = 100
MAX_RETIRED_OWNERS = 100
MAX_RECENT_TOOLS = 10
TEARDOWN_FLUSH_TIMEOUT_S = 5.0
_profile_generations = count(1)

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


@dataclass(frozen=True)
class _PendingStart:
    """Local explicit-start evidence; remote authority binds after settlement."""

    model: str
    platform: str
    birth_generation: int
    resume_idle: bool = True
    token: object = field(default_factory=object, repr=False)


@dataclass
class SessionState:
    working_directory: str = field(default_factory=os.getcwd)
    intention: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    intaris_session_id: str | None = None
    session_created: bool = False
    # Only this Hermes session's successful start proves post-reload freshness.
    start_confirmed: bool = False
    _pending_start: _PendingStart | None = field(default=None, repr=False)
    _confirmed_start: object | None = field(default=None, repr=False)
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
    # A new event is installed on resume; old invocations retain cancellation.
    _ended: threading.Event = field(default_factory=threading.Event, repr=False)
    # Lock for session creation dedup
    _creating: bool = False
    _creation_done: threading.Event = field(default_factory=threading.Event, repr=False)
    _completion: _CompletionOwner | None = field(default=None, repr=False)


# ============================================================================
# Profile-owned runtime state
# ============================================================================


@dataclass
class ProfileRuntime:
    """One registration generation; callbacks retain this owner for life."""

    home: str
    cfg: Config
    client: IntarisClient
    generation: int = field(
        default_factory=lambda: next(_profile_generations), init=False
    )
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
    continuity_adopted: bool = False
    predecessor: ProfileRuntime | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _GuardAdmission:
    """Authority and lifetime captured before entering a foreign wrapper."""

    profile: ProfileRuntime
    session_id: str
    state: SessionState
    invocation: Invocation
    completion: _CompletionOwner


@dataclass
class _SessionContinuity:
    """Session bindings retained across unload, without registration resources."""

    fingerprint: str
    sessions: dict[str, SessionState]
    sessions_lock: Any
    recording_lock: Any
    session_start_required: threading.Event


@dataclass
class _CompletionOwner:
    """Original authority for one remote session's lifecycle effects only."""

    home: str
    session_id: str
    state: SessionState = field(repr=False)
    client: IntarisClient = field(repr=False)
    sessions: dict[str, SessionState] = field(repr=False)
    sessions_lock: Any = field(repr=False)
    recording_lock: Any = field(repr=False)
    session_start_required: threading.Event = field(repr=False)
    birth_generation: int
    token: object = field(default_factory=object, repr=False)
    lock: Any = field(default_factory=threading.RLock, repr=False)
    effects_lock: Any = field(default_factory=threading.Lock, repr=False)
    status: str = "active"
    emitted_status: str = "active"
    admissions: set[object] = field(default_factory=set, repr=False)


@dataclass(frozen=True)
class _InvocationCancellation:
    """Cancel only calls whose exact owner predates the lifecycle callback."""

    ended: threading.Event
    owner_token: object
    birth_generation: int


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

# Only live cancellation events cross generations; no client/config authority.
_active_invocations: dict[tuple[str, str], dict[object, _InvocationCancellation]] = {}
_invocations_lock = threading.Lock()
# Completion records retain no registration, timer, or new-call authority.
_completion_owners: dict[tuple[str, str], dict[object, _CompletionOwner]] = {}
_completion_owners_lock = threading.Lock()
# Unloaded and incompatible generations share one budget, counted by exact owner.
_retired_owners: dict[object, _CompletionOwner] = {}
_completion_effects = threading.local()
# A later plugin may retain an older guard in its closure. Route that exact
# guard to a fresh guard while executing the preserved wrapper chain.
_guard_replacements: contextvars.ContextVar[dict[Callable, Callable] | None] = (
    contextvars.ContextVar("intaris_guard_replacements", default=None)
)


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
    evicted_owners = []
    # Publish ownership before a captured start can pause, and serialize new
    # state admission with unload. A late callback cannot repopulate retired maps.
    with profile.lifecycle_lock:
        if not profile.active or not profile.ready:
            state = SessionState()
            state._ended.set()
            return state
        with profile.sessions_lock:
            state = profile.sessions.get(task_id)
            if state is None:
                state = SessionState()
                profile.sessions[task_id] = state
                _get_completion_owner(profile, task_id, state)
                evicted_owners = _trim_sessions(profile)
    _finish_evictions(evicted_owners)
    return state


def _trim_sessions(profile: ProfileRuntime) -> list[_CompletionOwner]:
    """Bound actual sessions and unmaterialized start records in the same map."""
    evicted = []
    while len(profile.sessions) > MAX_SESSIONS:
        state = profile.sessions.pop(next(iter(profile.sessions)))
        state._ended.set()
        state._pending_start = None
        if state._completion is not None:
            evicted.append(state._completion)
    return evicted


def _finish_evictions(owners: list[_CompletionOwner]) -> None:
    for owner in owners:
        _claim_session_end(owner, terminal=True)
    for owner in owners:
        _emit_lifecycle(owner)


def _receive_explicit_start(
    profile: ProfileRuntime, session_id: str, model: str, platform: str
) -> tuple[ProfileRuntime, SessionState] | None:
    """Record one start locally, including the exact published handoff interval."""
    if not isinstance(session_id, str) or not session_id.strip():
        return None
    with _profiles_lock:
        current = _profiles.get(profile.home)
        if current is profile or (current is None and profile.active and profile.ready):
            target = profile
        elif (
            current is not None and not current.ready and current.predecessor is profile
        ):
            target = current
        else:
            return None  # Disposed callbacks gain no general forwarding authority.
        with target.lifecycle_lock:
            # Cleanup still owns the published handoff until rollback settles.
            # Accept local evidence there, but never in an unloaded standalone
            # runtime or after a failed generation has lost that reference.
            if not target.active and not (
                current is target
                and target.predecessor is not None
                and not target.registered
            ):
                return None
            with target.sessions_lock:
                state = target.sessions.get(session_id)
                if state is None:
                    state = SessionState()
                    target.sessions[session_id] = state
                if state._ended.is_set() and not state.is_idle:
                    return None
                if (
                    state.is_idle
                    and (
                        state._pending_start is None
                        or not state._pending_start.resume_idle
                    )
                ) or (not state.start_confirmed and state._pending_start is None):
                    generation = (
                        state._completion.birth_generation
                        if state._completion is not None
                        else target.generation
                    )
                    state._pending_start = _PendingStart(model, platform, generation)
                evicted = _trim_sessions(target)
    _finish_evictions(evicted)
    return target, state


def _materialize_pending_start(
    profile: ProfileRuntime,
    session_id: Any,
    *,
    expected: SessionState | None = None,
    resume_idle: bool = False,
) -> tuple[SessionState | None, bool]:
    """Create outside bookkeeping locks and validate the exact local receipt."""
    with profile.lifecycle_lock, profile.sessions_lock:
        state = (
            profile.sessions.get(session_id) if isinstance(session_id, str) else None
        )
        if expected is not None and state is not expected:
            return expected, False
        if state is None or state._pending_start is None:
            return state, True
        pending = state._pending_start
        if (
            not profile.active
            or not profile.ready
            or (state._ended.is_set() and not state.is_idle)
            or (state.is_idle and not (pending.resume_idle or resume_idle))
            or getattr(_completion_effects, "pending", None) is not None
        ):
            return state, False
        # Publish the owner before creation or a wrapped helper can block.
        owner = _get_completion_owner(profile, session_id, state)
        must_resume = state.is_idle
        ended = state._ended
    if must_resume:
        if not _resume_session(
            profile, session_id, state, pending_start=pending, ended=ended
        ):
            return state, False
        ended = state._ended
    waiter = Invocation(ended, 0)
    try:
        waiter.check()
        remote_id = _ensure_session(
            profile, session_id, state, pending.platform, pending.model
        )
        while remote_id is None:
            waiter.check()
            with profile.lifecycle_lock, profile.sessions_lock, owner.lock:
                if (
                    not profile.active
                    or not profile.ready
                    or profile.sessions.get(session_id) is not state
                    or state._ended is not ended
                    or (
                        state._pending_start is not pending
                        and not (
                            state._pending_start is None
                            and state._confirmed_start is pending.token
                        )
                    )
                ):
                    return state, False
                remote_id = state.intaris_session_id
                creating = state._creating
            if remote_id or not creating:
                break
            # Only this exact captured receipt waits for its shared creation.
            # No bookkeeping lock spans waiting; end and host interrupt remain
            # observable even while another worker's HTTP request is blocked.
            state._creation_done.wait(0.1)
        waiter.check()
    except WaitStopped:
        return state, False
    finally:
        waiter.close()
    with profile.lifecycle_lock, profile.sessions_lock, owner.lock:
        valid = bool(
            remote_id
            and profile.active
            and profile.ready
            and profile.sessions.get(session_id) is state
            and (
                state._pending_start is pending
                or (
                    state._pending_start is None
                    and state._confirmed_start is pending.token
                )
            )
            and state._ended is ended
            and not ended.is_set()
        )
        if valid:
            state.start_confirmed = True
            state._confirmed_start = pending.token
            state._pending_start = None
    return state, valid


def _restore_pending_starts(profile: ProfileRuntime, previous: ProfileRuntime) -> None:
    """Return only raw evidence on rollback, never provisional remote authority."""
    with profile.sessions_lock:
        pending = [
            (sid, state)
            for sid, state in profile.sessions.items()
            if state._pending_start is not None and state._completion is None
        ]
        if profile.sessions is not previous.sessions:
            for sid, state in pending:
                if profile.sessions.get(sid) is state:
                    del profile.sessions[sid]
    with previous.sessions_lock:
        for sid, state in pending:
            receipt = state._pending_start
            if receipt is None or (state._ended.is_set() and not state.is_idle):
                continue
            state._pending_start = replace(
                receipt, birth_generation=previous.generation
            )
            existing = previous.sessions.get(sid)
            if existing is None or existing is state:
                previous.sessions[sid] = state
            elif existing.is_idle or not existing.start_confirmed:
                existing._pending_start = state._pending_start
                state._pending_start = None
                state._ended.set()
            else:
                state._pending_start = None
                state._ended.set()
        evicted = _trim_sessions(previous)
    # Caller is in close's deferred-effects scope; HTTP drains after outer locks.
    _finish_evictions(evicted)


def _requires_fresh_start(profile: ProfileRuntime, session_id: Any) -> bool:
    """Keep post-reload admission proof scoped to each Hermes session."""
    if not profile.session_start_required.is_set():
        return False
    with profile.sessions_lock:
        state = (
            profile.sessions.get(session_id) if isinstance(session_id, str) else None
        )
        return state is None or not state.start_confirmed


def _resolve_invocation_session(
    profile: ProfileRuntime, session_id: Any
) -> SessionState:
    """Resolve only the authoritative Hermes invocation session identity.

    Hermes passes session_id and task_id separately to handlers and hooks.
    task_id identifies tool resources, not the session used by lifecycle hooks.
    Missing or unknown identity must never borrow another session, even when
    fail-open is enabled. Idle state and insertion order are not identity.
    """
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("Missing or invalid Hermes session_id.")
    with profile.sessions_lock:
        state = profile.sessions.get(session_id)
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
    profile: ProfileRuntime,
    state: SessionState,
    tool_name: str,
    args: dict[str, Any] | None,
    call_id: str,
) -> dict[str, str] | None:
    """Remember and return the correlation entry owned by this invocation."""
    if not call_id:
        return None
    pending = {
        "tool": tool_name,
        "args": _args_fingerprint(args),
        "call_id": str(call_id),
    }
    with profile.sessions_lock:
        state.pending_tool_results.append(pending)
    return pending


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

    if state._ended.is_set():
        return None

    # Publish lifecycle ownership before creation HTTP can block. An end hook
    # may detach this state while creation finishes, without losing its outcome.
    owner = _get_completion_owner(profile, task_id, state)
    with owner.lock:
        if owner.status == "completed":
            return None
        if state.intaris_session_id or state._creating:
            return state.intaris_session_id
        state._creating = True
        state._creation_done.clear()
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
        with owner.lock:
            state._creating = False
            state._creation_done.set()
        _emit_lifecycle(owner)


# ============================================================================
# Recording
# ============================================================================


def _record_event(
    profile: ProfileRuntime,
    task_id: str,
    event: dict[str, Any],
    *,
    _state: SessionState | None = None,
) -> None:
    """Buffer an event on the state captured by its admitted producer."""
    if not profile.cfg.recording:
        return
    state = _state if _state is not None else profile.sessions.get(task_id)
    if not state or not state.intaris_session_id:
        return
    with profile.recording_lock:
        state.recording_buffer.append(event)
        # A hook admitted before unload may reach this point after the final
        # flush. Send its event through the original client immediately; no
        # timer remains to drain an inactive generation's buffer.
        should_flush = (
            not profile.ready
            or state._ended.is_set()
            or len(state.recording_buffer) >= profile.cfg.recording_flush_size
        )
    if should_flush:
        _flush_recording_buffer(profile, task_id, _state=state)


def _flush_recording_buffer(
    profile: ProfileRuntime | _CompletionOwner,
    task_id: str,
    *,
    timeout_s: float = 5.0,
    _state: SessionState | None = None,
) -> None:
    """Flush buffered events through their captured original authority."""
    state = _state if _state is not None else profile.sessions.get(task_id)
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


def _get_completion_owner(
    profile: ProfileRuntime, session_id: str, state: SessionState
) -> _CompletionOwner:
    """Share one lifecycle record across compatible registration generations."""
    with _completion_owners_lock:
        if state._completion is None:
            owner = _CompletionOwner(
                profile.home,
                session_id,
                state,
                profile.client,
                profile.sessions,
                profile.sessions_lock,
                profile.recording_lock,
                profile.session_start_required,
                (
                    state._pending_start.birth_generation
                    if state._pending_start is not None
                    else profile.generation
                ),
            )
            state._completion = owner
            _completion_owners.setdefault((profile.home, session_id), {})[
                owner.token
            ] = owner
        return state._completion


def _forget_completion_owner(owner: _CompletionOwner) -> None:
    with _completion_owners_lock:
        _retired_owners.pop(owner.token, None)
        key = (owner.home, owner.session_id)
        owners = _completion_owners.get(key)
        if owners is not None and owners.get(owner.token) is owner:
            del owners[owner.token]
            if not owners:
                del _completion_owners[key]


def _claim_session_end(owner: _CompletionOwner, terminal: bool) -> None:
    """Cancel and claim a transition before waiting for any network effects."""
    with owner.lock:
        state = owner.state
        state._ended.set()
        state._confirmed_start = None
        if owner.status == "completed":
            return
        owner.status = "completed" if terminal else "idle"
        state.is_idle = not terminal
        if terminal:
            state.start_confirmed = False
            state._pending_start = None
        elif state._pending_start is not None:
            state._pending_start = replace(
                state._pending_start, resume_idle=False, token=object()
            )
    if terminal:
        # Detach before HTTP so a fresh start can reuse the Hermes SID. A later
        # cleanup must never remove a replacement state under that same key.
        with owner.sessions_lock:
            if owner.sessions.get(owner.session_id) is state:
                del owner.sessions[owner.session_id]


def _emit_lifecycle(owner: _CompletionOwner, *, deadline: float | None = None) -> None:
    """Serialize local claims/emissions; HTTP retains best-effort semantics."""
    pending = getattr(_completion_effects, "pending", None)
    if pending is not None:
        pending[owner.token] = owner
        _completion_deadline()
        return
    if deadline is None:
        owner.effects_lock.acquire()
    elif not owner.effects_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
        return  # The existing effect worker still owns this pending transition.
    try:
        while True:
            with owner.lock:
                if (
                    owner.state._creating
                    or owner.status == owner.emitted_status
                    or (owner.status == "completed" and owner.admissions)
                ):
                    return
                status = owner.status
                if not owner.state.intaris_session_id:
                    if status == "completed":
                        _forget_completion_owner(owner)
                    return
                owner.emitted_status = status
            # Only this per-owner effect lock spans I/O. Other sessions/homes
            # and cancellation signals never wait for global network locks.
            if status == "completed":
                try:
                    _signal_completion(
                        owner, owner.session_id, owner.state, deadline=deadline
                    )
                finally:
                    _forget_completion_owner(owner)
                return
            remaining = _lifecycle_timeout(deadline, 5.0)
            if status == "idle" and remaining > 0:
                _flush_recording_buffer(
                    owner, owner.session_id, _state=owner.state, timeout_s=remaining
                )
            remaining = _lifecycle_timeout(deadline, 2.0)
            if remaining > 0:
                try:
                    owner.client.update_status(
                        owner.state.intaris_session_id, status, timeout_s=remaining
                    )
                except Exception:
                    pass
    finally:
        owner.effects_lock.release()


def _resume_session(
    profile: ProfileRuntime,
    session_id: str,
    state: SessionState,
    *,
    pending_start: _PendingStart | None = None,
    ended: threading.Event | None = None,
) -> bool:
    # Receipt changes take the map lock; lifecycle claims take the owner lock.
    # Validate both together with the local transition, before any HTTP effects.
    with profile.lifecycle_lock, profile.sessions_lock:
        owner = _get_completion_owner(profile, session_id, state)
        with owner.lock:
            if owner.status == "completed":
                return False
            if pending_start is not None and (
                not profile.active
                or not profile.ready
                or profile.sessions.get(session_id) is not state
                or (
                    state._pending_start is not pending_start
                    and not (
                        state._pending_start is None
                        and state._confirmed_start is pending_start.token
                    )
                )
            ):
                return False
            if pending_start is not None and state._ended is not ended:
                # Another materializer may have resumed this exact receipt.
                # A later idle/end replaces the receipt and is rejected above.
                return (
                    owner.status == "active"
                    and not state.is_idle
                    and not state._ended.is_set()
                )
            state._ended = threading.Event()
            state.is_idle = False
            owner.status = "active"
    _emit_lifecycle(owner)
    return not state._ended.is_set()


def _lifecycle_timeout(deadline: float | None, limit: float) -> float:
    """Cap each best-effort request by the outer operation's remaining budget."""
    return (
        limit if deadline is None else min(limit, max(0.0, deadline - time.monotonic()))
    )


def _signal_completion(
    profile: ProfileRuntime | _CompletionOwner,
    task_id: str,
    state: SessionState,
    *,
    deadline: float | None = None,
) -> None:
    """Signal session completion to Intaris within an optional shared deadline."""
    if not state.intaris_session_id:
        return

    remaining = _lifecycle_timeout(deadline, 5.0)
    if remaining > 0:
        _flush_recording_buffer(profile, task_id, _state=state, timeout_s=remaining)

    sid = state.intaris_session_id
    remaining = _lifecycle_timeout(deadline, 2.0)
    if remaining > 0:
        try:
            profile.client.update_status(sid, "completed", timeout_s=remaining)
        except Exception:
            pass
    remaining = _lifecycle_timeout(deadline, 2.0)
    if remaining > 0:
        try:
            profile.client.submit_agent_summary(
                sid, _build_agent_summary(state), timeout_s=remaining
            )
        except Exception:
            pass


def _send_checkpoint(
    profile: ProfileRuntime, state: SessionState, invocation: Invocation
) -> None:
    """Send a periodic checkpoint if interval reached."""
    assert profile.cfg is not None and profile.client is not None
    if profile.cfg.checkpoint_interval <= 0:
        return
    if state.call_count % profile.cfg.checkpoint_interval != 0:
        return
    if not state.intaris_session_id:
        return
    client = profile.client
    try:
        invocation.request(
            lambda: client.submit_checkpoint(
                state.intaris_session_id, _build_checkpoint_content(profile, state)
            )
        )
    except WaitStopped:
        raise
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


def _poll_human(
    invocation: Invocation,
    label: str,
    fetch: Callable[[], ApiResult],
    field_name: str,
    terminal_values: tuple[str, ...],
) -> str:
    """Poll only while the originating invocation and its approval budget live."""
    backoff = [2.0, 4.0, 8.0, 16.0, 30.0]
    start = time.monotonic()
    last_reminder = start
    attempt = 0
    with invocation.human_wait(label) as heartbeat:
        while True:
            invocation.check()
            now = time.monotonic()
            if now - last_reminder >= 60.0:
                logger.warning(
                    "[intaris] Still waiting for %s... %.0fs elapsed",
                    label,
                    now - start,
                )
                last_reminder = now
            # Poll once immediately, then back off in interruptible slices.
            if attempt:
                delay = backoff[min(attempt - 1, len(backoff) - 1)]
                end = time.monotonic() + delay
                while time.monotonic() < end:
                    invocation.sleep(min(1.0, end - time.monotonic()))
                    heartbeat()
            attempt += 1
            result = invocation.request(fetch)
            if result.protocol_error:
                return "invalid_response"
            if result.data is None:
                continue  # Server unreachable; remain within the wait budget.
            if not isinstance(result.data, dict):
                return "invalid_response"
            value = result.data.get(field_name)
            if field_name == "user_decision":
                if field_name not in result.data:
                    return "invalid_response"
                if value is not None and value not in terminal_values:
                    return "invalid_response"
            if value in terminal_values:
                logger.info("[intaris] %s: %s", label, value)
                return value


def _poll_escalation(
    profile: ProfileRuntime, call_id: str, tool_name: str, invocation: Invocation
) -> str:
    """Poll for escalation resolution within a Hermes human-wait window."""
    assert profile.client is not None
    client = profile.client
    return _poll_human(
        invocation,
        f"{tool_name} escalation ({call_id})",
        lambda: client.get_audit(call_id),
        "user_decision",
        ("approve", "deny"),
    )
    # No decision yet — continue polling


def _poll_session_status(
    profile: ProfileRuntime, session_id: str, tool_name: str, invocation: Invocation
) -> str:
    """Poll for session reactivation within a Hermes human-wait window."""
    assert profile.client is not None
    client = profile.client
    return _poll_human(
        invocation,
        f"{tool_name} session reactivation ({session_id})",
        lambda: client.get_session(session_id),
        "status",
        ("active", "terminated"),
    )
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
    *,
    _admission: _GuardAdmission | None = None,
) -> Callable:
    """Create a wrapper handler that evaluates via Intaris before dispatching."""
    wrapped = original_handler
    seen: set[int] = set()
    replacement_target = None
    while wrapped is not None and id(wrapped) not in seen:
        seen.add(id(wrapped))
        metadata = getattr(wrapped, "__dict__", {})
        if metadata.get("_intaris_guard") is wrapped:
            replacement_target = wrapped
            break
        wrapped = getattr(wrapped, "__wrapped__", None)

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

    def invoke_composed(args: dict, admission: _GuardAdmission, **kwargs: Any) -> Any:
        # Preserve foreign validation/argument transformations, but never let
        # the inner guard resolve a resumed session or create a new lifetime.
        replacement = _make_guarded_handler(
            profile,
            replacement_target._intaris_original_handler,
            tool_name,
            toolset,
            # The foreign wrapper may bridge sync and async handlers. Preserve
            # the retained guard's contract independently of the outer entry.
            inspect.iscoroutinefunction(replacement_target),
            _admission=admission,
        )
        replacements = dict(_guard_replacements.get() or {})
        replacements[replacement_target] = replacement
        if is_async:

            async def run() -> Any:
                token = _guard_replacements.set(replacements)
                try:
                    admission.invocation.check()
                    result = invoke_original(args, **kwargs)
                    return await result if inspect.isawaitable(result) else result
                finally:
                    _guard_replacements.reset(token)

            return run()
        token = _guard_replacements.set(replacements)
        try:
            admission.invocation.check()
            return invoke_original(args, **kwargs)
        finally:
            _guard_replacements.reset(token)

    def evaluate_and_dispatch(
        args: dict, state: SessionState, invocation: Invocation, **kwargs: Any
    ) -> Any:

        def dispatch(call_id: str = "") -> Any:
            invocation.check()
            pending = _queue_pending_tool_result(
                profile, state, tool_name, args, call_id
            )
            try:
                invocation.check()
            except WaitStopped:
                # No tool ran, so this invocation must not consume a later result.
                with profile.sessions_lock:
                    for i, candidate in enumerate(state.pending_tool_results):
                        if candidate is pending:
                            del state.pending_tool_results[i]
                            break
                raise
            return invoke_original(args, **kwargs)

        # Evaluate the tool call
        intention_pending = state.intention_pending
        client = profile.client
        result = invocation.request(
            lambda: client.evaluate(
                state.intaris_session_id,
                tool_name,
                args,
                intention_pending=intention_pending,
            )
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
            if profile.cfg.fail_open:
                logger.warning(
                    "[intaris] Evaluate failed for %s — allowing (fail-open)", tool_name
                )
                return dispatch()
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
        _send_checkpoint(profile, state, invocation)

        # Update intention after gathering enough context
        if not state.intention_updated and state.call_count >= 3:
            state.intention_updated = True
            try:
                invocation.request(
                    lambda: client.update_session(
                        state.intaris_session_id,
                        state.intention,
                        state.details,
                    )
                )
            except WaitStopped:
                raise
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
                    profile, state.intaris_session_id, tool_name, invocation
                )
                if poll_result == "invalid_response":
                    return json.dumps({"error": "[intaris] Invalid session response"})
                if poll_result == "active":
                    # Re-evaluate after reactivation
                    logger.info(
                        "[intaris] Session reactivated — re-evaluating %s",
                        tool_name,
                    )
                    re_result = invocation.request(
                        lambda: client.evaluate(
                            state.intaris_session_id, tool_name, args
                        )
                    )
                    response_error = _decision_response_error(re_result)
                    if response_error:
                        return json.dumps(
                            {"error": f"[intaris] {tool_name}: {response_error}"}
                        )
                    if re_result.data and re_result.data.get("decision") == "approve":
                        return dispatch(str(re_result.data.get("call_id") or ""))
                    if re_result.data and re_result.data.get("decision") == "escalate":
                        re_call_id = str(re_result.data.get("call_id") or "")
                        re_reason = str(
                            re_result.data.get(
                                "reasoning", "Tool call requires human approval"
                            )
                        )
                        poll_result = _poll_escalation(
                            profile, re_call_id, tool_name, invocation
                        )
                        if poll_result == "invalid_response":
                            return json.dumps(
                                {
                                    "error": f"[intaris] Invalid escalation response ({re_call_id})"
                                }
                            )
                        if poll_result == "approve":
                            return dispatch(re_call_id)
                        return json.dumps(
                            {
                                "error": f"[intaris] DENIED by user ({re_call_id}): {re_reason}"
                            }
                        )
                    re_reason = (
                        re_result.data.get("reasoning", "denied after reactivation")
                        if re_result.data
                        else "re-evaluation failed"
                    )
                    return json.dumps({"error": f"[intaris] DENIED: {re_reason}"})
                return json.dumps(
                    {
                        "error": f"[intaris] Session terminated: {status_reason or 'terminated by user'}"
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
            poll_result = _poll_escalation(profile, call_id, tool_name, invocation)
            if poll_result == "invalid_response":
                return json.dumps(
                    {"error": f"[intaris] Invalid escalation response ({call_id})"}
                )
            if poll_result == "approve":
                return dispatch(call_id)
            return json.dumps(
                {"error": f"[intaris] DENIED by user ({call_id}): {reasoning}"}
            )

        # -- APPROVE -----------------------------------------------------------
        if decision == "approve":
            return dispatch(call_id)
        return json.dumps({"error": "[intaris] Invalid evaluation response"})

    def stopped_result(exc: WaitStopped) -> str:
        return json.dumps(
            {
                "error": (
                    f"[intaris] {exc}. Tool was not executed. "
                    "Review approval in the Intaris UI, then retry in a new invocation."
                )
            }
        )

    def guarded_handler(args: dict, **kwargs: Any) -> Any:
        redirects = _guard_replacements.get() or {}
        redirect = redirects.get(public_handler)
        if redirect is not None:
            return redirect(args, **kwargs)

        admission_token = None
        if _admission is not None:
            # Private continuation of an admitted call: keep its exact state,
            # runtime and Invocation even if the session has since resumed.
            if (
                _admission.profile is not profile
                or _profile_key() != profile.home
                or kwargs.get("session_id") != _admission.session_id
            ):
                return json.dumps(
                    {
                        "error": "[intaris] Composed tool changed its originating home/session"
                    }
                )
            admission = _admission
        else:
            if (
                not profile.active
                or not profile.ready
                or _profile_key() != profile.home
            ):
                return json.dumps(
                    {
                        "error": "[intaris] Tool belongs to a different or unloaded profile"
                    }
                )
            prepared, start_valid = _materialize_pending_start(
                profile, kwargs.get("session_id")
            )
            if not start_valid:
                return stopped_result(
                    WaitStopped("CANCELLED: explicit session start is not active")
                )
            # Admission and quiescing serialize before publishing cancellation.
            with profile.lifecycle_lock:
                if (
                    not profile.active
                    or not profile.ready
                    or _profile_key() != profile.home
                ):
                    return json.dumps(
                        {
                            "error": "[intaris] Tool belongs to a different or unloaded profile"
                        }
                    )
                if _requires_fresh_start(profile, kwargs.get("session_id")):
                    return json.dumps(
                        {
                            "error": "[intaris] Profile changed; start a fresh Hermes session"
                        }
                    )
                session_id = kwargs.get("session_id")
                try:
                    state = _resolve_invocation_session(profile, session_id)
                    if prepared is not None and state is not prepared:
                        return stopped_result(
                            WaitStopped("CANCELLED: Hermes session changed")
                        )
                except ValueError as exc:
                    return json.dumps(
                        {"error": f"[intaris] {exc} Cannot evaluate {tool_name}."}
                    )
                owner = _get_completion_owner(profile, session_id, state)
                with owner.lock:
                    # Lease the captured outer lifetime atomically against
                    # retirement. Private continuations share this same lease.
                    if owner.status == "completed":
                        return stopped_result(
                            WaitStopped("CANCELLED: Hermes session ended")
                        )
                    ended = state._ended
                    admission = _GuardAdmission(
                        profile,
                        session_id,
                        state,
                        Invocation(ended, profile.cfg.escalation_timeout_s),
                        owner,
                    )
                    admission_token = object()
                    owner.admissions.add(admission_token)
                    with _invocations_lock:
                        key = (profile.home, session_id)
                        _active_invocations.setdefault(key, {})[admission_token] = (
                            _InvocationCancellation(
                                ended, owner.token, owner.birth_generation
                            )
                        )

        invocation = admission.invocation

        def release_admission() -> None:
            if admission_token is None:
                return  # Only the outer call owns this lifetime.
            invocation.close()
            with _invocations_lock:
                key = (profile.home, admission.session_id)
                pending = _active_invocations.get(key)
                if pending is not None:
                    pending.pop(admission_token, None)
                    if not pending:
                        del _active_invocations[key]
            owner = admission.completion
            with owner.lock:
                owner.admissions.discard(admission_token)
            # The last sync/awaited outer lifetime settles deferred terminal
            # effects without holding admission, profile or session-map locks.
            _emit_lifecycle(owner)

        try:
            invocation.check()
            if replacement_target is not None:
                result = invoke_composed(args, admission, **kwargs)
            else:
                result = evaluate_and_dispatch(
                    args, admission.state, invocation, **kwargs
                )
        except BaseException as exc:
            release_admission()
            if isinstance(exc, WaitStopped):
                return stopped_result(exc)
            raise
        if inspect.isawaitable(result):

            async def finish() -> Any:
                try:
                    return await result
                except WaitStopped as exc:
                    return stopped_result(exc)
                finally:
                    release_admission()

            return finish()
        release_admission()
        return result

    public_handler = guarded_handler
    if is_async:

        @wraps(guarded_handler)
        async def async_guarded_handler(args: dict, **kwargs: Any) -> Any:
            result = guarded_handler(args, **kwargs)
            return await result if inspect.isawaitable(result) else result

        public_handler = async_guarded_handler
    public_handler._intaris_original_handler = original_handler
    # wraps() copies __dict__; a copied marker must not identify a foreign guard.
    public_handler._intaris_guard = public_handler
    return public_handler


def _register_tool_guard(
    profile: ProfileRuntime, ctx: Any, registry: Any, scoped: bool, entry: Any
) -> None:
    """Install an owned guard for one entry, at startup or first ordinary dispatch."""
    original = entry.handler
    metadata = getattr(original, "__dict__", {})
    if metadata.get("_intaris_mcp_owner") is not None:
        return  # These handlers evaluate through /mcp/call themselves.
    if metadata.get("_intaris_guard") is original:
        original = metadata["_intaris_original_handler"]
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
            raise RuntimeError(f"Hermes did not register Intaris guard: {entry.name}")
    else:
        registry.register(**options)
        _track_registration(
            profile,
            _LegacyToolRegistration(registry, entry, registry._tools[entry.name]),
        )


def _make_execution_middleware(
    profile: ProfileRuntime, registry: Any, scoped: bool
) -> Callable:
    """Guard ordinary Hermes dispatch independently of tool registration order."""
    registration_lock = _registration_locks[profile.home]

    def execute(**kwargs: Any) -> Any:
        # Hermes skips middleware callbacks that raise, then executes downstream.
        # Keep all safety work inside this boundary and return an error on failure.
        downstream_started = False
        try:
            tool_name, args, next_call = (
                kwargs["tool_name"],
                kwargs["args"],
                kwargs["next_call"],
            )
            # Serialize lazy guard installation with this profile's reload and
            # other first calls. Never hold this lock while evaluating or waiting.
            with registration_lock:
                if (
                    not profile.active
                    or not profile.ready
                    or _profile_key() != profile.home
                ):
                    return json.dumps(
                        {
                            "error": "[intaris] Tool belongs to a different or unloaded profile"
                        }
                    )
                get_entry = getattr(registry, "get_entry", None)
                entry = (
                    get_entry(tool_name)
                    if callable(get_entry)
                    else registry._tools.get(tool_name)
                )
                handler = entry.handler if entry is not None else None
                seen: set[int] = set()
                while handler is not None and id(handler) not in seen:
                    seen.add(id(handler))
                    metadata = getattr(handler, "__dict__", {})
                    if (
                        metadata.get("_intaris_guard") is handler
                        or metadata.get("_intaris_mcp_owner") is not None
                    ):
                        break
                    handler = getattr(handler, "__wrapped__", None)
                else:
                    if entry is not None:
                        _register_tool_guard(
                            profile, profile.context, registry, scoped, entry
                        )

            def dispatch(payload: dict) -> Any:
                nonlocal downstream_started
                downstream_started = True
                return next_call(payload)

            if entry is not None:
                # The installed guard sees final args, including changes made by
                # later middleware, and owns the single evaluation/dispatch.
                return dispatch(args)
            # Some Hermes dispatchers resolve virtual tools outside the registry.
            # Their synchronous continuation still needs the normal native guard.
            guarded = _make_guarded_handler(profile, dispatch, tool_name, "", False)
            return guarded(args, session_id=kwargs.get("session_id"))
        except Exception as exc:
            # Do not log exception text: a provider may include tool args/secrets.
            logger.error("[intaris] Execution guard failed (%s)", type(exc).__name__)
            message = (
                "[intaris] Tool execution failed; it may have started"
                if downstream_started
                else "[intaris] Tool execution blocked: safety guard failed"
            )
            return json.dumps({"error": message})

    return execute


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
                prepared, start_valid = _materialize_pending_start(
                    profile, kwargs.get("session_id")
                )
                if not start_valid or not profile.active or not profile.ready:
                    return json.dumps(
                        {
                            "error": "[intaris] CANCELLED: explicit session start is not active"
                        }
                    )
                if _requires_fresh_start(profile, kwargs.get("session_id")):
                    return json.dumps(
                        {
                            "error": "[intaris] Profile changed; start a fresh Hermes session"
                        }
                    )

                assert profile.client is not None

                try:
                    state = _resolve_invocation_session(
                        profile, kwargs.get("session_id")
                    )
                    if prepared is not None and state is not prepared:
                        return json.dumps(
                            {"error": "[intaris] CANCELLED: Hermes session changed"}
                        )
                except ValueError as exc:
                    return json.dumps(
                        {"error": f"[intaris] {exc} Cannot call MCP tool {srv}:{tn}."}
                    )

                result = profile.client.call_mcp_tool(
                    state.intaris_session_id, srv, tn, args
                )

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
    received = _receive_explicit_start(profile, session_id, model, platform)
    if received is None:
        return
    target, state = received
    if not target.ready or getattr(_completion_effects, "pending", None) is not None:
        return  # Local receipt only during registration; never wait or do HTTP.
    _materialize_pending_start(target, session_id, expected=state)

    if (
        target.active
        and target.ready
        and target.cfg.mcp_tools
        and _is_mcp_cache_stale(target)
    ):
        try:
            _refresh_mcp_tool_cache(target)
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
    terminal = completed or interrupted
    # Only an exact active handoff lets the predecessor invalidate successor
    # raw start evidence. After settlement, the ordinary generation fence wins.
    with _profiles_lock, profile.lifecycle_lock:
        current = _profiles.get(profile.home)
        handoff = (
            current
            if current is not None
            and not current.ready
            and (current is profile or current.predecessor is profile)
            else None
        )
        with _invocations_lock:
            for record in _active_invocations.get(
                (profile.home, session_id), {}
            ).values():
                if record.birth_generation <= profile.generation:
                    record.ended.set()
        targets = [profile]
        if handoff is not None and handoff.sessions is not profile.sessions:
            targets.append(handoff)
        for target in targets:
            with target.sessions_lock:
                state = target.sessions.get(session_id)
                if state is None:
                    continue
                receipt = state._pending_start
                if state._completion is None and receipt is not None:
                    if receipt.birth_generation <= profile.generation or (
                        handoff is not None and target.sessions is handoff.sessions
                    ):
                        state._ended.set()
                        state.is_idle = not terminal
                        if terminal:
                            state._pending_start = None
                            state.start_confirmed = False
                            if target.sessions.get(session_id) is state:
                                del target.sessions[session_id]
                        else:
                            state._pending_start = replace(
                                receipt, resume_idle=False, token=object()
                            )
                elif state._completion is None:
                    _get_completion_owner(target, session_id, state)
        with _completion_owners_lock:
            owners = tuple(
                owner
                for owner in _completion_owners.get(
                    (profile.home, session_id), {}
                ).values()
                if owner.birth_generation <= profile.generation
            )
        for owner in owners:
            _claim_session_end(owner, terminal)
    for owner in owners:
        _emit_lifecycle(owner)


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
    prepared, start_valid = _materialize_pending_start(
        profile, session_id, resume_idle=bool(user_message)
    )
    if not start_valid or _requires_fresh_start(profile, session_id):
        return None

    state = profile.sessions.get(session_id)
    if prepared is not None and state is not prepared:
        return None
    if not state:
        state = _get_or_create_state(profile, session_id)
        _ensure_session(profile, session_id, state, platform, model)

    if not state.intaris_session_id:
        return None

    # Resume from idle when user provides new input
    if state.is_idle and user_message:
        if not _resume_session(profile, session_id, state):
            return None
    if state._ended.is_set():
        return None

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
                _state=state,
            )
            _flush_recording_buffer(profile, session_id, _state=state)
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
    session_id: str = "",
    **kwargs: Any,
) -> None:
    """pre_tool_call: Record tool call event (evaluation happens in wrapper)."""
    try:
        state = _resolve_invocation_session(profile, session_id)
    except ValueError:
        return
    _record_event(
        profile,
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
        _state=state,
    )


def _on_post_tool_call(
    profile: ProfileRuntime,
    tool_name: str = "",
    args: dict | None = None,
    result: Any = "",
    task_id: str = "",
    session_id: str = "",
    **kwargs: Any,
) -> None:
    """post_tool_call: Record tool result."""
    try:
        state = _resolve_invocation_session(profile, session_id)
    except ValueError:
        return
    args_key = _args_fingerprint(args)
    mapped_call_id: str | None = None
    with profile.sessions_lock:
        # Oldest-match first keeps correlation stable for repeated identical calls.
        for i, candidate in enumerate(state.pending_tool_results):
            if candidate.get("tool") == tool_name and candidate.get("args") == args_key:
                mapped_call_id = candidate.get("call_id")
                del state.pending_tool_results[i]
                break
    _record_event(
        profile,
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
        _state=state,
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
            _state=state,
        )


# ============================================================================
# Plugin Entry Point
# ============================================================================


def _bind_hook(profile: ProfileRuntime, callback: Callable) -> Callable:
    """Keep manager callbacks bound to their registration, even after a turn ends."""

    @wraps(callback)
    def bound(*args: Any, **kwargs: Any) -> Any:
        # Session end remains authoritative through replacement and for a
        # callback already captured before old hook registrations were disposed.
        if callback in (_on_session_start, _on_session_end) or (
            profile.active and profile.ready
        ):
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


@contextmanager
def _defer_completion_effects() -> Iterator[None]:
    """Drain retirement effects after the outer registration/unload returns."""
    if getattr(_completion_effects, "pending", None) is not None:
        yield
        return
    pending: dict[object, _CompletionOwner] = {}
    _completion_effects.pending = pending
    _completion_effects.deadline = None
    try:
        yield
    finally:
        deadline = _completion_effects.deadline
        del _completion_effects.pending
        del _completion_effects.deadline
        for owner in pending.values():
            _emit_lifecycle(owner, deadline=deadline)


def _completion_deadline() -> float:
    """Share one teardown budget across nested close and retirement effects."""
    if _completion_effects.deadline is None:
        _completion_effects.deadline = time.monotonic() + TEARDOWN_FLUSH_TIMEOUT_S
    return _completion_effects.deadline


def _continuity(profile: ProfileRuntime) -> _SessionContinuity:
    return _SessionContinuity(
        _session_fingerprint(profile),
        profile.sessions,
        profile.sessions_lock,
        profile.recording_lock,
        profile.session_start_required,
    )


def _retire_continuity(retained: _SessionContinuity, *, discard: bool = False) -> None:
    """Account for detached owners under _profiles_lock, deferring all effects."""
    # Published runtimes and their rollback maps stay owned through cleanup,
    # even after admission closes. Settlement explicitly accounts released maps.
    if any(
        profile.sessions is retained.sessions
        or (
            profile.predecessor is not None
            and profile.predecessor.sessions is retained.sessions
        )
        for profile in _profiles.values()
    ):
        return
    with retained.sessions_lock:
        # Raw receipts have no remote owner. Keep them only in the existing
        # bounded continuity cache; discard invalidates them without HTTP.
        cached = any(
            item.sessions is retained.sessions for item in _retired_sessions.values()
        )
        if discard or not cached:
            for sid, state in list(retained.sessions.items()):
                if state._completion is None and state._pending_start is not None:
                    state._ended.set()
                    state._pending_start = None
                    retained.session_start_required.set()
                    del retained.sessions[sid]
        owners = [state._completion for state in retained.sessions.values()]
    retiring = []
    with _completion_owners_lock:
        for owner in owners:
            if owner is None or owner.token not in _completion_owners.get(
                (owner.home, owner.session_id), {}
            ):
                continue
            if discard:
                _retired_owners.pop(owner.token, None)
                retiring.append(owner)
            else:
                _retired_owners.setdefault(owner.token, owner)
        while len(_retired_owners) > MAX_RETIRED_OWNERS:
            retiring.append(_retired_owners.pop(next(iter(_retired_owners))))
    # Cancellation and detachment happen before any I/O or effects-lock wait.
    # Captured creation/guard work keeps its own owner after index removal.
    for owner in retiring:
        owner.session_start_required.set()
        _claim_session_end(owner, terminal=True)
        _forget_completion_owner(owner)
        cached = _retired_sessions.get(owner.home)
        if cached is not None and cached.sessions is owner.sessions:
            with cached.sessions_lock:
                if not cached.sessions:
                    del _retired_sessions[owner.home]
        _emit_lifecycle(owner)


def _adopt_continuity(retained: _SessionContinuity) -> None:
    """Remove published continuity from retired accounting without ending it."""
    with retained.sessions_lock, _completion_owners_lock:
        for state in retained.sessions.values():
            if state._completion is not None:
                _retired_owners.pop(state._completion.token, None)


def _retain_sessions(profile: ProfileRuntime) -> None:
    """Retain detached continuity while the caller holds _profiles_lock."""
    previous = _retired_sessions.pop(profile.home, None)
    retained = _continuity(profile)
    _retired_sessions[profile.home] = retained
    if previous is not None and previous.sessions is not retained.sessions:
        _retire_continuity(previous)
    _retire_continuity(retained)
    while len(_retired_sessions) > MAX_RETIRED_PROFILES:
        _retire_continuity(
            _retired_sessions.pop(next(iter(_retired_sessions))), discard=True
        )


@_defer_completion_effects()
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
        deadline = _completion_deadline()
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
            previous = profile.predecessor
            if _profiles.get(profile.home) is profile:
                if not profile.registered and previous is not None:
                    _restore_pending_starts(profile, previous)
                # Keep shared state/locks for already-admitted callbacks, but
                # do not retain registration context, tools, or timers.
                # Outstanding lifecycle records own their original client.
                # Restore adopted successful continuity if cache pressure
                # removed it during a failed provisional registration. A new
                # identity that never registered must not replace it.
                if profile.registered or profile.continuity_adopted:
                    _retain_sessions(profile)
                if previous is not None and previous.active:
                    _profiles[profile.home] = previous
                else:
                    # An incompatible provisional load may outlive an unloaded
                    # predecessor whose protected cache entry was evicted.
                    if (
                        previous is not None
                        and previous.registered
                        and not (profile.registered or profile.continuity_adopted)
                    ):
                        _retain_sessions(previous)
                    del _profiles[profile.home]
            _retire_continuity(_continuity(profile))
            if previous is not None:
                _retire_continuity(_continuity(previous))
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


@_defer_completion_effects()
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
            current = _profiles.get(home)
        if (
            current is not None
            and current.context is ctx
            and current.active
            and current.ready
        ):
            return
        if getattr(ctx, "_load_abandoned", False) is True:
            return
        cfg = _resolve_config(ctx)
        profile = ProfileRuntime(
            home=home,
            cfg=cfg,
            context=ctx,
            client=IntarisClient(cfg.url, cfg.api_key, cfg.user_id, cfg.agent_id),
            policy=_build_policy(cfg.allow_paths),
            ready=False,
        )
        fingerprint = _session_fingerprint(profile)
        with _profiles_lock:
            if not scoped and any(key != home for key in _profiles):
                raise RuntimeError(
                    "Multiple Intaris profiles require Hermes' profile-scoped tool registry"
                )
            # Capture and publish the predecessor in one bookkeeping step.
            # Closing it cannot expose an evictable gap before our unload wait.
            previous = _profiles.get(home)
            profile.predecessor = previous
            if home in _registered_homes:
                profile.session_start_required.set()
            if previous is not None and previous.registered:
                _retain_sessions(previous)
            retained = _retired_sessions.get(home)
            if retained is not None and retained.fingerprint == fingerprint:
                profile.sessions = retained.sessions
                profile.sessions_lock = retained.sessions_lock
                profile.recording_lock = retained.recording_lock
                profile.session_start_required = retained.session_start_required
                profile.continuity_adopted = True
                _adopt_continuity(retained)
            _profiles[home] = profile
            if previous is not None:
                _adopt_continuity(_continuity(previous))
        try:
            if previous is not None and not _quiesce_profile(previous):
                # Wait outside bookkeeping locks after securing rollback state.
                previous.closed.wait()
            _register_profile(profile, ctx, registry, scoped)
        except Exception:
            _close_profile(profile)
            raise
        with _profiles_lock, profile.lifecycle_lock:
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
                discarded = _retired_sessions.pop(home, None)
                if discarded is not None:
                    _retire_continuity(discarded)
                if previous is not None:
                    _retire_continuity(_continuity(previous))
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

    register_middleware = getattr(ctx, "register_middleware", None)
    if callable(register_middleware):
        handle = register_middleware(
            "tool_execution", _make_execution_middleware(profile, registry, scoped)
        )
        _track_registration(profile, handle)
        if handle is None:
            raise RuntimeError("Hermes did not register Intaris execution middleware")
    else:
        logger.warning(
            "[intaris] Hermes lacks execution middleware; only tools present at "
            "registration are guarded. Upgrade Hermes for startup/late-tool protection."
        )

    # Scoped public enumeration includes other plugins visible to this profile.
    # Legacy Hermes has only a global registry; support one profile there.
    entries = registry.get_all_entries() if scoped else list(registry._tools.values())
    for entry in entries:
        _register_tool_guard(profile, ctx, registry, scoped, entry)

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
