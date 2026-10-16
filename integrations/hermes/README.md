# Hermes Agent Plugin -- Intaris

A [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that evaluates every tool call through [Intaris](https://github.com/fpytloun/intaris) safety pipeline before allowing execution.

## Features

- **Tool Call Guardrails**: Every tool call is evaluated via `POST /api/v1/evaluate` before execution -- including built-in tools
- **Full Blocking**: Denied and escalated tool calls are blocked and return an error to the LLM
- **Session Management**: Creates/manages Intaris sessions mirroring Hermes agent sessions
- **Escalation Handling**: Escalated tool calls enter a polling loop waiting for human approval via the Intaris UI
- **Session Recording**: Optional audit trail recording of all messages, tool calls, and results
- **MCP Tool Proxy**: Fetches and registers MCP tools from Intaris-connected MCP servers as native Hermes tools
- **Reasoning Context**: Forwards user messages and assistant responses to Intaris for informed safety decisions
- **Context Injection**: Injects behavioral alerts into the agent's system prompt via `pre_llm_call`
- **Fail-open/Fail-closed**: Configurable behavior when Intaris is unreachable

## Prerequisites

A running [Intaris](https://github.com/fpytloun/intaris) server accessible via HTTP.

## Install

### Via pip (recommended)

```bash
pip install hermes-intaris
```

The plugin is auto-discovered by Hermes via the `hermes_agent.plugins` entry point.

### Via directory

```bash
git clone https://github.com/fpytloun/intaris.git
cp -r intaris/integrations/hermes/hermes_intaris ~/.hermes/plugins/intaris
cp intaris/integrations/hermes/hermes_intaris/plugin.yaml ~/.hermes/plugins/intaris/
```

## Configure

Set environment variables:

```bash
export INTARIS_API_KEY=your-api-key
export INTARIS_URL=http://localhost:8060  # default
```

Enable the plugin in the profile's `config.yaml`. Current Hermes requires the
`tools.override` capability to wrap built-in tools; the supported legacy grant
is also accepted:

```yaml
plugins:
  enabled: [intaris]
  entries:
    intaris:
      allow_tool_override: true
      settings:
        url: https://intaris.example.com
        user_id: work
        agent_id: hermes-work
        allow_paths: ~/work
        mcp_tools: true
        session_recording: false
```

### Profiles in one process

Each resolved Hermes home owns its config snapshot, HTTP client, sessions,
authenticated MCP cache and tool registrations, recording buffers, and timer.
Identical Hermes session IDs in different profiles create distinct Intaris
sessions. Loading another profile cannot redirect existing callbacks. Unloading
or reloading a profile cancels its timer and releases its registrations; an
already-running flush retains its original client. Final recording uploads share
a five-second HTTP timeout budget across all sessions. Buffers not attempted
within that budget remain available to a compatible reload or to the original
session's later idle/completion event, even after an identity-changing reload.

Non-secret options can be set under `plugins.entries.intaris.settings`, using
the environment variable name below without `INTARIS_`, in lowercase (for
example, `escalation_timeout`, `session_recording`, `mcp_tools_cache_ttl_s`).
Precedence is **explicit plugin setting → Hermes profile-scoped env value →
built-in default**. Explicit `false`, `0`, and empty strings override defaults.
Hermes' `ctx.get_config()` also supports its legacy `config` subtree. Config is
captured at registration; use Hermes' plugin reload to apply changes.

Store `INTARIS_API_KEY` through Hermes' profile credentials or Desktop secret
field, not in YAML. The adapter uses `agent.secret_scope.get_secret()` for env
and credential lookup, preserving Hermes' fail-closed behavior when a required
secret scope is missing. It never reads credential files or changes
`os.environ`. Single-profile process-env configuration still works. Merely
changing `HERMES_HOME` does not load credentials: embedded hosts must install
the matching Hermes secret scope and propagate context to workers, as Hermes
does. Process env is shared, so use profile settings/scopes for distinct values.

Multiple profiles require Hermes' scoped tool registry. Older global-only
registries retain single-profile support and reject a second profile instead
of sharing guards or authenticated MCP tools. A handler called with a foreign
or unloaded profile is blocked even when fail-open is enabled. Hooks and timer
callbacks remain bound to their originating manager.

With the pip entry-point installation, reloading a profile preserves active
Intaris sessions, intention context, and counters when the backend URL,
credentials, user/agent identity, and effective path policy are unchanged.
Runtime callbacks, tools, MCP cache, and timers are replaced. Admission
continuity is cached for the 100 most recently unloaded profiles, without
retaining managers or timers. Outstanding sessions keep their original client
and state solely for lifecycle completion until their terminal end event. These
records preserve final recording/status/summary routing across identity changes
and cannot authorize new tool calls. Duplicate end callbacks produce one local
completion transition; HTTP delivery retains its existing best-effort behavior.
Changing identity or policy, or reloading after admission continuity was evicted,
requires each Hermes session to receive its own fresh session-start event. One
session's start cannot unlock another; tools remain blocked even with fail-open
enabled until that session starts.
If replacement registration fails, the last successful profile's retained
sessions remain available when retrying with that profile's configuration.
Direct in-process replacement keeps old guards blocking until the new guards
are ready, including failed replacement attempts. Hermes' force discovery
unloads plugin registrations before calling the adapter; tool dispatch must be
paused by the host during that unload/reload interval.
Legacy global-only tool registrations are restored on unload, provided another
plugin has not replaced them in the meantime.

Directory installations re-import the plugin module during force reload,
resetting its in-memory state. Start a new Hermes session after a directory
reload; use the pip entry-point installation for active-session continuity.

### Configuration Options

| Env Var | Default | Description |
|---------|---------|-------------|
| `INTARIS_URL` | `http://localhost:8060` | Intaris server URL |
| `INTARIS_API_KEY` | (required) | API key for authentication |
| `INTARIS_USER_ID` | (empty) | User ID (optional if API key maps to user) |
| `INTARIS_AGENT_ID` | (empty) | Optional agent metadata |
| `INTARIS_FAIL_OPEN` | `false` | Allow tool calls when Intaris is unreachable. 4xx errors and invalid protocol responses always block. |
| `INTARIS_ALLOW_PATHS` | (empty) | Comma-separated parent directories for policy allow_paths |
| `INTARIS_ESCALATION_TIMEOUT` | `0` | Additional approval-wait limit in seconds (0 = Hermes approval limit only) |
| `INTARIS_CHECKPOINT_INTERVAL` | `25` | Evaluate calls between checkpoints (0 = disabled) |
| `INTARIS_SESSION_RECORDING` | `false` | Enable session recording |
| `INTARIS_MCP_TOOLS` | `true` | Enable MCP tool proxy |
| `INTARIS_MCP_TOOLS_CACHE_TTL_S` | `900` | MCP tool list cache TTL in seconds (15 min) |
| `INTARIS_RECORDING_FLUSH_SIZE` | `50` | Events per recording batch |
| `INTARIS_RECORDING_FLUSH_INTERVAL` | `10` | Recording flush interval in seconds |

## How It Works

### Tool Wrapping

The plugin uses a **tool wrapping** approach: during initialization, it captures every tool handler registered in Hermes's tool registry and re-registers each with a guarded wrapper. The wrapper calls `POST /api/v1/evaluate` before dispatching to the original handler.

This works because Hermes plugins load **after** built-in tools, and the tool registry allows handler replacement. The wrapper is transparent -- same schema, same toolset, same availability checks.

### Invocation Identity

Native tool handlers and Intaris-proxied MCP handlers require the `session_id` keyword supplied by Hermes's tool dispatcher. It must match a session established by `on_session_start` or `pre_llm_call`. Tool recording hooks use the same identity. Hermes's separate `task_id` identifies tool resources; it is not a substitute for `session_id`. Tool arguments cannot supply or override this identity.

The plugin resolves that exact session regardless of session insertion order or idle status. Missing, invalid, or unknown identity blocks the call before evaluation, MCP forwarding, or native execution, even with `INTARIS_FAIL_OPEN=true`. Integrations that dispatch tools directly must forward the originating Hermes `session_id`; the plugin never guesses from the latest, only, or active session.

Host paths that omit `session_id` are also blocked. For example, the nested `execute_code` RPC and kernel dispatchers in Hermes revision `63d0b94120027d487c9a5235b9ec64b696af1b26` forward only `task_id`. Those paths need the host to propagate the originating session identity before their nested tool calls can run through this guard.

### Hook Flow

1. **`on_session_start`**: Creates an Intaris session via `POST /api/v1/intention`
2. **`pre_llm_call`**: Forwards user message as reasoning context via `POST /api/v1/reasoning`
3. **Tool wrapper**: Evaluates every tool call via `POST /api/v1/evaluate`
   - **approve**: calls original handler, returns result
   - **deny**: returns `{"error": "BLOCKED by Intaris: ..."}` to the LLM
   - **escalate**: polls only when `/evaluate` still returns unresolved escalation
4. **`pre_tool_call`**: Records tool call events for session recording
5. **`post_tool_call`**: Records tool results, sends periodic checkpoints
6. **`post_llm_call`**: Captures assistant response for reasoning context
7. **`on_session_end`**: Signals session completion to Intaris

### MCP Tool Proxy

When `INTARIS_MCP_TOOLS=true` (default), the plugin fetches MCP tools from Intaris and registers them as native Hermes tools. These tools proxy execution through `POST /api/v1/mcp/call` with full safety evaluation server-side.

## Tests

From the Intaris repository root:

```bash
PYTHONPATH=integrations/hermes uv run pytest integrations/hermes/tests -q
HERMES_SOURCE=/path/to/hermes-agent PYTHONPATH=integrations/hermes uv run pytest integrations/hermes/tests -q
```

The first command uses controlled Hermes boundary doubles and no network. The
second additionally exercises Hermes' real profile/secret contexts, worker
context propagation, tool registry, plugin settings, managers, hooks, and unload
handles. It requires an environment that can import that checkout's
`hermes_cli.plugins`. All HTTP responses and profile credentials are synthetic;
no live Hermes service or real credential files are used.

## Risks and Caveats

### Registry compatibility

Current Hermes is enumerated through `registry.get_all_entries()` and wrapped
through `ctx.register_tool(override=True)`, preserving profile overlays and host
unload tracking. The host must grant `tools.override` (or
`allow_tool_override: true`); the adapter does not bypass that check. Legacy
global-only versions use `registry._tools` and `registry.register()` for one
profile. Tool discovery after registration still depends on Hermes load order.

### Latency on every tool call

Every tool call goes through Intaris evaluation, adding network round-trip latency. Read-only tools are fast-pathed by Intaris (<1ms server-side), but the HTTP round-trip adds ~5-20ms depending on network conditions. Write operations that require LLM evaluation add up to 4 seconds.

### Synchronous blocking

Tool evaluation is synchronous -- the Hermes agent loop blocks while waiting for Intaris to respond. The `/evaluate` call may already wait for judge review and return a final `approve` or `deny`. Only unresolved escalations block for human approval in the Intaris UI.

### Approval deadlines and cancellation

Unresolved escalations and suspended sessions register a human-wait window with
Hermes. Its sequential and concurrent tool deadlines exclude this time using the
originating approval session key. Evaluation and re-evaluation HTTP time are not
excluded. The adapter checks cancellation during HTTP requests, between polls,
and immediately before dispatching the original handler.

Waiting ends on a Hermes worker interrupt (including executor abandonment),
session end/reset/idle, denial, or timeout. Resuming a session creates a new
cancellation lifetime; it cannot revive an old invocation. The total budget
starts at the first human wait and spans any reactivation/re-evaluation/escalation
sequence. It is capped by Hermes `approvals.timeout` (normally 300 seconds), or
the smaller positive `INTARIS_ESCALATION_TIMEOUT`. Setting the latter to `0`
removes only the extra adapter limit; it does not bypass Hermes's finite
human-wait accounting ceiling.

Overlapping adapter waits under the same Hermes approval key share the first
waiter's host allowance. A later waiter receives only the remaining allowance,
even if the first waiter finishes sooner. Other approval keys remain independent.
Native Hermes prompts can also share its accounting window; the host's ceiling
and interruption remain authoritative when those prompts overlap adapter waits.

This integration was verified against Hermes commit
[`63d0b94120027d487c9a5235b9ec64b696af1b26`](https://github.com/NousResearch/hermes-agent/tree/63d0b94120027d487c9a5235b9ec64b696af1b26).
Safe polling requires `tools.interrupt.is_interrupted`,
`tools.approval_context.get_current_session_key`, and the window, ceiling,
margin and heartbeat APIs in `tools.approval_human_wait`, plus the worker
interruption fan-out and deadline accounting in that host's executors. Hermes
must supply the originating `session_id` for evaluation and lifecycle cancellation;
`task_id` is not a substitute. Missing or invalid session identity blocks every
guarded call, even when exactly one adapter session exists or fail-open is enabled.
If these APIs or session context are unavailable, human waits fail closed with
an instruction to review the Intaris decision and retry; `INTARIS_FAIL_OPEN`
does not override this restriction. Immediate evaluation results remain supported
on older hosts, but host cancellation requires the interrupt API.

Cancellation releases the waiting worker and closes wait accounting. An in-flight
urllib request may finish later under its socket timeout; its result is discarded
and cannot invoke the original tool. Once a tool has started, its own interruption
behavior applies. This is cooperative cancellation, not termination of arbitrary
Python code. Proxied MCP tools retain their immediate escalation/retry behavior.

### No sub-agent linking

Hermes's `delegate_task` tool spawns sub-agents, but the plugin system does not expose pre/post hooks for sub-agent lifecycle. Each sub-agent gets its own `on_session_start` but without parent session linkage. Sub-agent sessions appear as independent sessions in Intaris.

### No session reset hook

Hermes has no equivalent of a "session reset" event. If the user runs `/new` or `/reset`, the `on_session_end` hook fires with `completed=False`, but the plugin cannot distinguish a reset from an idle timeout.

### Plugin load order dependency

The tool wrapping approach depends on plugins loading after built-in tools. This is the current Hermes behavior (built-in tools register at import time, plugins load via `discover_plugins()` afterward), but is not a guaranteed contract.

## Verify

After starting Hermes with the plugin, open the Intaris management UI at `http://localhost:8060/ui`. You should see a new session appear in the Sessions tab when Hermes starts a conversation.

Offline regression tests (no Intaris server or model API required):

```bash
PYTHONPATH=integrations/hermes python -m pytest integrations/hermes/tests -q
HERMES_SOURCE=/path/to/hermes-agent PYTHONPATH=integrations/hermes \
  python -m pytest integrations/hermes/tests -q
```

The second command additionally executes the checkout's real human-wait,
interrupt, and sequential/concurrent executor wait code with controlled transport,
clock and configuration boundaries. It does not modify or start Hermes.

## License

MIT
