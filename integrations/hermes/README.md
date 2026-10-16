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
already-running flush retains its original client.

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
Runtime callbacks, tools, MCP cache, and timers are
replaced. Session state for the 100 most recently unloaded profiles is retained
in memory without retaining their clients, managers, or timers. Changing identity
or policy, or reloading after that state was evicted, requires a fresh Hermes
session start; tools remain blocked even with fail-open enabled until then.
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
| `INTARIS_FAIL_OPEN` | `false` | Allow tool calls when Intaris is unreachable |
| `INTARIS_ALLOW_PATHS` | (empty) | Comma-separated parent directories for policy allow_paths |
| `INTARIS_ESCALATION_TIMEOUT` | `0` | Max seconds to wait for escalation (0 = no timeout) |
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

### No sub-agent linking

Hermes's `delegate_task` tool spawns sub-agents, but the plugin system does not expose pre/post hooks for sub-agent lifecycle. Each sub-agent gets its own `on_session_start` but without parent session linkage. Sub-agent sessions appear as independent sessions in Intaris.

### No session reset hook

Hermes has no equivalent of a "session reset" event. If the user runs `/new` or `/reset`, the `on_session_end` hook fires with `completed=False`, but the plugin cannot distinguish a reset from an idle timeout.

### Plugin load order dependency

The tool wrapping approach depends on plugins loading after built-in tools. This is the current Hermes behavior (built-in tools register at import time, plugins load via `discover_plugins()` afterward), but is not a guaranteed contract.

## Verify

After starting Hermes with the plugin, open the Intaris management UI at `http://localhost:8060/ui`. You should see a new session appear in the Sessions tab when Hermes starts a conversation.

## License

MIT
