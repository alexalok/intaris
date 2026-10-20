# Hermes Agent

[Hermes Agent](https://github.com/NousResearch/hermes-agent) (by Nous Research) has a plugin system that enables tool call safety evaluation via lifecycle hooks and tool registry wrapping. The Intaris plugin intercepts every tool call and evaluates it through Intaris's safety pipeline before allowing execution.

## Install

```bash
pip install hermes-intaris
```

The plugin is auto-discovered by Hermes via the `hermes_agent.plugins` entry point. No additional configuration in Hermes is needed -- just set the environment variables.

Alternatively, for directory-based installation:

```bash
git clone https://github.com/fpytloun/intaris.git
cp -r intaris/integrations/hermes/hermes_intaris ~/.hermes/plugins/intaris
cp intaris/integrations/hermes/hermes_intaris/plugin.yaml ~/.hermes/plugins/intaris/
```

## Configure

Set environment variables before starting Hermes:

```bash
export INTARIS_API_KEY=your-api-key
export INTARIS_URL=http://localhost:8060
```

### Configuration Options

All configuration is via environment variables.

| Env Var | Default | Description |
|---|---|---|
| `INTARIS_URL` | `http://localhost:8060` | Intaris server URL |
| `INTARIS_API_KEY` | (required) | API key for authentication |
| `INTARIS_USER_ID` | (empty) | User ID. Optional if API key maps to a user. |
| `INTARIS_FAIL_OPEN` | `false` | Allow tool calls when Intaris is unreachable. 4xx errors and invalid protocol responses always block regardless. |
| `INTARIS_ALLOW_PATHS` | (empty) | Comma-separated parent dirs for `allow_paths` policy. Supports `~` expansion. |
| `INTARIS_ESCALATION_TIMEOUT` | `0` | Additional approval-wait limit in seconds; 0 uses only Hermes's finite approval limit. |
| `INTARIS_CHECKPOINT_INTERVAL` | `25` | Evaluate calls between periodic checkpoints. `0` = disabled. |
| `INTARIS_SESSION_RECORDING` | `false` | Enable session recording. |
| `INTARIS_MCP_TOOLS` | `true` | Enable MCP tool proxy (registers upstream MCP tools as native Hermes tools). |
| `INTARIS_MCP_TOOLS_CACHE_TTL_S` | `900` (15 min) | MCP tool list cache TTL in seconds. |
| `INTARIS_RECORDING_FLUSH_SIZE` | `50` | Events per recording batch flush. |
| `INTARIS_RECORDING_FLUSH_INTERVAL` | `10` | Recording flush interval in seconds. |

**Note:** `agentId` is not configurable via env var -- Hermes does not expose an agent identifier to plugins. Sessions appear with the default agent ID.

## Verify

After starting Hermes, open the Intaris management UI at `http://localhost:8060/ui`. You should see a new session appear in the Sessions tab when Hermes starts a conversation.

## How It Works

### Tool Wrapping

The Hermes plugin combines profile-owned **tool execution middleware** with a **terminal registry dispatch guard**. Middleware reserves the exact profile generation, then continues the host chain. Once downstream middleware finishes rewriting arguments, the dispatch shim captures the current tool entry and passes an invocation-local guarded copy to Hermes' native dispatcher. This preserves kwargs filtering, async handling, result normalization and all entry metadata without replacing provider registrations.

The guard calls `POST /api/v1/evaluate` and waits for approval using the existing session and cancellation rules. Immediately before invoking the captured handler, it rechecks source identity; removal or replacement during approval blocks execution. Revocation after final admission retains native in-flight semantics. No registry lock is held during HTTP requests, human waits or execution. Intaris MCP proxies keep server-side evaluation without a duplicate request.

One coordinator lives on the registry instance across independent plugin imports. Owners remain profile-scoped, and unload cannot restore native dispatch while a reserved middleware call remains in flight. The adapter restores only its own shim, never another component's later wrapper.

Startup and late-tool coverage require the scoped registry and execution middleware API. Compatibility is verified against Hermes `63d0b94120027d487c9a5235b9ec64b696af1b26`; changes to the native dispatcher contract require revalidation. Older hosts log an upgrade warning and retain snapshot-only handler protection. Direct raw-handler calls bypass guarding; direct registered-tool dispatch remains guarded while the plugin is loaded.

Hermes virtual connectors (`connectors__*`) are blocked before evaluation or downstream middleware, even when a registry tool shares the name or `INTARIS_FAIL_OPEN=true`. Their terminal path bypasses the registry, so the adapter cannot guard final arguments. The host must not bypass execution middleware for virtual calls, and must pause new tool dispatch during full plugin unload/reload gaps.

### Plugin Flow

The plugin registers 6 lifecycle hooks, execution middleware and registry guards:

1. **`on_session_start`**: Creates an Intaris session via `POST /api/v1/intention` with session ID format `hm-{uuid}`.
2. **`pre_llm_call`**: Forwards the user message as reasoning context via `POST /api/v1/reasoning`. When session recording is enabled, the user message event is recorded first and `/reasoning` is called with `from_events=true`. Otherwise, includes the last assistant message as context.
3. **Tool wrapper**: Core guardrail -- evaluates every tool call via `POST /api/v1/evaluate`:
   - **approve**: calls original handler, returns result
   - **deny**: returns error JSON to the LLM (blocks execution)
   - **escalate**: polls immediately when `/evaluate` returns unresolved escalation, then backs off (2s, 4s, 8s, 16s, 30s cap)
   - **session suspended**: polls session status until reactivated or terminated
   - **session terminated**: immediate block
4. **`pre_tool_call`**: Records tool call events when session recording is enabled.
5. **`post_tool_call`**: Records tool results when session recording is enabled.
6. **`post_llm_call`**: Captures last assistant text for reasoning context on the next user turn.
7. **`on_session_end`**: Signals session completion (`PATCH /session/{id}/status` + `POST /session/{id}/agent-summary`).

Human waits register with Hermes's sequential/concurrent deadline accounting and
stop on interruption, session end, or the smaller of Hermes `approvals.timeout`
and a positive `INTARIS_ESCALATION_TIMEOUT`. Cancellation is checked before tool
dispatch, including after reactivation and re-evaluation. Hosts without the
required wait/interrupt APIs return an approval/retry error instead of polling.
See [compatibility and cancellation limits](../../integrations/hermes/README.md#approval-deadlines-and-cancellation).

### Approval Expiration Reporting

When a native guarded invocation exits before dispatch, Hermes reports its known
escalation ID to `POST /api/v1/audit/{call_id}/expire` with the captured Intaris
`session_id` and a reason: `timeout`, `cancelled`, or `abandoned`. Invalid or
rejected polling, missing safe-wait support, and a changed tool registration count
as abandonment. Cancellation is checked again before entering an async handler.
An explicit denial, an already-expired audit, or a handler that has started is not
retired. Handler failures after entry retain native execution semantics.

Expiration is idempotent and can supersede an approval that raced cancellation;
the audit retains human/judge decision history. Polling gives `expired_at`
precedence over that history and returns a distinct **APPROVAL EXPIRED** error,
never permission to dispatch. A late evaluation reply after cancellation is also
retired if it identifies an escalation, using the original client and session.
Inline judge/human approvals retain this lifecycle through the server's
`requires_expiration: true` response field. Such approvals require a nonempty
`call_id` and remain tracked until dispatch; direct approvals and final denials
are not retired. Older servers without the field cannot identify inline approvals
for cleanup. Cleanup never sends another evaluation or execution request.

Reporting is best effort and nonblocking: up to 128 reports queue behind four
daemon workers. Each report gets at most three delivery attempts, a two-second
socket timeout per attempt, and short retry delays for transport/5xx failures.
Workers drain queued reports and exit when idle. Queue overflow, unavailable
workers, exhausted retries, and malformed acknowledgments log that expiration is
**not confirmed**. A `404` logs a server compatibility limitation; an older server
may lack the endpoint. Local blocking still applies, including with fail-open
enabled, and a failed report is never described as successfully recorded.

The queue is in memory, with no durable spool or shutdown flush guarantee. A
process crash/exit, unreachable endpoint, or sustained queue overload can leave
server approvals pending. If evaluation never returns an identifiable call ID,
Hermes cannot report its expiration. There is no server lease or automatic expiry
inferred from silence. Existing approval timeout settings are unchanged.

### MCP Tool Proxy

When `INTARIS_MCP_TOOLS=true` (default), the plugin:

1. Fetches the MCP tool list from Intaris at plugin init
2. Registers each MCP tool as a native Hermes tool via `ctx.register_tool()`
3. Refreshes the cache when stale (TTL-based)
4. Proxies tool execution through `POST /api/v1/mcp/call`
5. Safety evaluation happens server-side -- MCP tools are not wrapped by the tool registry guard to avoid double evaluation

MCP escalations return immediately with instructions to approve and retry; there
is no waiting native invocation to retire. Returning an MCP escalation or ending
its Hermes session does **not** expire that approval. The existing server-side
MCP retry flow is preserved.

## Behavioral Analysis

The plugin supports Intaris's behavioral analysis pipeline:

- **Intention tracking**: User messages are forwarded as reasoning context. Intaris now tracks recent user-message arrival server-side, so evaluation waits for the IntentionBarrier without requiring client-managed state. The legacy `intention_pending` flag remains as backward-compatible redundancy.
- **Periodic checkpoints**: Every `INTARIS_CHECKPOINT_INTERVAL` evaluate calls, sends a checkpoint with call counts, decision breakdown, and recent tool names.
- **Session completion**: On session end, sends completion status and agent summary with session statistics.

## Session Recording

In-process Hermes profiles have separate config/client snapshots, sessions,
MCP tools/caches, and recording timers. Configure non-secret per-profile values
under `plugins.entries.intaris.settings`; these override scoped env values.
Keep `INTARIS_API_KEY` in Hermes' profile credentials. The adapter reads Hermes'
secret scope and keeps env-only single-profile behavior. Current Hermes also
requires `tools.override` or `allow_tool_override: true` to wrap built-ins.
See [profile configuration and precedence](../../integrations/hermes/README.md#profiles-in-one-process).

When `INTARIS_SESSION_RECORDING=true`, the plugin buffers events in-memory per session and flushes them in batches:

- **Buffer size**: `INTARIS_RECORDING_FLUSH_SIZE` events (default: 50) triggers a flush
- **Flush interval**: `INTARIS_RECORDING_FLUSH_INTERVAL` seconds (default: 10s) periodic flush
- **Events recorded**: `message` (user/assistant), `tool_call`, `tool_result`
- **Sent via**: `POST /api/v1/session/{id}/events` with header `X-Intaris-Source: hermes`
- **Non-blocking**: Recording failures never block tool execution

## Tool Name Conventions

When using the **plugin**, tool names are Hermes's native tool names:

- Built-in tools: `terminal`, `read_file`, `write_file`, `search_files`, `patch_file`, `web_search`, etc.
- MCP tools (via plugin): `server_tool` format (e.g., `mnemory_add_memory`)

When configuring session policies, use these names:

```json
{
  "policy": {
    "allow_tools": ["read_file", "search_files"],
    "deny_tools": ["terminal"]
  }
}
```

## Troubleshooting

- **"Evaluation failed" with no server logs**: Missing user identity. If using `INTARIS_API_KEY` (single shared key), you must also set `INTARIS_USER_ID`. Alternatively, use `INTARIS_API_KEYS` on the server with a key mapped to your user_id.
- **Tool calls blocked unexpectedly**: Check `INTARIS_URL` and `INTARIS_API_KEY`. Verify the session appears in the Intaris UI.
- **"Cannot create session" errors**: Verify Intaris is running and reachable.
- **All tool calls allowed**: If `INTARIS_FAIL_OPEN=true`, Intaris may be unreachable. Check connectivity.
- **Plugin not loading**: Verify `INTARIS_API_KEY` is set (the `plugin.yaml` declares it in `requires_env`). Check `hermes plugins list`.
- **Checkpoints not appearing**: Verify `INTARIS_CHECKPOINT_INTERVAL` is not `0`.
- **Session not completing**: If Hermes exits abnormally, the `on_session_end` hook may not fire. The server's background sweep transitions idle sessions after `SESSION_IDLE_TIMEOUT_MINUTES`.
- **MCP tools not appearing**: Check that `INTARIS_MCP_TOOLS=true` and upstream MCP servers are configured in Intaris.
