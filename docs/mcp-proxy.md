# MCP Proxy

Intaris can act as an MCP proxy, sitting between LLM clients and upstream MCP servers. Every tool call is evaluated through the safety pipeline before being forwarded upstream.

## How It Works

1. **Client connects** to Intaris at `/mcp` using MCP Streamable HTTP transport
2. **`tools/list`** -- Intaris aggregates tools from all configured upstream servers, namespaced as `server_name:tool_name`
3. **`tools/call`** -- Intaris evaluates the call through the full safety pipeline (classify -> LLM -> decide -> audit), then forwards approved calls to the upstream server
4. **Escalated calls** return an `isError: true` result with a message directing the user to the Intaris UI for approval

## Configuration

### Via REST API

Create servers through the REST API or management UI:

```bash
curl -X PUT http://localhost:8060/api/v1/mcp/servers/my-server \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "transport": "streamable-http",
    "config": {
      "url": "https://example.com/mcp",
      "headers": {"Authorization": "Bearer upstream-token"}
    },
    "enabled": true
  }'
```

### Via Config File

Define servers in a JSON file and point to it with `MCP_CONFIG_FILE`:

```json
{
  "users": {
    "alice@example.com": {
      "mcpServers": {
        "my-server": {
          "type": "streamable-http",
          "url": "https://example.com/mcp",
          "headers": {"Authorization": "Bearer token"},
          "agent_pattern": "*",
          "trust_readonly_annotations": false
        }
      }
    }
  }
}
```

File-defined servers are stored with `source="file"` in the database. On startup, the config loader reconciles: new servers are inserted, existing ones are updated, and orphaned file-sourced entries are deleted.

### Via Management UI

The Servers tab in the management UI provides a visual interface for adding, editing, and deleting MCP servers, as well as setting per-tool preferences.

<p align="center">
  <img src="../files/screenshots/ui-servers.png" width="800" alt="MCP Servers">
  <br><em>MCP server management with per-tool preference overrides</em>
</p>

## Transports

| Transport | Config Fields | Description |
|---|---|---|
| `stdio` | `command`, `args`, `env` | Subprocess-based. Requires `MCP_ALLOW_STDIO=true`. |
| `streamable-http` | `url`, `headers` | HTTP-based (MCP SDK `streamablehttp_client`). |
| `sse` | `url`, `headers` | Server-Sent Events (MCP SDK `sse_client`). |

### Stdio Example

```json
{
  "transport": "stdio",
  "config": {
    "command": "npx",
    "args": ["-y", "tavily-mcp"],
    "env": {"TAVILY_API_KEY": "tvly-..."}
  }
}
```

### HTTP Example

```json
{
  "transport": "streamable-http",
  "config": {
    "url": "https://mnemory.example.com/mcp",
    "headers": {"Authorization": "Bearer token"}
  }
}
```

## Tool Namespacing

Tools are namespaced as `server_name:tool_name` (colon separator). When a client calls a namespaced tool, the proxy strips the prefix, routes to the correct upstream server, and forwards the original tool name.

Example: Client calls `tavily:tavily_search` -> Intaris evaluates -> forwards `tavily_search` to the `tavily` upstream server.

## Tool Preferences

Per-tool overrides of the default classification behavior. Set via the REST API or management UI.

| Preference | Effect |
|---|---|
| Default (no override) | Use trusted readonly metadata when eligible; otherwise run normal evaluation |
| `evaluate` | Disable readonly metadata approval for this tool and run normal evaluation |
| `auto-approve` | Skip LLM evaluation, classify as READ (fast path) |
| `escalate` | Always escalate for human review |
| `deny` | Always deny (classify as CRITICAL) |

Preferences are checked at steps 2-5 of the classification priority chain, before critical patterns and the read-only allowlist.

## Readonly Metadata Approval

`MCP_AUTO_APPROVE_READONLY=true` enables the feature server-wide. Each upstream
server must also explicitly opt in with `trust_readonly_annotations=true`; new
and migrated servers default to `false`. Configure trust in the Servers tab,
the server create/update API, or that server's `MCP_CONFIG_FILE` entry. The
Settings tab and `GET /api/v1/config` expose the global switch. Changing the
environment switch requires a server restart, as with other environment config.

Only use this opt-in for an upstream whose tool descriptions you trust. MCP
annotations are hints, not a sandbox or proof that a tool cannot write. A tool
qualifies only when its exact upstream tool definition explicitly reports
`annotations.readOnlyHint=true` as a JSON boolean (strings and numbers do not
qualify). Missing or false hints, failed/timed-out
discovery, and ambiguous tool definitions use normal evaluation. An explicit
`evaluate` tool preference opts out; choose **default** to remove that override.
Existing explicit allow rules and `auto-approve` preferences retain their
semantics independently of this switch.

The proxy reads metadata from the same live upstream connection used for
execution, with tenant and current configuration binding. It checks again before
dispatch and rejects a changed configuration, connection, or tool preference
with retry instructions. Server edits invalidate persistent discovery caches
and reconnect on next use. Cached annotations are discovery data only; they
never grant approval and are not forwarded as approval claims to clients.

Every call still passes through the evaluator and audit log. Deny and escalation
rules, session/parent lifecycle, alignment and outcome bounds retain priority.
Pending alignment checks are awaited. Child sessions retain normal per-call
evaluation against their parent's latest intention; readonly metadata never
replaces that review, including after an alignment timeout or failure.
Path checks use the original arguments before LLM payload compaction; reads
outside the allowed project boundary require normal evaluation. Known path
fields, including arrays and nested objects, are checked. Relative MCP paths
require normal evaluation: an upstream server may resolve them against a
different cwd or logical root than the agent's session. Without a session
working directory, absolute deny rules still apply and absolute paths need
normal evaluation unless explicitly allowed. Cancellation
during metadata discovery or evaluation never dispatches the tool.

This applies only to `/mcp` calls and `POST /api/v1/mcp/call`, including Hermes
tools routed through that REST proxy. Direct `POST /api/v1/evaluate` calls,
Hermes native tools, and MCP connections that bypass Intaris do not acquire
readonly status from caller arguments or model claims. Native `terminal` and
`browser_console` are not blanket-approved. Existing credential restrictions
remain in force: restricted agent API keys cannot access MCP routes or change
server trust settings.

### Setting Preferences

```bash
# Auto-approve all tavily_search calls
curl -X PUT http://localhost:8060/api/v1/mcp/servers/tavily/preferences/tavily_search \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"preference": "auto-approve"}'

# Always escalate dangerous_tool calls
curl -X PUT http://localhost:8060/api/v1/mcp/servers/my-server/preferences/dangerous_tool \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"preference": "escalate"}'
```

## Escalation Retry

When a tool call is escalated and later approved by a human, subsequent identical calls (same tool + same args) reuse the approval for 10 minutes. Identity is based on SHA-256 of `json.dumps(args, sort_keys=True, separators=(',', ':'))`.

This means the agent can retry the exact same call after approval without triggering another escalation.

## Session Auto-Creation

The MCP proxy auto-creates sessions for new connections. Intention is resolved in priority order:

1. `X-Intaris-Intention` request header
2. `server_instructions` from the MCP initialize request
3. Default: `"MCP proxy session — evaluate all tool calls for safety"`

## Connecting Clients

### OpenCode

```json
{
  "mcp": {
    "intaris": {
      "type": "remote",
      "url": "http://localhost:8060/mcp",
      "headers": {
        "Authorization": "Bearer your-key",
        "X-Agent-Id": "opencode",
        "X-Intaris-Intention": "OpenCode coding session"
      }
    }
  }
}
```

### Claude Code

```json
{
  "mcpServers": {
    "intaris": {
      "type": "streamable-http",
      "url": "http://localhost:8060/mcp",
      "headers": {
        "Authorization": "Bearer your-key",
        "X-Agent-Id": "claude-code",
        "X-Intaris-Intention": "Claude Code coding session"
      }
    }
  }
}
```

### Any MCP Client

Any client that supports MCP Streamable HTTP transport can connect to `http://localhost:8060/mcp` with appropriate auth headers.

## Encryption

MCP server secrets (API keys in headers, environment variables for stdio) are encrypted at rest using Fernet symmetric encryption. Set `INTARIS_ENCRYPTION_KEY` to enable:

```bash
# Generate a key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set it
export INTARIS_ENCRYPTION_KEY=your-generated-key
```

The encryption key is required when any MCP server has secrets in its configuration. Without it, creating servers with secrets will fail.

## Connection Management

The `MCPConnectionManager` handles upstream connections:

- **Lazy connections**: Upstream servers are connected on first use
- **Idle timeout**: Connections are closed after 30 minutes of inactivity
- **Per-user limit**: Maximum 10 concurrent connections per user
- **Background sweep**: Periodic cleanup of idle connections
- **Tools cache**: Tool lists are cached for 5 minutes per server

## Tool Name Conventions

Different clients use different naming conventions:

| Client | Built-in Tools | MCP Tools (via proxy) |
|---|---|---|
| OpenCode | `read`, `edit`, `write`, `bash` | `server_name:tool_name` |
| Claude Code | `Read`, `Edit`, `Write`, `Bash` | `server_name:tool_name` |

When using the MCP proxy, all tools are namespaced regardless of the client. Session policies must use the namespaced format.
