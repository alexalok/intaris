# Configuration Reference

All settings are loaded from environment variables. Defaults are optimized for local development -- just set `LLM_API_KEY` and run.

Data is stored in `~/.intaris` by default (override with `DATA_DIR`). In Docker, `DATA_DIR` is set to `/data` for volume mounting.

## Server

| Variable | Default | Description |
|---|---|---|
| `INTARIS_HOST` | `0.0.0.0` | HTTP server bind address |
| `INTARIS_PORT` | `8060` | HTTP server port |
| `METRICS_ENABLED` | `true` | Start the dedicated unauthenticated metrics listener |
| `METRICS_HOST` | `0.0.0.0` | Metrics listener bind address |
| `METRICS_PORT` | `9090` | Dedicated Prometheus metrics port; must differ from `INTARIS_PORT` |
| `INTARIS_API_KEY` | (empty) | Single shared API key. Authenticates requests but does not bind to a user -- clients must send `X-User-Id` header. |
| `INTARIS_API_KEYS` | (empty) | JSON dict mapping API keys to user IDs: `{"key1": "alice", "key2": "bob", "key3": "*"}`. A value of `"*"` means auth-only (no user binding). |
| `INTARIS_AGENT_API_KEYS` | (unset) | Opt-in JSON mapping of restricted agent API keys to fixed user IDs. Requires `INTARIS_AGENT_POLICY`; keys must not overlap either admin key setting. |
| `INTARIS_AGENT_POLICY` | (unset) | Server-owned JSON session policy for restricted credentials. Strict validation; see below. |
| `INTARIS_JWT_PUBLIC_KEY` | (empty) | Path to a Cognis ES256 public key PEM for JWT validation |
| `INTARIS_JWKS_URL` | (empty) | JWKS URL for Cognis-issued JWT validation (mutually exclusive with `INTARIS_JWT_PUBLIC_KEY`) |
| `RATE_LIMIT` | `60` | Max evaluations per session per minute. Set to `0` to disable. |
| `DATA_DIR` | `~/.intaris` | Base directory for database and event store files |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### Authentication

At least one of `INTARIS_API_KEY`, `INTARIS_API_KEYS`, `INTARIS_AGENT_API_KEYS`, `INTARIS_JWT_PUBLIC_KEY`, or `INTARIS_JWKS_URL` should be set in production. Without any of them, the server accepts unauthenticated requests.

With `INTARIS_API_KEY` (single shared key), clients must also send `X-User-Id` to identify themselves. With `INTARIS_API_KEYS`, the user identity is resolved from the key mapping. With Cognis JWTs, Intaris resolves `user_id` from the JWT `sub` claim and optional `agent_id` from the JWT `agent_id` claim (or `X-Agent-Id` when the claim is absent).

Clients authenticate via `Authorization: Bearer <key-or-jwt>` header or `X-API-Key: <key>` header.

For Cognis integration, configure one JWT verifier source:

```bash
INTARIS_JWT_PUBLIC_KEY=/path/to/cognis-public.pem
# or
INTARIS_JWKS_URL=https://cognis.example.com/.well-known/jwks.json
```

JWT validation requires:

- `iss="cognis"`
- `aud` includes `"intaris"`
- `sub` claim present
- matching `agent_id` claim and `X-Agent-Id` header when both are provided

### Restricted agent credentials

Existing `INTARIS_API_KEY`, `INTARIS_API_KEYS`, and Cognis JWT/SSO credentials keep their existing administrative privileges. Give the adapter a **different**, restricted key. Both keys may map to the same tenant so a human operator can review and resolve the agent's calls.

Example server environment (replace the placeholder keys and user):

```dotenv
INTARIS_API_KEYS={"replace-admin-key":"operator"}
INTARIS_AGENT_API_KEYS={"replace-agent-key":"operator"}
INTARIS_AGENT_POLICY={"allow_tools":["read_file","search_files","read_terminal"],"deny_commands":["*sudo*"],"deny_paths":[],"maximum_outcome":"deny"}
JUDGE_MODE=advisory
```

The adapter uses `INTARIS_API_KEY=replace-agent-key` in its **own** environment and sends `X-Agent-Id: hermes`. The server's admin key, model credentials, database, configuration, and process environment must remain accessible only to the separate Intaris service user. Do not give Hermes the server environment file or service-account access. This change adds no OS isolation or sandbox.

Validation and enforcement:

- `INTARIS_AGENT_API_KEYS` is a JSON object of nonempty ASCII keys without whitespace to nonempty fixed user IDs without surrounding whitespace or glob characters (`*`, `?`, `[`, `]`). Values are never coerced. Duplicate JSON keys, malformed JSON, and overlap with `INTARIS_API_KEY` or `INTARIS_API_KEYS` fail startup. An absent or empty mapping disables the role.
- `INTARIS_AGENT_POLICY` must be an explicit JSON object when agent keys are present. Unknown fields, duplicate JSON keys (including nested ones), and invalid types fail startup. Supported fields are the string arrays `allow_tools`, `deny_tools`, `allow_commands`, `deny_commands`, `allow_paths`, `deny_paths`; `allow_policies`/`deny_policies` arrays of strings or objects; and optional `maximum_outcome`, which may only be `"deny"` (or null/omitted). Here `deny` preserves the full severity of the evaluator's decision; it does not deny every call. `judge` and `interaction_mode` overrides are unsupported: the operator controls `JUDGE_MODE`.
- `allow_tools` is an explicit, trusted native-tool list. Do not include `terminal` or `bash`, or broad shell command patterns. The example deliberately leaves `allow_commands` unset so shell calls use the conservative classifier. An explicit `allow_tools` match returns READ before the ordinary project-boundary check, including for paths outside `working_directory`. With `deny_paths: []`, access by those trusted readonly tools is bounded by the agent process's OS permissions, not by the project directory. Keep sensitive service files inaccessible to that OS user. When `working_directory` is supplied, explicit `deny_paths` rules are checked before tool allows and retain precedence. Ordinary built-in readonly classification still checks the project boundary when no explicit allow rule applies.
- The fixed tenant cannot be overridden by `X-User-Id`, `X-Agent-Id`, or role headers. If a request includes a restricted key in any supported credential carrier, it remains restricted even with an admin SSO cookie. Conflicting restricted tenants are rejected. Agent credentials cannot exchange themselves for admin cookies or use WebSocket/MCP surfaces.
- Agent session creation ignores client-supplied policy and stores the server policy plus a durable, server-only `agent_restricted` flag. Evaluating an existing same-tenant session with an agent key permanently sets this flag, including sessions created by an admin. Every later evaluation and Judge review uses the current server policy independently of the stored session policy and caller role. Removing the policy from configuration makes restricted-session evaluation fail closed. A restart or PATCH cannot remove the flag.
- Agent PATCH permits `details` and the legacy ignored `intention` field only. Policy, parent, and security-field edits are forbidden. Status PATCH permits `active`, `idle`, and `completed` only while the current status is one of those values. Its database update is conditional, so an agent cannot clear a concurrent human suspension/termination. Human admin keys retain the full lifecycle controls.
- Client `maximum_outcome`, `judge`, and unattended-mode policy cannot weaken mandatory enforcement. Restricted sessions never reuse cached Judge approvals or learned directory-prefix approvals. They do not train the path-prefix cache, including when an earlier admin inference finishes after agent adoption. Human approval applies to the exact tool and arguments on retry, not to other reads in the same directory. A human admin can still approve the exact call through `/decision`, and normal human approval polling/retry remains supported.

Only these agent routes are enabled; all other methods and paths return 403:

| Method | Routes (under `/api/v1`) |
|---|---|
| POST | `/intention`, `/evaluate`, `/reasoning`, `/checkpoint`, `/session/{id}/agent-summary`, `/session/{id}/events`, `/session/{id}/events/flush` |
| GET | `/session/{id}`, `/audit/{call_id}`, `/session/{id}/summary`, `/profile` |
| PATCH | `/session/{id}` (constrained fields), `/session/{id}/status` (constrained lifecycle) |

In particular, `/decision`, configuration/management endpoints, MCP management and calls (including stdio launch), token exchange, action-token routes, and WebSocket streams are unavailable to restricted credentials. The native Hermes lifecycle/recording works; its optional MCP tool discovery returns no tools with this key. Agent access is tenant-scoped, not an isolation boundary between sessions in the same tenant.

`terminal` and `bash` now share command, critical-pattern, and path classification; audit records keep the original tool name. Simple reads such as `cat README.md`, `ls -la`, `pwd`, and `git status --short` remain fast. Compounds/pipelines, expansion, redirection, executable scripts, and write/exec options require evaluation. Raw brace, glob (`*`, `?`, `[`, `]`), and parenthesis characters (including extended-glob syntax) require evaluation even when quoted or escaped. This deliberately sends harmless patterns such as `find . -name '*.py'` and `git tag -l 'v1.*'` through evaluation too: the syntax guard does not interpret shell quoting or expand filenames. An unquoted glob can turn files named `-delete` and `-print` into options for `find . *`. This matcher assumes the named executables and their environment/configuration are trusted; it is not a complete shell sandbox.

Git filter conversion (`git cat-file --filters`) can execute configured smudge/process commands. `--filters` and all its long-option prefixes require evaluation; this conservatively includes the distinct `--filter=...` object-selection option in newer Git versions. Plain `git cat-file -p` object reads remain fast. See [Git cat-file filters](https://git-scm.com/docs/git-cat-file) and [Git option abbreviations](https://git-scm.com/docs/gitcli).

The regression cases follow the documented behavior of [Bash command substitution](https://www.gnu.org/s/bash/manual/html_node/Command-Substitution.html), [Bash filename expansion](https://www.gnu.org/s/bash/manual/html_node/Filename-Expansion.html) and [extended patterns](https://www.gnu.org/s/bash/manual/html_node/Pattern-Matching.html), [GNU find execution actions](https://www.gnu.org/software/findutils/manual/html_node/find_html/Single-File.html), [GNU sort output files](https://www.gnu.org/software/coreutils/manual/html_node/sort-invocation.html), and [Git diff output/external helpers](https://git-scm.com/docs/git-diff). These are reasons to inspect the whole command, rather than auto-approve a leading command name.

No model or timeout defaults change with this opt-in role. Size the adapter HTTP timeout for intention/alignment barriers plus evaluator and synchronous Judge latency. A planned 60-second Hermes HTTP timeout requires a separate measured model/timeout configuration; these deterministic tests do not establish provider latency.

## Tool-Call Evaluator

| Variable | Default | Description |
|---|---|---|
| `EVALUATOR_BACKEND` | `llm` | Bounded evaluator backend: `llm` or `jev`. |
| `LLM_API_KEY` | (required for generative features) | API key for the LLM provider. Falls back to `OPENAI_API_KEY`. |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | LLM API base URL. Falls back to `OPENAI_API_BASE`. |
| `LLM_MODEL` | `gpt-5.4-nano` | Model for safety evaluation when `EVALUATOR_BACKEND=llm`. |
| `LLM_REASONING_EFFORT` | `low` | Reasoning effort hint (provider-specific). |
| `LLM_TIMEOUT_MS` | `4000` | Timeout for LLM calls in milliseconds. Must be under the 5-second circuit breaker. Minimum: 500ms. |
| `JEV_API_KEY` | (required for Jev) | Jev provider API key. Falls back to `TYPESAFE_API_KEY` only for the native TypeSafe endpoint; OpenRouter requires an explicit key. |
| `JEV_BASE_URL` | `https://api.typesafe.ai` | TypeSafe API base URL; set `https://openrouter.ai/api` for OpenRouter's decisions API. |
| `JEV_MODEL` | `jev-1.13.0` | Pinned Jev model; OpenRouter: `typesafe/jev-1.13-20260917`. |
| `JEV_TIMEOUT_MS` | `4000` | Jev timeout in milliseconds. Minimum: 500ms. |
| `JEV_MINIMUM_CONFIDENCE` | `0.6` | Minimum confidence for each Jev classification dimension. Lower-confidence tool calls and alignments escalate. |
| `JEV_DECISION_QUESTION` | `true` | Keep the third Jev disposition question; set `false` only for the experimental two-axis benchmark, where Intaris derives disposition from alignment and risk. |
| `JEV_DIAGNOSTICS` | `false` | Include model probabilities, per-question confidence, and token usage in authenticated evaluation responses for calibration. No tool arguments or intention text. |
| `JEV_APPROVAL_RISK_CONFIDENCE` | (unset) | Experimental risk-confidence floor for aligned low/medium-risk calls when `JEV_DECISION_QUESTION=false`; alignment and all other risks retain `JEV_MINIMUM_CONFIDENCE`. Requires explicit calibration. |

### Model Selection

The evaluation model should be fast and inexpensive -- it is called on every
non-read-only tool call. The default `llm` backend requires an
OpenAI-compatible model with structured JSON output.

The `jev` backend uses TypeSafe's System One API for bounded alignment, risk,
and disposition classifications. It also handles parent/child intention
alignment. Jev does not replace generative features: intention generation,
the judge, L2 summaries and L3 analysis continue using their respective LLM
configuration. Jev provider failures propagate as evaluation failures; Intaris
does not silently switch models. Jev's returned probabilities are converted
into concise audit text and are not represented as model-generated reasoning.
It is opt-in and **not the recommended production default**; see the
[Jev evaluator assessment](jev-evaluator.md) for benchmark results and caveats.

Example split configuration:

```bash
EVALUATOR_BACKEND=jev
JEV_API_KEY=...
JEV_MODEL=jev-1.13.0

# Generative intention, analysis and judge paths
LLM_API_KEY=...
ANALYSIS_LLM_MODEL=gpt-5.4-mini
JUDGE_LLM_MODEL=gpt-5.4
```

For Jev through OpenRouter with the production Groq-backed generative setup:

```bash
EVALUATOR_BACKEND=jev
JEV_BASE_URL=https://openrouter.ai/api
JEV_MODEL=typesafe/jev-1.13-20260917
JEV_API_KEY=<OpenRouter API key>
LLM_MODEL=gpt-oss-20b
LLM_BASE_URL=https://openai.fpy.cz/v1
ANALYSIS_LLM_MODEL=gpt-oss-120b
JUDGE_LLM_MODEL=gpt-oss-120b
```

## LLM (L2 Behavioral Analysis)

Separate LLM configuration for L2 analysis tasks (session summaries). Typically a more capable model with longer timeout than the evaluation model.

| Variable | Default | Description |
|---|---|---|
| `ANALYSIS_LLM_API_KEY` | (falls back to `LLM_API_KEY`) | API key for analysis LLM |
| `ANALYSIS_LLM_BASE_URL` | (falls back to `LLM_BASE_URL`) | Base URL for analysis LLM |
| `ANALYSIS_LLM_MODEL` | `gpt-5.4-mini` | Model for L2 analysis tasks |
| `ANALYSIS_LLM_REASONING_EFFORT` | `low` | Reasoning effort for analysis |
| `ANALYSIS_LLM_TIMEOUT_MS` | `30000` | Timeout for analysis LLM calls (30s) |

## LLM (L3 Cross-Session Analysis)

Separate LLM configuration for L3 cross-session behavioral analysis. L3 detects subtle patterns across sessions (progressive escalation, coordinated access, intent masking) and typically uses a more capable model than L2. Falls back to the L2 analysis config, then the evaluate LLM config.

| Variable | Default | Description |
|---|---|---|
| `ANALYSIS_L3_LLM_API_KEY` | (falls back to `ANALYSIS_LLM_API_KEY`, then `LLM_API_KEY`) | API key for L3 analysis |
| `ANALYSIS_L3_LLM_BASE_URL` | (falls back to `ANALYSIS_LLM_BASE_URL`, then `LLM_BASE_URL`) | Base URL for L3 analysis |
| `ANALYSIS_L3_LLM_MODEL` | (falls back to `ANALYSIS_LLM_MODEL`, then `gpt-5.4`) | Model for L3 analysis |
| `ANALYSIS_L3_LLM_REASONING_EFFORT` | (falls back to `ANALYSIS_LLM_REASONING_EFFORT`) | Reasoning effort for L3 analysis |
| `ANALYSIS_L3_LLM_TIMEOUT_MS` | (falls back to `ANALYSIS_LLM_TIMEOUT_MS`, default `30000`) | Timeout for L3 analysis LLM calls |

## Database

| Variable | Default | Description |
|---|---|---|
| `DB_PATH` | `~/.intaris/intaris.db` | SQLite database file path |

## Behavioral Analysis

| Variable | Default | Description |
|---|---|---|
| `ANALYSIS_ENABLED` | `true` | Master switch for behavioral analysis pipeline |
| `SESSION_IDLE_TIMEOUT_MINUTES` | `30` | Minutes of inactivity before session transitions to idle |
| `SUMMARY_VOLUME_THRESHOLD` | `50` | Evaluate calls per session before triggering a summary |
| `ANALYSIS_INTERVAL_MINUTES` | `60` | Minutes between periodic cross-session analysis runs |
| `ANALYSIS_LOOKBACK_DAYS` | `7` | Days of history to include in cross-session analysis |
| `ANALYSIS_WORKER_COUNT` | `4` | Number of parallel task queue workers |
| `ANALYSIS_WINDOW_CHARS` | `150000` | Max chars per L2 analysis window prompt. The partitioner creates more windows when data exceeds this budget. Tune for smaller/larger model context windows. |
| `ANALYSIS_L3_WINDOW_CHARS` | `200000` | Max chars per L3 cross-session analysis prompt. Progressive summarization compresses older sessions when the prompt exceeds this budget. |

## Barriers

| Variable | Default | Description |
|---|---|---|
| `INTENTION_BARRIER_TIMEOUT_MS` | `1000` | Max time (ms) the evaluate endpoint waits for a pending intention update |
| `INTENTION_BARRIER_POLL_TIMEOUT_MS` | `10000` | Max time (ms) the evaluate endpoint waits for `/reasoning` to arrive when `/evaluate` races ahead of the user-message trigger |
| `ALIGNMENT_BARRIER_TIMEOUT_MS` | `15000` | Max time (ms) the evaluate endpoint waits for a pending alignment check |

## Webhook

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URL` | (empty) | URL for escalation webhook callbacks (optional) |
| `WEBHOOK_SECRET` | (empty) | HMAC-SHA256 secret for signing webhook payloads. Required if `WEBHOOK_URL` is set. |
| `WEBHOOK_TIMEOUT_MS` | `3000` | Webhook HTTP timeout in milliseconds |
| `INTARIS_BASE_URL` | (empty) | Base URL for constructing `intaris_url` in webhook payloads |

## MCP Proxy

| Variable | Default | Description |
|---|---|---|
| `MCP_CONFIG_FILE` | (empty) | Path to JSON file defining MCP servers (optional) |
| `MCP_ALLOW_STDIO` | `true` | Allow stdio transport for MCP servers. Disable in multi-tenant deployments. |
| `INTARIS_ENCRYPTION_KEY` | (empty) | Fernet key for encrypting MCP server secrets at rest. Required when servers have secrets. |
| `MCP_UPSTREAM_TIMEOUT_MS` | `30000` | Timeout for upstream MCP server calls in milliseconds |

### Generating an Encryption Key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Event Store (Session Recording)

| Variable | Default | Description |
|---|---|---|
| `EVENT_STORE_ENABLED` | `true` | Master switch for session recording |
| `EVENT_STORE_BACKEND` | `filesystem` | Storage backend: `filesystem` or `s3` |
| `EVENT_STORE_PATH` | `~/.intaris/events` | Filesystem backend storage path |
| `EVENT_STORE_FLUSH_SIZE` | `100` | Events per chunk before flushing |
| `EVENT_STORE_FLUSH_BYTES` | `4194304` | Approximate serialized bytes per chunk before flushing |
| `EVENT_STORE_FLUSH_INTERVAL` | `30` | Seconds between periodic flushes |
| `EVENT_STORE_S3_CHUNK_CACHE_TTL` | `300` | Seconds to cache S3 chunk indexes in each process |
| `EVENT_CACHE_BACKEND` | `filesystem` | Immutable S3 chunk cache: `filesystem` or `disabled` |
| `EVENT_CACHE_PATH` | `~/.intaris/event-cache` | Local cache path; used only by the S3 event backend |
| `EVENT_CACHE_MAX_BYTES` | `10737418240` | Maximum local event cache size |
| `EVENT_CACHE_TTL_SECONDS` | `604800` | Remove chunks not accessed within this interval |
| `EVENT_CACHE_TOUCH_INTERVAL_SECONDS` | `3600` | Minimum interval between persistent access-time updates |
| `EVENT_CACHE_SWEEP_INTERVAL_SECONDS` | `60` | Minimum interval between cache eviction sweeps |

### S3 Backend

The S3 backend caches immutable chunk contents on local storage by default.
The filesystem event backend does not use this cache because its event files
are already local and authoritative.

| Variable | Default | Description |
|---|---|---|
| `EVENT_STORE_S3_ENDPOINT` | `http://localhost:9000` | S3/MinIO endpoint URL |
| `EVENT_STORE_S3_ACCESS_KEY` | (required for S3) | S3 access key |
| `EVENT_STORE_S3_SECRET_KEY` | (required for S3) | S3 secret key |
| `EVENT_STORE_S3_BUCKET` | `intaris-events` | S3 bucket name |
| `EVENT_STORE_S3_REGION` | (empty) | S3 region |

## Notifications

| Variable | Default | Description |
|---|---|---|
| `NOTIFICATION_ACTION_TTL_MINUTES` | `60` | TTL for one-click approve/deny action tokens in minutes |

Notification channels (Pushover, Slack, webhook) are configured per-user via the REST API, not environment variables.

## Judge Auto-Resolution

| Variable | Default | Description |
|---|---|---|
| `JUDGE_MODE` | `disabled` | Judge mode: `disabled` (no judge), `auto` (approve/deny, deny if uncertain), `advisory` (approve/deny/defer to human) |
| `JUDGE_NOTIFY_MODE` | `deny_only` | When to notify in judge mode: `deny_only` (judge denials only), `always` (judge approvals/denials and final unresolved escalations after defer/failure), `never` (fully silent) |

### LLM (Judge)

The judge uses a more capable model (default gpt-5.4) with longer timeout than the evaluate model. Falls back to the evaluate LLM for base URL and API key.

When `JUDGE_MODE` is enabled and the evaluator escalates, `POST /evaluate` waits for the judge. This means `JUDGE_LLM_TIMEOUT_MS` contributes directly to request latency for those escalated calls. If the judge fails or times out, the request degrades to an unresolved `escalate` for human review.

| Variable | Default | Description |
|---|---|---|
| `JUDGE_LLM_MODEL` | `gpt-5.4` | LLM model for judge reviews |
| `JUDGE_LLM_BASE_URL` | (falls back to `LLM_BASE_URL`) | LLM base URL for judge |
| `JUDGE_LLM_API_KEY` | (falls back to `LLM_API_KEY`) | LLM API key for judge |
| `JUDGE_LLM_REASONING_EFFORT` | `low` | Reasoning effort for judge LLM |
| `JUDGE_LLM_TIMEOUT_MS` | `15000` | Timeout for judge LLM calls in milliseconds |

## Client-Side Variables

These are set on the client machine, not the Intaris server:

| Variable | Default | Description |
|---|---|---|
| `INTARIS_URL` | `http://localhost:8060` | Intaris server URL |
| `INTARIS_API_KEY` | (empty) | API key for authentication |
| `INTARIS_AGENT_ID` | `opencode` / `claude-code` | Agent identifier |
| `INTARIS_USER_ID` | (empty) | User identifier (required with single-key auth) |
| `INTARIS_FAIL_OPEN` | `false` | Allow tool calls when Intaris is unreachable |
| `INTARIS_INTENTION` | (auto) | Session intention override |
| `INTARIS_ALLOW_PATHS` | (empty) | Comma-separated parent dirs for cross-project reads |
| `INTARIS_CHECKPOINT_INTERVAL` | `25` | Evaluate calls between periodic checkpoints (0 = disabled) |
| `INTARIS_SESSION_RECORDING` | `false` | Enable session recording (Claude Code only) |
| `INTARIS_DEBUG` | `false` | Enable debug logging (Claude Code only) |
