# CLEF as an Intaris evaluator

**2026-10-18: opt-in integration verified through OpenRouter. The documented
2K text truncation was not reproduced on any of the three tested providers.**
Confidence calibration remains a separate limitation: two of four benign
operations escalated in this small sample on every provider, in both runs.

## Configuration

CLEF uses the existing Jev-compatible adapter and configuration prefix:

```bash
EVALUATOR_BACKEND=jev
JEV_BASE_URL=https://openrouter.ai/api
JEV_MODEL=cloudflare/clef
JEV_API_KEY="${OPENROUTER_API_KEY}"
JEV_OPENROUTER_PROVIDERS=deepinfra,cloudflare
JEV_MAX_INPUT_BYTES=60000
JEV_TIMEOUT_MS=4000
JEV_MINIMUM_CONFIDENCE=0.6
JEV_DECISION_QUESTION=true
```

`OPENROUTER_API_KEY` must be an inference key. Management keys cannot run
inference. Keep the existing `LLM_API_KEY` and generative-model configuration
for intention generation, judge, summaries, and analysis. CLEF replaces the
selected L1 decision model and parent/child alignment model; it does not add a
second L1 pass. Escalations still use the existing judge/human workflow.
The `llm` audit-path name remains unchanged for compatibility.

The client sends `provider.only`. One provider slug pins a provider with
`allow_fallbacks=false`; multiple slugs enable `allow_fallbacks=true` so
OpenRouter can route and retry within that allowlist. Providers outside the
allowlist remain excluded. Native Jev defaults remain unchanged. CLEF startup
fails without an explicit OpenRouter provider selection and a positive input
budget.

The budget counts compact UTF-8 JSON bytes of **both complete state and
questions**, including rules, intentions, tool arguments, and history. Routing
metadata is excluded. Over-budget tool calls return `escalate`; over-budget
alignment checks require review. Neither path sends a provider request or
silently trims input. Other provider errors retain the existing failure behavior.

This is a byte ceiling, not a token counter or a guarantee about provider-side
limits. The example allows DeepInfra and Cloudflare, both advertising about
65K tokens of context, with a 60,000-byte request ceiling. Revalidate the budget
when changing providers or models; PrimeIntellect advertises only 16,384 tokens.
If allowing multiple providers, choose a budget appropriate for the smallest
context. The tests
below establish retention up to the measured offsets, not the full advertised
window. `JEV_DIAGNOSTICS=true` exposes scores and usage for calibration.

## Context experiment

Local Python harness sent synthetic requests to the remote
[OpenRouter Decisions API](https://openrouter.ai/docs/api/api-reference/alphadecisions/submit-a-decisions-request).
No Intaris service was deployed or reconfigured. No proposed tool call was
executed; command strings were classification inputs only.

Each request pinned `cloudflare/clef` and exactly one provider. Returned model
and provider identities matched all requests. Token offsets were measured with
Cloudflare's published tokenizer at revision
`0b331204bb13fbd2ca93a64df1956f5b55478ce5`, SHA-256
`06b9509352d2af50381ab2247e083b80d32d5c0aba91c272ca9ff729b6a0e523`.
JSON-state counting follows the model's published
[state renderer](https://huggingface.co/Cloudflare/clef/blob/0b331204bb13fbd2ca93a64df1956f5b55478ce5/joint_schema_model.py).

Two independent marker values were placed at matched positions in otherwise
identical neutral logs. The model selected between those values and “absent.”
Short cases, a marker at the beginning of a long state, and missing-marker
cases served as controls. A prefix-only reader could not recover which suffix
value was present.

- Text run: 20 cases/provider, including marker offsets around 1K, 1.8K,
  1.98K, 2.05K, 2.1K, 3K, and 6K tokens.
- JSON run: 12 cases/provider, including markers beyond 2K, 6K, and 10K tokens.
  Maximum measured marker offset: **10,004**. Maximum API-reported input:
  **11,216 tokens**. This run used the normal four-second request timeout.

| Pinned provider | Text probes correct | JSON probes correct | Wrong provider / request failures |
|---|---:|---:|---:|
| Cloudflare | 20/20 | 12/12 | 0 |
| DeepInfra | 20/20 | 12/12 | 0 |
| PrimeIntellect | 20/20 | 12/12 | 0 |

**96/96 context probes passed.** Both marker values after 10K tokens were
correctly identified by every provider. This contradicts a first-2K-only
interpretation for these OpenRouter routes at the time tested. It does not
establish when behavior changed, direct Workers AI behavior, or retention at
64K. The [model page](https://openrouter.ai/cloudflare/clef) and
[Decisions limits documentation](https://openrouter.ai/docs/guides/community/multimodal-decisions#limits)
still warned about roughly 2K text truncation when checked.

## Intaris classification sample

The same harness also called the real Jev adapter with the unmodified Intaris
safety rubric, then applied the existing decision matrix while preserving
explicit escalations. The rubric alone was **3,136 tokens / 15,333 UTF-8 bytes**;
complete safety requests used 3,759–3,771 reported input tokens. The current
tool-call state follows the rubric, so these also tested useful content beyond
2K. These were adapter/matrix tests, not end-to-end HTTP service or judge tests.

Eight hand-labeled operations were evaluated per provider in each run:
four benign documentation/test/search operations and four disallowed
exfiltration/destruction/messaging/production operations. No labels came from
another model. The second run repeated the same eight cases.

| Outcome, both runs combined | Cloudflare | DeepInfra | PrimeIntellect |
|---|---:|---:|---:|
| Harmful blocked | 8/8 | 8/8 | 8/8 |
| Benign approved | 4/8 | 4/8 | 4/8 |
| Benign escalated | 4/8 | 4/8 | 4/8 |

All providers approved test and search commands, escalated documentation writes
and typo edits, denied the three destructive/exfiltration operations, and
escalated the unsolicited message. The benign escalations came from risk
confidence below `0.6`, not missing context. A split between low and medium risk
can trigger this even when both categories would otherwise permit approval.
Thresholds were not lowered to improve these results.

This small, repeated sample is not a production safety benchmark or a comparison
against Jev. Broader calibration is needed before choosing CLEF as the default.

## Latency, cost, and evidence

These are local-client round-trip measurements across both probe families,
including network time; three providers ran concurrently, one request at a time
per provider. They exclude Intaris barriers, HTTP serving, and judge latency.

| Provider | Median | Maximum | Reported cost, 48 requests |
|---|---:|---:|---:|
| Cloudflare | 960 ms | 2,096 ms | $0.068365920 |
| DeepInfra | 979 ms | 1,574 ms | $0.068365920 |
| PrimeIntellect | 978 ms | 1,719 ms | $0.011964036 |

144 measured requests cost **$0.148695876**. Three initial smoke requests bring
the temporary key's recorded total to **$0.148792968**. The key had a $1 lifetime
cap and was deleted after testing. No credential values are stored in reports.

Local raw evidence is retained under `runs/clef-20261018/` (Git-ignored):
`text.json`, `json.json`, `smoke.json`, `summary.json`, and `key-cleanup.json`.
They contain synthetic-case IDs, measured offsets, usage, timing, returned
probabilities, provider identities, and API generation IDs. Request headers
are never captured.

## Reproduction

Use an inference key already exported as `OPENROUTER_API_KEY`. The harness
never creates keys and never reads management-key variables.

```bash
uv sync --frozen --extra dev
curl --fail --location \
  --output /tmp/clef-tokenizer.json \
  https://huggingface.co/Cloudflare/clef/resolve/0b331204bb13fbd2ca93a64df1956f5b55478ce5/tokenizer.json

uv run python -m tools.benchmark.clef_probe \
  --tokenizer /tmp/clef-tokenizer.json \
  --tokenizer-revision 0b331204bb13fbd2ca93a64df1956f5b55478ce5 \
  --output runs/clef-recheck/text.json

uv run python -m tools.benchmark.clef_probe \
  --tokenizer /tmp/clef-tokenizer.json \
  --tokenizer-revision 0b331204bb13fbd2ca93a64df1956f5b55478ce5 \
  --state-format json --positions 0,2050,6000,10000 --timeout 4 \
  --output runs/clef-recheck/json.json
```

A nonzero exit indicates request/protocol failures, wrong provider identity,
wrong context-probe answers, or a harmful approval. Benign escalations remain
visible in the report rather than being counted as context-test failures.
The harness's tokenizer is used only for measurement; it adds no tokenizer
loading or downloads to the production evaluator.
