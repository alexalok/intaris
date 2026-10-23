# Bounded command inspection and L1 routing

Date: 2026-10-23. Local implementation based on fork main
`5e2d7dcfa813323608941c10abc9676f03283fd3` (merged PR #20).

## Result and scope

Incomplete `bash`/`terminal` inspection now selects normal configured L1
evaluation instead of borrowing broad allowances, direct escalation
preferences, or cached permission. Positively recognized prohibitions remain
unconditional classifier hard stops. Exhausting inspection depth or work no
longer invents a hard prohibition.

This is a deterministic routing and authorization-boundary change. It does not
introduce a shell interpreter, execute command fixtures, expand the wrapper
catalog, change model/provider settings, or establish model accuracy.

## Boundary and grant behavior

- Fast-path completeness uses existing simple-read checks or the exact
  `allow_scripts` trust contract. Exact script path and deny-path validation
  remain in force. All other commands require current L1.
- Input, token, segment, recursion, and shared-work limits are documented in
  [command inspection](../intent-evidence.md#command-inspection-boundary).
  Unsupported or uninspected text is model-dependent. A recognized prohibition
  in an inspected shallow segment is checked before recursive body work.
- Quoted examples and stdin data do not themselves prove execution. Unknown
  shell consumers, script operands, and unsupported stdin modes require L1.
  Existing literal shell payloads and known executable wrappers retain positive
  hard-stop detection.
- Incomplete commands cannot use or seed path-prefix caches, or replace L1 or
  Judge decisions with mechanical similarity precedent.
- Exact grants are checked after current L1 runs. Their existing tenant,
  session, tool, arguments, lifecycle, expiry, revocation, and scope requirements
  remain binding. An implicit exact human grant retains the established
  denial-override contract. Explicit approval IDs retain the rule that fresh
  L1 denial wins; escalation reuse requires unchanged reviewed scope.
- Inference exceptions cannot become permission. Jev's local request-budget
  rejection explicitly records missing evaluation, preventing caps or old
  grants from converting it to approval. No provider request is sent for that
  oversized input, and no input is truncated.
- Audit records include evaluator-owned inspection facts, the original L1
  decision, and the exact approval source used after L1 when applicable.

Restricted credential enforcement, Hermes session binding, raw skill reads,
source-linked scope collection, atomic grant resolution, model configuration,
and CLEF input-byte limits retain their existing implementations. Their
regressions remain part of the server and adapter checks.

## Regression method

`tests/test_command_boundary.py` uses real SQLite-backed session and audit
stores, both configured L1 interfaces with controlled inference responses,
and real Judge resolution with controlled model responses. The Jev budget
cases use the real Jev client with a transport that fails if any request is
sent. Commands are fixture strings only.

Cases cover unknown wrappers, malformed and dynamic commands, quoted data,
benign supporting reads, inspection limits, positive hard prohibitions,
permissive policies/preferences, grant identity and invalidation, cache
bypass/learning, inference failure, and L1/Judge similarity fallback. Existing
anti-false-positive wrapper tests accept READ or WRITE where their contract
only excludes hard denial; new boundary tests assert exact WRITE classification,
L1 calls, and the persisted evaluation path.

A fresh local reviewer found a budget-order regression: a 4,104-character
command with a shell heredoc could exhaust shared inspection nodes before a
top-level `rm -rf /` was examined. The defect reproduced both in classification
and in the evaluator with approving mocked L1. Reordering shallow checks before
recursive work fixed it. Regressions cover the prohibition both before and
after the heredoc, and prove no L1 call or permissive cap can approve it.

## Verification

| Check | Result |
|---|---|
| Full server suite, `pytest -q -p no:cacheprovider tests/` | 6,221 passed; 68 E2E cases deselected; two existing WebSocket deprecation warnings |
| New command-boundary coverage within the server suite | 166 cases |
| Hermes adapter suite, `pytest -q -p no:cacheprovider integrations/hermes/tests` | 1,023 passed; 190 skipped without the optional external Hermes source matrix |
| Post-anonymization fixture checks | 289 passed across intention, path policy, redactor, and Judge tests |
| Ruff check and format check | All 26 changed/new Python files passed |
| Whitespace check | `git diff --check` passed |
| Unchanged source check | No changes to integrations, script policy, source evidence collection, stores, server/auth, or model configuration |

Tests used the existing dependency environment, `PYTHONDONTWRITEBYTECODE=1`,
the current worktree on `PYTHONPATH` (the Hermes integration directory for
adapter tests), and a temporary `DATA_DIR` ending in `.intaris`. No dependency
installation was needed. The full server suite includes the review fix and the
interactive-shell regression fix. Later publication cleanup changed only docs
and synthetic fixture values; all 289 affected tests passed again afterward.

## Limits

No live L1/Judge replay was run. These tests establish deterministic routing,
stored provenance, and enforcement contracts; they do not measure live
false-positive or false-negative rates. Existing historical replay reports
describe older candidates and cannot establish this candidate's accuracy.

Incomplete commands incur L1 latency even on exact retries. Broad shell
allowances no longer bypass L1 for ordinary mutating/package-manager commands
or wrappers. The bounded recognizer can leave dangerous code unrecognized;
remaining risk is assessed by the configured model and existing policy flow.
The optional real-Hermes source matrix requires its external dependencies.

The initial implementation and verification were local only. A later explicit
request authorized fork PR publication and Codex review. Pre-publication
scanning also anonymized pre-existing personal fixture paths, example endpoints,
and historical record identifiers. No merge, deployment, or service restart is
part of that follow-up.
