# Command parsing boundary implementation plan

> **For agentic workers:** Use superpowers:executing-plans. The supplied task authorizes this design and local implementation without another design gate.

**Goal:** Send commands without a bounded fast-path proof through the configured L1 evaluator, without confusing uncertainty with a hard prohibition.

**Architecture:** Keep the existing positive hard-prohibition recognizer. Add an explicit inspection result with independent completeness and prohibition fields. Completeness is deliberately limited to existing simple read checks and exact script grants; recognizing a wrapper for a prohibition does not certify it for permission.

**Tech Stack:** Python, existing standard-library shell tokenization, SQLite-backed tests and mocked external inference. No new dependencies.

**Spec:** The authorized command-boundary task, plus the existing contracts in `docs/intent-evidence.md` and `intaris/script_policy.py`.

## Global constraints

- Initial scope was local implementation, tests, and documentation only. The subsequent explicit `pr-loop` request authorizes committing, pushing to the fork, opening a ready PR, and iterating on Codex feedback. No merge, deployment, or service restart is authorized.
- Preserve positive hard prohibitions, source-linked scope, exact grant identity and lifecycle, restricted authentication, Hermes session binding, CLEF provider and input limits, and raw skill reads.
- No full shell interpreter or expanding wrapper catalog. Literal quoted data is not execution.
- Uncertainty must reach normal L1, not the classifier's direct approval-queue shortcut. Inference failure never grants permission.

## Review focus

- Incomplete commands masked by broad allow patterns or tool preferences.
- Exact retries, explicit approval IDs, caps, and similarity precedent overriding current assessment.
- Oversized simple reads bypassing inspection through the path cache.
- Quoted shell examples and skill contents becoming false hard prohibitions.
- Budget exhaustion hiding a positively recognized prohibition in another inspected segment.

### Task 1: Bounded inspection and classifier boundary

**Files:** `intaris/classifier.py`, `tests/test_command_boundary.py`, `tests/test_shell_depth.py`, existing classifier tests.

**Interfaces:** Produce `CommandInspection` and `inspect_command(tool, args, session_policy=...)`; classification may consume the already-computed inspection internally.

- [x] Add failing regressions for unknown wrappers, dynamic/incomplete forms, broad permissions, safe reads, exact scripts, and recursion/size/work exhaustion.
- [x] Add independent `complete` and `critical` results; retain positive detection and stop on bounded work. Require completeness before permissive classifier shortcuts.
- [x] Verify focused classifier and hard-prohibition suites; update only expectations intentionally superseded by the boundary.

### Task 2: Current evaluation and grant boundaries

**Files:** `intaris/evaluator.py`, `intaris/judge.py`, `intaris/decision.py`, `intaris/jev.py`, `tests/test_command_boundary.py`.

**Interfaces:** Consume Task 1 inspection once per evaluation; keep all existing scope, identity, expiration, and atomic-resolution checks.

- [x] Reproduce fast-path approval reuse and cache bypasses with real stores and mocked LLM/Jev.
- [x] Require L1 for incomplete commands before grant decisions; disable mechanical similarity overrides and cache learning for incomplete commands. Preserve valid exact-grant scope contracts.
- [x] Test successful, denied, escalated, and failing inference; current/ancestor restrictions; unchanged deterministic prohibitions and exact-script behavior.

### Task 3: Documentation and verification

**Files:** `docs/intent-evidence.md`, a dated evaluation report, this plan.

- [x] Document actual supported fast paths, inspection budgets, retry semantics, and model-dependent limitations.
- [x] Run the full server suite, scoped Ruff checks, and whitespace checks; verify untouched integration/security files.
- [x] Perform one fresh local code review and address substantiated findings with regressions. No external review loop.

## Execution ledger

- Baseline fork main verified at `5e2d7dcfa813323608941c10abc9676f03283fd3`.
- Baseline server suite: 6,054 passed, one environment-dependent config failure. Setting the temporary DATA_DIR to a `.intaris` directory makes that test pass; no source change needed. 68 E2E cases excluded; two existing WebSocket warnings.
- Pre-flight: Task 2 consumes Task 1 completeness; both classifier and evaluator must gate shortcuts. Judge similarity fallback also needs this boundary.
- Ruling: Use existing read/script proofs rather than a new wrapper grammar. Other commands may incur more L1 calls; this is deliberate conservative routing, not a claim that their behavior is prohibited.
- Ruling: Preserve the exact-grant contract after L1, including implicit human denial overrides. Requiring L1 approval itself would break retries for human-approved calls. The cost is fresh inference on uncertain retries; current source identity and scope checks still decide whether a grant can apply.
- Ruling: Extend the internal decision result with `evaluation_complete` for Jev's local input-budget rejection. A real-client regression reproduced caps/old grants converting missing inference into permission; the new state prevents that without changing provider settings or byte limits.
- Existing pending-approval tests now supply controlled L1 responses because uncertain commands no longer use preference-only escalation. Security assertions for tenant, restricted role, exact identity, lifecycle, and policy remain in force.
- Existing wrapper anti-false-positive tests retain their no-hard-denial contract; dedicated boundary tests pin WRITE, inference call counts, and audit paths. No new wrapper catalog was added.
- Fresh local review found one P1: heredoc recursion depleted the shared node budget before shallow hard checks. Two regressions failed before the fix; both now pass, with four additional evaluator checks proving deterministic denial and no inference/cap bypass.
- Follow-up stdin checks distinguish scripts, help/no-exec, and unknown consumers from proven shell execution. The full suite caught implicit `chroot` using `sh -i`; recognized interactive stdin was restored without relaxing its original hard-stop assertions. Focused review/fix suite: 514 passed.
- Lint and format checks pass for all 22 changed/new Python files. Formatting preserved their ASTs. Integration sources, script policy, scope collection, stores, server/auth, and configuration sources remain unchanged.
- Hermes adapter suite: 1,023 passed, 190 skipped without the optional external Hermes source matrix. No live model accuracy measurement or remote mutation was performed.
- Initial final server suite: 6,221 passed, 68 E2E cases deselected, two existing WebSocket deprecation warnings. Includes 166 new command-boundary cases. Ruff check/format and whitespace verification passed. At that point changes remained local and uncommitted on `alex/command-parsing-boundary`.
- Publication follow-up: the user selected Codex only for `pr-loop`. Full projected-tree scanning found pre-existing personal fixture paths, private example endpoints, and private record identifiers in historical reports. Replaced those with synthetic equivalents, retaining fixture path lengths, depth, and scope relationships. Private automation and the ownership marker are excluded from publication.
- Publication verification: 314 projected public files scanned; suspicious secret matches were synthetic redactor fixtures. All 289 affected fixture tests passed after anonymization; all 26 changed/new Python files passed Ruff check/format. No unrelated files are staged.
