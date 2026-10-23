# Rich Intent and Scoped Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Preserve source-linked user scope without letting contextual approval bypass hard prohibitions.

**Architecture:** Keep the fork's decision engines. Add a shared, bounded evidence packet and persist generated intent separately from source authority. Enforce deterministic prohibitions before any permissive path.

**Tech Stack:** Python 3.11+, existing SQLite/PostgreSQL store, existing LLM and Jev/CLEF clients, pytest.

**Spec:** ../specs/2026-10-21-rich-intent-authorization-design.md

## Initial implementation constraints

- No upstream hybrid engine or permission-reuse cache.
- No new dependencies, paid provider calls, remote writes, deployment, or checkpoint merge.
- Preserve redaction, tenant/session isolation, provider input budgets, approval expiry and request floors.
- Work only in the owned feature worktree; preserve the main checkout's pending workflow docs.

## Review Focus

- Quoted root paths and shell wrappers must not evade prohibition; prose containing commands must not be blocked.
- Missing, forged, or expired sources must not establish scope.
- New user restrictions during inference must invalidate an earlier approval assessment.
- Repeated background reasoning must not displace user constraints.
- Ambiguous confirmations and same-tool/different-target calls must not gain blanket authorization.

### Task 1: Deterministic hard prohibitions

**Files:** classifier.py, evaluator.py, audit.py, judge.py, tests/test_hard_prohibitions.py and affected existing tests.

**Interfaces:** classifier CRITICAL is non-overridable; audit resolution refuses approval of a critical record atomically.

- [x] Add paired literal command/prose cases and cap/retry/Judge/human-resolution cases.
- [x] Run `pytest tests/test_hard_prohibitions.py -q`; expect failures demonstrating existing bypasses.
- [x] Detect executable critical commands before allow rules, retain critical denial through caps/retries, and guard audit resolution/Judge.
- [x] Run focused classifier/evaluator/API/Judge tests; expect pass after updating intentional override expectations.

### Task 2: Source-linked intent

**Files:** new intaris/intent_evidence.py; intention.py, session.py, audit.py, db.py; tests/test_intent_evidence.py.

**Interfaces:** `collect_intent_evidence(session, audit)` returns a bounded server packet; generated profile facts bind to exact source IDs and complete source quotes.

- [x] Add tests for source isolation, full quotes, ineligible messages, agent text, oversized sources, source expiry, persistence, and stale updates.
- [x] Run new tests; expect failures for missing behavior.
- [x] Add shared source collector/validator, dedicated session profile and audit evidence storage, and same-call generation.
- [x] Run intention/store tests; expect pass without weakening stale-write guards.

### Task 3: Consumer integration and scope regressions

**Files:** evaluator.py, prompts.py, judge.py, jev.py; tests/test_intent_authorization.py; product docs.

**Interfaces:** all model consumers receive source evidence separately from untrusted context, with a freshness check before approval.

- [x] Add paired scoped-target tests for LLM/CLEF/Judge, spoofed context, revocation during inference, and compatibility with old sessions.
- [x] Run new tests; expect missing evidence/freshness failures.
- [x] Integrate evidence and scope instructions, preserve audit snapshot, and prevent permissive postprocessing from bypassing evidence failures.
- [x] Run full offline server suite and relevant Hermes tests, lint, and diff checks; expect green.
- [x] Document semantics and offline validation limits; obtain one fresh whole-change review and fix substantive findings.

The initial implementation remained local. Subsequent user requests authorized
historical inference, prompt corrections, supporting-read changes, and PR publication.
Merge, deployment, and upstream checkpoint creation remain outside this PR task.

## Initial implementation validation

- Offline server suite: 3,114 passed; 68 live-backend tests deselected.
- Hermes adapter suite: 886 passed; 121 optional runtime-dependent tests skipped.
- PostgreSQL 17 disposable database: source eligibility, profile/evidence persistence,
  hard-denial resolution, and idempotent migrations passed. Test DB stopped.
- Ruff lint and formatting, Git whitespace checks, and changed-document local links passed.
- Whole-change review findings were reproduced with failing regression tests and fixed:
  wrapper/control syntax, literal heredocs versus executable input, pipe versus sequence,
  fresh revocations versus old precedent, incomplete evidence, ineligible-message floods,
  and idle-resume fingerprints. Additional checks cover permissive Judge policy,
  nested substitutions, durable restriction references, and legacy derived grants.
- This initial implementation stage used offline checks. Later historical and focused
  inference results are recorded in the evaluation reports linked below.
- Branch: `alex/rich-intent-authorization`.


## Follow-up validation and PR preparation

- [Historical replay](../../evaluations/2026-10-21-historical-intent-replay.md)
  exposed over-strict interpretation of optional allow rules.
- [Policy-prompt correction](../../evaluations/2026-10-21-policy-prompt-replay.md)
  reduced unnecessary final reviews while preserving hard prohibitions.
- [Supporting-read follow-up](../../evaluations/2026-10-22-supporting-reads.md)
  permits corroborating evidence and adds raw Hermes skill inspection without
  activation; later actions retain separate evaluation.
- PR preparation incorporates current fork main
  `3f7a6d6039c181653ddc1ab18c9b154adc409461`. Full server and Hermes adapter
  checks are rerun on the combined tree before publication. Historical reports
  retain their original inputs, model results, and revision boundaries.
- Combined-tree verification passed 3,181 server tests (68 external E2E tests
  deselected) and 1,187 Hermes adapter tests. Adapter checks used Hermes fork
  source `e4ee1687a6f799b7f21f2b173138f910e862ee94`, including canonical cron
  approval APIs. Scoped Ruff lint/format and Git whitespace checks passed.
- The inherited cron fixture now removes collection-time legacy `tools` stubs
  before importing the real host package, matching the existing profile fixture.
  The fixture regression passed 294 tests before the full adapter rerun.
