# Native Telegram Escalations Implementation Plan

**Goal:** Deliver Intaris human-required approvals inline through the existing Hermes Telegram bot, preserving exact session/profile/topic identity, with an operator-configured fallback.

**Architecture:** Hermes owns presentation and authenticated Telegram updates. Intaris owns durable, bounded approval leases and decisions. A local Unix socket accepts requests only from the attested gateway process (kernel peer UID/PID plus process start time); agent subprocesses and ordinary agent HTTP credentials cannot approve. No additional bot poller, bot token, or administrative API key is introduced.

**Tech stack:** Existing Python/asyncio, SQLite/PostgreSQL, Hermes plugin hooks, python-telegram-bot already installed by Hermes.

**Approved scope:** User's handoff and explicit clarification require existing Hermes bot and native inline prompts. Local implementation, tests, documentation, two fresh Astra medium reviews and fresh findings verification. Subsequent PR-loop request authorizes scoped commits, push, PR publication, and Codex/Bugbot reviews. No merge, deploy, service restart, credential changes, or real messages in this task.

## Trust and lifecycle contract

- Operator configuration lives on the isolated Intaris service. It maps an attested gateway and absolute profile home to one tenant/agent, explicit Telegram approver IDs, and optional fallback chat/topic.
- Root/Intaris-owned PID attestation contains gateway PID and Linux `/proc/PID/stat` start time. Gateway UID differs from Intaris service UID. No keys placed in agent configuration.
- Gateway origin uses admitted source, exact Hermes session lookup, explicit child-parent hooks, and transport profile identity. Model-supplied destinations and session heuristics are ignored.
- Origin actor must be explicitly allowed. Origin prompt binds only that actor; fallback uses configured approvers. Callback also binds bot connection, chat, topic, message, profile, session, call, random lease, and deadline.
- One durable lease per pending call. Uncertain sends are not retried. Lost/expired/cancelled leases cannot approve. Native callback never executes tools; existing Intaris audit polling and invocation cancellation checks remain authoritative.
- An explicit Telegram topic rejection can switch an undelivered lease once to the operator-configured fallback. The lease, deadline, and invocation remain unchanged; callbacks bind the new destination and its configured approvers.
- Intaris resolution uses an atomic pending-only guard. Telegram actions cannot override decisions from UI or judge.
- Missing route/transport leaves the existing bounded UI approval wait. Notification failure never grants permission.
- Strict transport support targets the verified Hermes revision and Linux deployment. A compromised gateway process remains a trusted-host compromise; the socket specifically rejects tool subprocesses, not arbitrary code already running inside the gateway process.

## Tasks

- [x] Fix judge deferral/error notification suppression under default `deny_only`, with regression tests.
- [x] Add operator configuration parser, protected PID attestation and bounded Unix protocol. Test invalid/foreign/agent peer identities and profile isolation.
- [x] Add durable leases and pending-only decisions, expiry/cancellation, exact callback identity, deduplication, and race tests.
- [x] Add existing-bot native plugin transport and trusted origin/child correlation. Test origin/topic/fallback/no route, callback authorization, failure, late send, and cancellation.
- [x] Connect native presentation to existing human-wait lifecycle without changing final dispatch authority. Run all adapter regression tests with pinned Hermes contracts.
- [x] Document protected socket/PID/profile configuration and operational limits; run server suite, lint, independent reviews, fixes, and final verification.

## Review focus

Concurrent calls in one topic; shared bot across runtime profiles; stale callback after UI resolution or session stop; delivery timeout followed by late send; gateway restart/PID reuse and agent child impersonation. Each must fail closed without duplicate execution.

## Verification results

- Server suite: 2,677 passed; 68 external E2E cases deselected.
- Hermes adapter suite: 799 passed with the pinned host source. The focused native
  presentation/lifecycle suite passes all 85 tests, including fallback delivery.
- PR follow-up tests cover portable socket paths, bounded origin/child routing
  caches, and event-buffer persistence after native shutdown error/cancellation/timeout.
- Ruff and diff checks pass. Before the fallback follow-up, two fresh scoped reviewers found no
  remaining actionable defects after fixes. A separate fresh verifier confirmed closure
  of all six review/self-review findings with 19 targeted passing tests.
- Verification is local. Linux peer authentication uses mocked kernel
  credentials in tests; live Linux/Telegram delivery remains untested.
- No deployment, service restart, or real Telegram message was performed.
