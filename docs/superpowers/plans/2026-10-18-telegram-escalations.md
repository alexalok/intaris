# Native Telegram Escalations Implementation Plan

**Goal:** Deliver Intaris human-required approvals inline through the existing Hermes Telegram bot, preserving exact session/profile/topic identity, with an operator-configured fallback.

**Architecture:** Hermes owns presentation and authenticated Telegram updates. Intaris owns durable, bounded approval leases and decisions. A local Unix socket accepts requests from configured Unix UIDs, including their tool subprocesses, for explicitly mapped profiles. Ordinary agent HTTP credentials cannot approve. This trusts the Hermes user rather than isolating it from its tools. No additional bot poller, bot token, or administrative API key is introduced.

**Tech stack:** Existing Python/asyncio, SQLite/PostgreSQL, Hermes plugin hooks, python-telegram-bot already installed by Hermes.

**Approved scope:** User's handoff and explicit clarification require existing Hermes bot and native inline prompts. Local implementation, tests, documentation, two fresh Astra medium reviews and fresh findings verification. Subsequent PR-loop request authorizes scoped commits, push, PR publication, and Codex/Bugbot reviews. No merge, deploy, service restart, credential changes, or real messages in this task.

## Trust and lifecycle contract

- Operator configuration lives on the isolated Intaris service. It maps a configured gateway UID and absolute profile home to one tenant/agent, explicit Telegram approver IDs, and optional fallback chat/topic.
- Gateway UID differs from Intaris service UID. Socket directories and profile configuration remain root/Intaris-owned. No PID attestation or decision keys are needed in agent configuration.
- Gateway origin uses admitted source, exact Hermes session lookup, explicit child-parent hooks, and transport profile identity. Model-supplied destinations and session heuristics are ignored.
- Origin actor must be explicitly allowed. Origin prompt binds only that actor; fallback uses configured approvers. Callback also binds bot connection, chat, topic, message, profile, session, call, random lease, and deadline.
- One durable lease per pending call. Uncertain sends are not retried. Lost/expired/cancelled leases cannot approve. Native callback never executes tools; existing Intaris audit polling and invocation cancellation checks remain authoritative.
- An explicit Telegram topic rejection can switch an undelivered lease once to the operator-configured fallback. The lease, deadline, and invocation remain unchanged; callbacks bind the new destination and its configured approvers.
- Intaris resolution uses an atomic pending-only guard. Telegram actions cannot override decisions from UI or judge.
- Missing route/transport leaves the existing bounded UI approval wait. Notification failure never grants permission.
- Transport support targets the verified Hermes revision and Linux deployment. Every process running under a configured gateway UID is trusted to submit approval actions; the bridge does not authenticate a real Telegram click against a malicious local Hermes user.

## Tasks

- [x] Fix judge deferral/error notification suppression under default `deny_only`, with regression tests.
- [x] Add operator configuration parser, kernel UID checks and bounded Unix protocol. Test invalid/foreign UID identities and profile isolation.
- [x] Add durable leases and pending-only decisions, expiry/cancellation, exact callback identity, deduplication, and race tests.
- [x] Add existing-bot native plugin transport and trusted origin/child correlation. Test origin/topic/fallback/no route, callback authorization, failure, late send, and cancellation.
- [x] Connect native presentation to existing human-wait lifecycle without changing final dispatch authority. Run all adapter regression tests with pinned Hermes contracts.
- [x] Document protected socket/UID/profile configuration and operational limits; run server suite, lint, independent reviews, fixes, and final verification.

## Review focus

Concurrent calls in one topic; shared bot across runtime profiles; stale callback after UI resolution or session stop; delivery timeout followed by late send; gateway restart/PID reuse and foreign-UID impersonation. Each must fail closed without duplicate execution.

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

## Shared-bot background fallback follow-up (2026-10-20)

The user approved explicitly mapping runtime profiles to an existing shared bot
for background approvals. `fallback_transport_profile` now names an absolute
bot-owning profile home in the same configured gateway. The authenticated socket
returns this operator policy before native transport selection; missing or
ambiguous bindings leave the bounded UI wait. Runtime tenant, agent, destination,
approvers, and callback ownership remain scoped to the requesting profile.
Correlated Telegram sessions keep their receiving transport. Separate-process
cron workers still require a worker-to-gateway relay and remain out of this
mapping change's scope.

- Reproduced missing shared-bot prompts before the fix, then verified mapped cron
  and webhook sessions and their callbacks, mapping precedence, invalid/foreign
  mappings, ambiguous/missing bots, origin preservation, and cancellation during
  lookup.
- Full verification: 2,687 server tests passed (68 external E2E cases deselected)
  and 810 Hermes adapter tests passed against the same pinned host revision.
  The first server run used a `DATA_DIR` without `.intaris`, failing
  `TestConfigDefaults.test_db_defaults`; correcting that test environment made
  the complete rerun pass. No product change was needed for that failure.
- Ruff and diff checks passed; a fresh independent review found no actionable
  issues. Live deployment and Telegram delivery remain untested.

## Codex and Bugbot follow-up (2026-10-20)

Both bots completed review of the shared-bot mapping commit. Five confirmed
findings were reproduced before fixing:

- Idle sessions and parents now keep native approval leases until the invocation
  deadline; completed, suspended, and terminated sessions still retire them.
- Telegram General-topic sends omit the thread parameter; delivery and callback
  checks accept only the equivalent absent/1 representations of General.
- Call-scoped approvals are excluded from later evaluator, JEV, and judge
  histories, including prior judge outcomes. Raw audit records remain intact.
- Socket startup captures an unpublished inode and permissions before atomic
  publication, cleans identified sockets after failure/cancellation, and preserves
  foreign replacements. Unknown initial metadata failures use at most four
  private staging slots, requiring operator cleanup if those slots fill.
- Socket admission rejects unconfigured UIDs before frame reads and caps
  admitted connections/backlog at 32, then rechecks profile authorization after
  framing.

Final local verification: 2,723 server tests passed (68 external E2E cases
deselected), 815 Hermes adapter tests passed, and Ruff/diff checks passed.
Actual Unix socket publication/connect/cleanup ran on macOS; Linux peer
credentials and Telegram delivery remain mocked. No deployment or live messages.

## Deadline and retention review follow-up (2026-10-20)

Bugbot passed commit `a0e6854`; Codex identified three further lifecycle findings.
Each was reproduced and fixed:

- Native profile disposal shares the existing teardown deadline across all lease
  closes. Local callbacks retire even when the remaining IPC budget is exhausted;
  actual Unix-socket tests verify the earlier aggregate deadline is enforced.
- Terminal leases with durable tenant/call audit verdicts are purged one hour
  after their original deadline. Unfinished withdrawals remain recoverable, raw
  audit history remains intact, and late requests cannot recreate a settled call.
- Telegram send/edit/acknowledgement operations use the pinned Hermes
  `agent.deadline.run_bounded_async` primitive with an eight-second cap.
  Cancellation-shielded I/O is abandoned without waiting indefinitely; late
  messages and button updates trigger withdrawal rather than becoming actionable.

Verification: 2,734 server tests passed (68 external E2E cases deselected) and
822 Hermes adapter tests passed. After making local callback invalidation
immediate on delivery failure, all 105 native tests passed again. The deadline
regressions execute the real pinned Hermes primitive. Ruff and diff checks pass.
No deployment or live Telegram message was performed.

## Legacy wrapper compatibility follow-up (2026-10-20)

Bugbot passed `f87ad10`; Codex identified two existing mixed sync/async wrapper
parametrizations failing without the pinned host source. Both failures reproduced.
Legacy immediate evaluations now retain their worker interruption and shared
session/lifetime checks across wrapper threads. Cross-thread human waits and
native callbacks still require the owner-thread API; a missing API fails closed.

Verification: 776 adapter tests passed with 51 host-contract skips using legacy
doubles, and all 827 passed against the pinned Hermes source. Five added
regressions cover immediate approval, interruption, session end, invocation
closure, and rejection of unsupported cross-thread human waits. Ruff and diff
checks pass. Server code is unchanged from its 2,734-test passing run.

## Attestation removal (2026-10-21)

The user chose to trust the existing Hermes Unix user, including its writable
gateway and tools. Removed PID/start-time attestation, its privileged watcher,
helper, and lifecycle tests. The bridge now checks kernel peer UID and explicit
profile mapping; other users and forged identity fields remain unauthorized.
Same-UID subprocesses are trusted and can submit approval actions. Old
`pid_file` config requires explicit migration so upgrades cannot silently
broaden the trust boundary. Retained socket permissions, bounded admission,
operator routing, callback bindings, lease expiry, and approval-note behavior.
Canonical cron presentation remains a separate companion PR.
