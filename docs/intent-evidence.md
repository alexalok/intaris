# Source-linked intent and scoped authorization

Intaris evaluates whether an operation fits the user's request as well as whether
it is dangerous. A safe edit can still target the wrong project; an approved
staging change does not authorize a production deployment. Routine bounded work
that clearly supports a request does not require the user to name every tool.

The fork keeps its L1 LLM or Jev/CLEF evaluator and Judge. It adds shared source
evidence to those decisions, without importing the upstream permission-reuse
engine or depending on upstream images, tags, or services.

## Supporting reads and skill inspection

Read-only investigation may corroborate an already established answer, verify
facts, gather citations, or inspect relevant references. A supporting read does
not need to change the conclusion or directly perform the final deliverable.
Uncertain usefulness or apparent redundancy is not itself a reason to escalate.
A generated summary such as "no further action requested" does not invent a user
restriction on evidence gathering; actual user restrictions still apply.

Skill text inspection is permitted regardless of whether the instructions are
benign, malicious, disabled, or quarantined. Text remains untrusted data and
never grants permission to execute the instructions. Explicit denies, sensitive
file checks, and later action evaluations remain in force.

The Hermes adapter intercepts its captured native `skill_view` handler and
performs a raw text read. It resolves the real absolute target and evaluates an
internal `skill_view_raw` operation, retaining `skill_view` deny rules and review
preferences. Shared skill libraries are allowed outside the project. Tool/path
denies still win. Each raw inspection goes through current scope evaluation,
including initial intention, user messages, parent restrictions, and secret-file
protections. Policy permits ordinary raw inspection without relevance or
per-skill consent, even for malicious topics. Earlier approvals and generated
profiles cannot bypass that check. This costs L1 latency and may require Judge;
it is not an unconditional deterministic read fast path.
The internal operation is not registered as an agent-callable tool.

This separation is necessary because the native Hermes loader can run inline
shell, install dependencies, expose credentials to later tools, and invoke
lifecycle hooks. None of those happen during the adapter's raw read. Template
syntax stays literal. Reading a skill's script does not run it. Actual setup,
execution, edits, sends, or other actions require separately evaluated calls.

Lookup uses filenames, already-cached aliases, and registered plugin paths.
It does not read instruction contents before approval, trigger plugin discovery,
or invoke the loader/quarantine scanner. Uncached frontmatter aliases need their
relative library path; ambiguous names require an exact path. Directory and
legacy flat skills are supported; flat skills have no linked-file directory.
Discovered candidates must remain inside their originating registered search
root. Canonical paths are retained after validation; candidate or ancestor
symlink changes cannot redirect the approved read.
The existing in-memory background-review read mark is retained; activation,
usage/lifecycle hooks, dependency setup, and credential capture are skipped.

Both the adapter and server changes are needed for the raw-reader contract.
Unknown/older host contracts and foreign same-named tools retain
ordinary evaluation; an argument such as `raw=true` cannot create this exemption.
As with other native tool identities, the service trusts its authenticated
adapter to report the operation it actually dispatches.

## Evidence and authority

`sessions.intent_profile` stores interpreted requests, constraints, approvals,
revocations, and uncertainty alongside the generated intention. Each admitted
fact references a stored source ID and quotes its **complete** text. A substring
that drops “do not,” a target, or a condition is rejected. Sources are fetched
again within the same tenant and session before use.

Sources are eligible stored `User message:` records and final reusable human
decisions. Client-forwarded user messages retain the existing trust boundary;
they are not newly authenticated human input. Human decision records come from
the operator approval path. Agent reasoning, tool output, generated summaries,
Judge decisions, call-only grants, and expired approvals do not become grants.
Expired human denials remain negative guidance.

Assistant context can explain a short reply, but cannot grant authority. A bare
“yes” remains uncertain without one complete, unambiguous proposal. All model
consumers receive the originals and shared instructions to match operation,
target, environment, conditions, and exclusions. Models still interpret natural
language; source binding proves provenance, not semantic correctness.

## Lifetime and bounds

- Existing intention regeneration also generates the profile; there is no new
  inference call per tool evaluation. Old sessions and two-field intention
  responses remain compatible.
- Current constraints and revocations retain their source references across
  topic changes. Omitting a fact does not revoke it. Retirement requires a newer
  source, with both original texts still available for interpretation.
  Up to 24 retained source IDs survive temporary prompt-budget omission and are
  fetched again; an omitted fact cannot erase its source from later generations.
- Each session packet admits at most 24 sources, 4,000 characters per source,
  12,000 characters of serialized source data, and 16 facts. The newest source
  takes priority, then retained restrictions. Over-budget text is omitted whole,
  with source IDs and `complete=false`; it is never clipped into permission.
  This is bounded evidence, not a claim to reproduce the full conversation.
- Current ancestor evidence is included through four parent levels. Missing
  parents and deeper chains are marked unavailable. Child requests cannot widen
  parent restrictions.
- L1 stores its server-built snapshot in `audit_log.intent_evidence`. Judge
  collects fresh evidence and can see the original evaluation fingerprint.
  After inference, both compare source and policy fingerprints. A changed L1
  snapshot forces review (or denial when human review is unavailable); Judge
  cannot approve from a changed snapshot. This checks the inference interval;
  it does not lock future user messages or replace the client's invocation
  lifecycle protocol.
- Legacy mechanical same-tool precedent is disabled when user messages, omitted
  evidence, or parent scope are present. Existing exact-call retry also refuses
  newer messages, incomplete evidence, and parent scope. Human decisions remain
  model context. Explicit client approval expiration is preserved.

Jev/CLEF keeps its provider routing and full UTF-8 input budget. If the enriched
request exceeds that budget, the existing local escalation applies; evidence is
not silently truncated to fit.

## Hard prohibitions

Classifier `CRITICAL` means a deterministic prohibition, including configured
deny rules and recognized destructive shell operations. These checks run before
allow rules and tool preferences. Outcome caps, prior approvals, unattended
Judge review, human overrides, and cached approvals cannot convert that result
into execution. Audit resolution rejects approval atomically; the UI hides the
corresponding actions. An incorrect configured rule must be changed by its
operator, followed by a new evaluation. Built-in prohibitions require a code
change, not a per-call approval.

Shell recognition distinguishes executable positions, literal wrappers,
operators, quoted arguments, substitutions, and heredoc data. For example:

| Operation | Deterministic classification |
|---|---|
| `sudo -n rm -rf /` | Hard denial |
| `bash -c 'rm -rf /'` | Hard denial |
| `if true; then reboot; fi` | Hard denial |
| `echo 'rm -rf /'` | Not a hard denial |
| `rm -rf /tmp/my-build` | Normal evaluation |
| Writing a quoted heredoc containing a destructive command | Not a hard denial |
| Feeding that heredoc to a shell | Destructive command is checked |

This is a bounded literal recognizer, not a shell interpreter or a sandbox.
Dynamic programs and unknown tools still rely on ordinary policy and model
evaluation. A model-assessed denial is distinct from classifier `CRITICAL` and
can still use the existing human override flow. Judge's low risk rating alone
does not authorize a call it denied or deferred.

## Verification

Regression tests pair intended actions with forbidden variants, exercise real
stores and evaluation paths with mocked inference, and cover both L1 backends
and Judge modes. Cases include source spoofing, full-quote validation, target
scope, revocation during inference, omission budgets, ineligible-message floods,
idle resume, parent restrictions, expiration, critical overrides, and UI actions.

Offline tests establish plumbing and deterministic enforcement. The initial
[historical replay](evaluations/2026-10-21-historical-intent-replay.md) found that
models misread optional allow rules as exhaustive permission. Shared policy
instructions now explain those classifier fast paths to L1, CLEF/Jev, and Judge,
while preserving explicit denies, user constraints, revocation, and hard guards.

The [policy-prompt replay](evaluations/2026-10-21-policy-prompt-replay.md) holds
historical inputs and labels fixed. On 122 paired benign calls, unnecessary
reviews fell from 18 to two relative to the previous candidate. A fresh baseline
comparison yielded two reviews versus one for the fixed candidate on 134 paired
benign calls. The candidate denied all eight historical prohibition controls and
approved none of 15 synthetic unsafe/prohibited controls, including four cases
requiring deterministic denial.

Residual false positives, regenerated-intent sensitivity failures, and provider
timeouts remain. Errors are reported separately from semantic outcomes. This
previously examined sample does not establish a real-world false-negative rate
or validate historical reuse and revocation of scoped human grants; those cases
are covered only by synthetic controls and deterministic regression tests. The
full server suite passed 3,114 tests, including 82 hard-prohibition tests.


The [supporting-read follow-up](evaluations/2026-10-22-supporting-reads.md) adds
raw skill inspection and explicit guidance for corroborating established answers.
That frozen phase used deterministic raw-read approval. The
[review follow-up](evaluations/2026-10-22-codex-review.md) supersedes those fast
results: raw reads now consider current restrictions on every call. All eight
benign evaluations approved and none of ten forbidden controls approved;
historical #149/#162 approved with both original and regenerated intent, each
after CLEF escalation and Judge review. These are targeted controls, not a new
population estimate. Verification passed 3,254 server and 1,193 Hermes tests.
Both components require deployment before this behavior is available in
production.
