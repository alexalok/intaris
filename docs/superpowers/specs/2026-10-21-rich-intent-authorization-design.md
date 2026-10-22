# Source-linked intent and scoped authorization

The fork keeps its existing classifier, L1 LLM/CLEF decision matrix, Judge,
human approval protocol, and explicit approval expiration. It adopts upstream's
idea of retaining requests, restrictions, approvals, revocations, and uncertainty
with their original evidence. It does not import upstream's hybrid engine or
permission-reuse cache.

## Contract

- Deterministic critical patterns and configured deny rules are hard prohibitions.
  Neither allow rules, permissive outcome caps, earlier approvals, Judge, nor a
  human decision on an old call can make them executable. An operator must change
  an erroneous configured rule before a new evaluation can pass.
- Source-linked intent is an interpretation, never an independent permission.
  Sources come from tenant/session-scoped stored user messages and usable human
  decisions. Assistant text, agent reasoning, tools, and generated summaries do
  not become user authority. Complete source text accompanies interpreted facts.
- Scope includes the operation, target, environment, conditions, and exclusions.
  A topical match or the same tool name does not authorize a different operation.
  A bare confirmation without an unambiguous recorded antecedent is uncertainty.
- Current source evidence outranks a compressed summary. Later restrictions and
  revocations must remain visible; missing or truncated evidence cannot silently
  become an authorization. Freshness is checked after model inference.
- L1 LLM, Jev/CLEF, and Judge consume the same server-built evidence representation.
  The call's evidence is recorded separately from client-provided context.
- Existing sessions and old model outputs remain readable. Profile generation
  uses the existing intention update call, with no new model round trip per tool.
- Retain fork isolation, request floors, exact script allowlists, provider routing,
  byte budgets, redaction, and expiration. No new dependency or upstream artifact.

## Architecture

A small intent-evidence module owns source collection, source binding, bounded
profile validation, prompt rendering, and freshness. A dedicated session field
stores the generated profile with the intention under the existing stale-write
guard. A dedicated audit field preserves the evidence used by an evaluated call.
Models interpret natural-language scope; deterministic guards enforce provenance
and hard prohibitions. Profile text is not a new allowlist.

## Validation

Pair allowed and forbidden examples: documentation mentioning destructive commands
versus their execution; bounded cleanup versus deleting root; an exact scoped
request versus another target; an explicit user request versus an assistant
proposal; current approval versus revocation/expiration; one session versus
another. Exercise both L1 backends and both Judge modes with hostile approve/low
model responses. Use real stores and request pipelines, mocking only inference.

Offline tests establish enforcement and context plumbing. They do not establish
live-model false-positive/false-negative rates. No live provider calls, push,
merge, deployment, or upstream checkpoint are part of this local implementation.
