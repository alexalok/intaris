# Evaluation outcome floor

`POST /api/v1/evaluate` accepts optional `minimum_outcome`: `deny`, `escalate`, or `approve`.
The evaluator chooses the stricter result in this order: `deny < escalate < approve`.
It applies this constraint before audit storage and the response. Requests without the field retain existing behavior.

An `escalate` floor requires human review. The evaluate endpoint does not invoke Judge for this escalation.
After approval, the client supplies the original `approval_call_id` together with the same floor, session, tool, and arguments.
Intaris checks the owner's audit record and human decision. Current denials remain denials.
A new floor request does not use the general recent-approval cache.

For reads that require current scope assessment, an old ID cannot override a
new restriction or a changed invocation directory. If L1 still escalates, a
fresh bare human approval can be reused only with complete recorded evidence,
unchanged session/ancestor revisions (apart from that approval's own increment),
and the same effective working directory. Conditional notes and missing or
changed evidence require current L1 approval. Read-only operator-preference
escalations store this evidence too, preserving fresh explicit retries.

This reference is not a single-use grant. The trusted controller sends it only when it resumes the approved operation.
The response echoes `minimum_outcome` when supplied, so clients can detect unsupported servers.

## Session enforcement ceiling

Session `policy.maximum_outcome` accepts `deny` (normal enforcement), `escalate`
(upgrade evaluated denials to human review), or `approve` (upgrade evaluated
denials and escalations to approval when no deterministic hard prohibition applies).
Classifier `CRITICAL` results always deny, including under an `approve` ceiling.
Omitting it preserves the existing API behavior. Invalid values are rejected.
It is an enforcement setting, not an instruction to the safety LLM.

Evaluation still runs normally. The ceiling is applied before the request
`minimum_outcome`; the stricter request minimum wins on conflict. A self-mutation
request with `minimum_outcome=escalate` therefore still needs exact human approval.
Invalid approval references, inactive sessions, parent lifecycle stops, and
alignment barriers are not bypassed. Exact approval retries retain their existing
checks, including refusal to override a current raw denial.

Audit records persist `raw_decision`, `effective_decision`, `maximum_outcome`,
`minimum_outcome`, and `outcome_override`. `decision` remains the initial enforced
evaluation result for compatibility with approval workflows and session counters.
`effective_decision` follows subsequent human/judge resolutions; historical raw
decisions and policy snapshots never change when session policy is refreshed.
Older migrated rows have null provenance (unknown, not inferred).

Judge denials under an `escalate` ceiling remain pending for human review, with
the original denial retained in `judge_decision`. Human resolutions remain final.
Ceiling-produced approvals do not train the approved-path cache or become human
approval precedents. Audit UI and L2 summaries expose the override so downstream
L3 analysis can distinguish permissive enforcement from safe behavior.

For sessions with `policy.interaction_mode=none` (unattended tasks), the task's
no-escalation restriction takes precedence over both the ceiling and request
minimum. Without an enabled Judge, a raw denial or escalation becomes a denial
even when `maximum_outcome=approve`. With Judge enabled and no explicit `deny`
ceiling, a raw denial or escalation (including with no ceiling) is provisionally
escalated for Judge review. Only an explicit Judge approval may allow it.
Judge denials, deferrals, errors,
and timeouts all finalize as denials, never pending human approval. This
restriction is recorded with the call so changing session policy during review
does not allow a human deferral. The provisional call is hidden from pending
human approvals and cannot be approved through `/decision`. An evaluated
approval remains allowed unless the request minimum makes it stricter.
Alignment barriers deny rather than
wait for an unavailable human. Raw and final decisions remain visible in audit
provenance. Prior human or Judge approvals are never reused to bypass review
for a later unattended call.
