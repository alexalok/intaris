"""Audit log storage for intaris.

Records every tool call evaluation with decision, reasoning, redacted
args, and timing information. Supports filtered queries for the audit
log browser and session detail views. All operations are scoped by
user_id for multi-tenant isolation.
"""

from __future__ import annotations

import json
import logging
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from weakref import WeakKeyDictionary

from intaris.approval_policy import validate_approval_policy
from intaris.db import Database
from intaris.decision import UNATTENDED_JUDGE_REVIEW
from intaris.session import load_session_policy_chain

logger = logging.getLogger(__name__)


def _not_revoked_sql(alias: str = "audit_log") -> str:
    """Match exact later human denials using only fixed internal SQL aliases."""
    assert alias in {"audit_log", "source"}
    return f"""NOT EXISTS (
        SELECT 1 FROM audit_log AS denial
        WHERE denial.user_id = {alias}.user_id
          AND denial.session_id = {alias}.session_id
          AND denial.record_type = 'tool_call'
          AND denial.tool = {alias}.tool
          AND denial.args_hash = {alias}.args_hash
          AND denial.resolved_by = 'user'
          AND denial.user_decision = 'deny'
          AND denial.resolved_at >= {alias}.resolved_at
    )"""


# Judge grants mechanically derived from a human approval retain that one-hop
# dependency for future reuse. Their original waiting invocation is unaffected.
_USABLE_APPROVAL_SOURCE = f"""(
    approval_source_call_id IS NULL OR EXISTS (
        SELECT 1 FROM audit_log AS source
        WHERE source.call_id = audit_log.approval_source_call_id
          AND source.user_id = audit_log.user_id
          AND source.session_id = audit_log.session_id
          AND source.resolved_by = 'user' AND source.user_decision = 'approve'
          AND source.expired_at IS NULL
          AND source.approval_scope = 'reusable'
          AND COALESCE(source.classification, '') != 'critical'
          AND source.evaluation_path != 'critical'
          AND {_not_revoked_sql("source")}
    )
)"""


class ApprovalExpiredError(ValueError):
    """The originating client has retired this guarded invocation."""


class ScopeChangedError(ValueError):
    """User authority changed after the Judge collected its evidence."""


def _check_scope_versions(cur: Any, user_id: str, expected: dict[str, int]) -> None:
    """Compare tenant-scoped revisions using the approval transaction cursor."""
    for session_id, version in expected.items():
        cur.execute(
            "SELECT scope_version FROM sessions WHERE user_id = ? AND session_id = ?",
            (user_id, session_id),
        )
        row = cur.fetchone()
        if row is None or row["scope_version"] != version:
            raise ScopeChangedError(
                "User scope changed during review; reassess current evidence"
            )


class ApprovalNotFoundError(ValueError):
    """No approval exists in the supplied tenant and session scope."""


class AuditStore:
    """Audit log CRUD backed by SQLite.

    All operations require user_id for tenant isolation.
    """

    VALID_RECORD_TYPES = {"tool_call", "reasoning", "checkpoint", "summary"}

    # Optional SearchService handle, set by the server lifespan once
    # both services are ready. When present, every insert fans out to
    # the search indexer (vector tier only — lexical search reads
    # canonical tables directly via tsvector). Best-effort: indexer
    # failures never block the canonical audit insert.
    _search_service: Any = None

    @classmethod
    def set_search_service(cls, service: Any) -> None:
        cls._search_service = service

    @classmethod
    def clear_search_service(cls, service: Any) -> None:
        """Clear the search hook only if the caller still owns it."""
        if cls._search_service is service:
            cls._search_service = None

    # Runtime policy is shared by stores using the same DB, never across app
    # instances. Weak keys release configuration when that DB is discarded.
    _agent_policies: WeakKeyDictionary[Database, dict[str, Any] | None] = (
        WeakKeyDictionary()
    )

    @classmethod
    def set_agent_policy(cls, db: Database, policy: dict[str, Any] | None) -> None:
        """Bind the server-owned policy used to resolve restricted approvals."""
        cls._agent_policies[db] = deepcopy(policy)

    def __init__(self, db: Database):
        self._db = db

    def insert(
        self,
        *,
        call_id: str,
        user_id: str,
        session_id: str,
        agent_id: str | None,
        tool: str | None,
        args_redacted: dict[str, Any] | None,
        classification: str | None,
        evaluation_path: str,
        decision: str,
        risk: str | None,
        reasoning: str | None,
        latency_ms: int,
        record_type: str = "tool_call",
        content: str | None = None,
        args_hash: str | None = None,
        profile_version: int | None = None,
        intention: str | None = None,
        injection_detected: bool = False,
        raw_decision: str | None = None,
        maximum_outcome: str | None = None,
        minimum_outcome: str | None = None,
        outcome_override: str | None = None,
        intent_evidence: dict[str, Any] | None = None,
        evaluation_context: dict[str, Any] | None = None,
        scope_versions: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        """Insert an audit record.

        Args:
            call_id: External correlation ID for the tool call.
            user_id: Tenant identifier.
            session_id: Session this call belongs to.
            agent_id: Agent that made the call (optional).
            tool: Tool name (e.g., "bash", "edit"). Null for reasoning checkpoints.
            args_redacted: Tool arguments with secrets redacted. For reasoning
                records, may store associated context metadata.
            classification: "read" or "write". Null for reasoning checkpoints.
            evaluation_path: "fast", "critical", "llm", or "reasoning".
            decision: "approve", "deny", or "escalate".
            risk: Risk level from LLM evaluation (null for fast path).
            reasoning: LLM reasoning or pattern match explanation.
            latency_ms: Time taken for the evaluation in milliseconds.
            record_type: Record type: "tool_call", "reasoning", "checkpoint",
                or "summary".
            content: Reasoning or checkpoint text (null for tool_call records).
            scope_versions: Observed revisions required to commit an approval.
                A mismatch inserts nothing and raises ScopeChangedError so the
                evaluator can persist its non-executable fallback exactly once.
            evaluation_context: Redacted server evaluation metadata, kept separate
                from arbitrary tool argument keys.
            args_hash: SHA-256 hash of canonical args for escalation retry.
            profile_version: Behavioral profile version at time of evaluation.
            intention: Session intention at time of evaluation (for tracking).
            injection_detected: Whether prompt injection patterns were detected
                in the tool args or session intention.

        Returns:
            The created audit record as a dict.
        """
        if record_type not in self.VALID_RECORD_TYPES:
            raise ValueError(
                f"Invalid record_type '{record_type}'. "
                f"Must be one of: {self.VALID_RECORD_TYPES}"
            )

        record_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        if decision != "approve" or record_type != "tool_call":
            scope_versions = None
        if scope_versions is not None and (
            session_id not in scope_versions
            or any(
                not isinstance(key, str) or type(value) is not int or value < 0
                for key, value in scope_versions.items()
            )
        ):
            raise ScopeChangedError("User scope changed or its revision is unavailable")
        scope_predicates = [
            "EXISTS (SELECT 1 FROM sessions WHERE user_id = ? "
            "AND session_id = ? AND scope_version = ?)"
            for _ in (scope_versions or {})
        ]
        scope_params = [
            item
            for key, value in (scope_versions or {}).items()
            for item in (user_id, key, value)
        ]

        with self._db.cursor() as cur:
            if scope_versions is not None and self._db.backend == "postgresql":
                ids = sorted(scope_versions)
                placeholders = ", ".join("?" for _ in ids)
                cur.execute(
                    "SELECT session_id FROM sessions "
                    f"WHERE user_id = ? AND session_id IN ({placeholders}) "
                    "ORDER BY session_id FOR UPDATE",
                    [user_id, *ids],
                )
                cur.fetchall()
                _check_scope_versions(cur, user_id, scope_versions)
            if (
                record_type == "reasoning"
                and isinstance(content, str)
                and content.startswith("User message:")
                and not (
                    isinstance(args_redacted, dict)
                    and args_redacted.get("intention_eligible") is False
                )
            ):
                # Update first: PostgreSQL scope writers take the session lock
                # before audit rows. The revision and source commit together.
                cur.execute(
                    "UPDATE sessions SET scope_version = scope_version + 1 "
                    "WHERE user_id = ? AND session_id = ?",
                    (user_id, session_id),
                )
            cur.execute(
                """
                INSERT INTO audit_log
                    (id, call_id, record_type, user_id, session_id, agent_id,
                     timestamp, tool, args_redacted, content, classification,
                     evaluation_path, decision, risk, reasoning, latency_ms,
                     args_hash, profile_version, intention, injection_detected,
                     raw_decision, effective_decision, maximum_outcome,
                     minimum_outcome, outcome_override, intent_evidence,
                     evaluation_context)
                SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?, ?, ?
                """
                + (
                    " WHERE " + " AND ".join(scope_predicates)
                    if scope_predicates
                    else ""
                ),
                (
                    record_id,
                    call_id,
                    record_type,
                    user_id,
                    session_id,
                    agent_id,
                    now,
                    tool,
                    json.dumps(args_redacted) if args_redacted is not None else None,
                    content,
                    classification,
                    evaluation_path,
                    decision,
                    risk,
                    reasoning,
                    latency_ms,
                    args_hash,
                    profile_version,
                    intention,
                    injection_detected,
                    raw_decision or decision,
                    decision,
                    maximum_outcome,
                    minimum_outcome,
                    outcome_override,
                    json.dumps(intent_evidence)
                    if intent_evidence is not None
                    else None,
                    json.dumps(evaluation_context)
                    if evaluation_context is not None
                    else None,
                    *scope_params,
                ),
            )
            if scope_versions is not None and cur.rowcount != 1:
                raise ScopeChangedError(
                    "User scope changed during evaluation; review current evidence"
                )

        # Fan out to the search indexer (vector tier only). Lexical
        # search reads canonical tables directly via tsvector — no
        # write needed here for that.
        svc = AuditStore._search_service
        if svc is not None:
            try:
                if intention and intention.strip():
                    svc.enqueue_audit_intention(
                        user_id=user_id,
                        session_id=session_id,
                        agent_id=agent_id,
                        ref_id=record_id,
                        intention=intention,
                        ts=now,
                    )
                if (
                    record_type in ("reasoning", "checkpoint")
                    and content
                    and content.strip()
                ):
                    svc.enqueue_audit_reasoning(
                        user_id=user_id,
                        session_id=session_id,
                        agent_id=agent_id,
                        ref_id=record_id,
                        content=content,
                        ts=now,
                    )
            except Exception:
                logger.exception(
                    "Search indexer enqueue failed (audit_log insert "
                    "user=%s session=%s record_type=%s)",
                    user_id,
                    session_id,
                    record_type,
                )

        return {
            "id": record_id,
            "call_id": call_id,
            "record_type": record_type,
            "user_id": user_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "timestamp": now,
            "tool": tool,
            "args_redacted": args_redacted,
            "content": content,
            "intent_evidence": intent_evidence,
            "evaluation_context": evaluation_context,
            "classification": classification,
            "evaluation_path": evaluation_path,
            "decision": decision,
            "raw_decision": raw_decision or decision,
            "effective_decision": decision,
            "maximum_outcome": maximum_outcome,
            "minimum_outcome": minimum_outcome,
            "outcome_override": outcome_override,
            "risk": risk,
            "reasoning": reasoning,
            "latency_ms": latency_ms,
            "user_decision": None,
            "user_note": None,
            "expired_at": None,
            "expiration_reason": None,
            "approval_source_call_id": None,
            "resolved_at": None,
            "resolved_by": None,
            "judge_reasoning": None,
            "judge_decision": None,
            "judge_risk": None,
            "args_hash": args_hash,
            "profile_version": profile_version,
            "intention": intention,
            "injection_detected": injection_detected,
        }

    def get_by_call_id(self, call_id: str, *, user_id: str) -> dict[str, Any]:
        """Get an audit record by call_id, scoped to user.

        Raises:
            ValueError: If record not found.
        """
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE call_id = ? AND user_id = ?",
                (call_id, user_id),
            )
            row = cur.fetchone()

        if row is None:
            raise ValueError(f"Audit record with call_id={call_id} not found")

        return _row_to_dict(row)

    def get_by_id(self, record_id: str, *, user_id: str) -> dict[str, Any]:
        """Get an audit record by internal ID, scoped to user.

        Raises:
            ValueError: If record not found.
        """
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE id = ? AND user_id = ?",
                (record_id, user_id),
            )
            row = cur.fetchone()

        if row is None:
            raise ValueError(f"Audit record {record_id} not found")

        return _row_to_dict(row)

    def query(
        self,
        *,
        user_id: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        record_type: str | None = None,
        tool: str | None = None,
        decision: str | None = None,
        risk: str | None = None,
        evaluation_path: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        resolved: bool | None = None,
        overridable_denials: bool = False,
        page: int = 1,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Query audit records with filters and pagination.

        Args:
            user_id: Tenant identifier (always required).
            record_type: Filter by record type (tool_call, reasoning, checkpoint).
            overridable_denials: Restrict unresolved tool denials to reviewable
                evaluation paths before pagination, excluding hard prohibitions.
            resolved: Filter by actionable status. ``True`` includes human/judge
                resolutions and expired invocations. ``False`` excludes both.
                ``None`` (default) returns the complete evaluation history.

        Returns:
            Dict with 'items', 'total', 'page', 'pages'.
        """
        conditions: list[str] = ["user_id = ?"]
        params: list[Any] = [user_id]

        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if record_type:
            conditions.append("record_type = ?")
            params.append(record_type)
        if tool:
            if self._db.backend == "postgresql":
                conditions.append("tool ILIKE ?")
            else:
                conditions.append("tool LIKE ? COLLATE NOCASE")
            params.append(f"%{tool}%")
        if decision:
            conditions.append("decision = ?")
            params.append(decision)
        if risk:
            conditions.append("risk = ?")
            params.append(risk)
        if evaluation_path:
            conditions.append("evaluation_path = ?")
            params.append(evaluation_path)
        if from_ts:
            conditions.append("timestamp >= ?")
            params.append(from_ts)
        if to_ts:
            conditions.append("timestamp <= ?")
            params.append(to_ts)
        if resolved is True:
            conditions.append("(user_decision IS NOT NULL OR expired_at IS NOT NULL)")
        elif resolved is False:
            conditions.append("user_decision IS NULL AND expired_at IS NULL")
            # Judge-only provisional calls must not appear in human approvals.
            conditions.append("(outcome_override IS NULL OR outcome_override != ?)")
            params.append(UNATTENDED_JUDGE_REVIEW)

        if overridable_denials:
            # Apply eligibility to both count and rows before LIMIT/OFFSET.
            # Unfiltered audit history continues to include hard/lifecycle denies.
            conditions.extend(
                [
                    "decision = 'deny' AND record_type = 'tool_call'",
                    "user_decision IS NULL AND expired_at IS NULL",
                    "COALESCE(classification, '') != 'critical'",
                    "evaluation_path NOT IN ('critical', 'fast')",
                    "(outcome_override IS NULL OR outcome_override != ?)",
                ]
            )
            params.append(UNATTENDED_JUDGE_REVIEW)

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        with self._db.cursor() as cur:
            # Count total matching records
            cur.execute(f"SELECT COUNT(*) FROM audit_log {where}", params)
            total = cur.fetchone()[0]

            # Fetch page
            offset = (page - 1) * limit
            cur.execute(
                f"""
                SELECT * FROM audit_log
                {where}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            )
            rows = cur.fetchall()

        pages = max(1, (total + limit - 1) // limit)
        return {
            "items": [_row_to_dict(row) for row in rows],
            "total": total,
            "page": page,
            "pages": pages,
        }

    def get_recent(
        self,
        session_id: str,
        *,
        user_id: str,
        limit: int = 10,
        record_type: str | None = None,
        before: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get recent audit records for a session.

        Used to assemble context for LLM safety evaluation.

        Args:
            session_id: Session to query.
            user_id: Tenant identifier.
            limit: Max records to return.
            record_type: Filter by record type (e.g., "tool_call", "reasoning").
            before: ISO timestamp upper bound (inclusive). When set, only
                records with ``timestamp <= before`` are returned. Used
                for time-bounding parent session queries to a child
                session's creation time.

        Returns:
            List of audit record dicts, most recent first.
        """
        if record_type and record_type not in self.VALID_RECORD_TYPES:
            raise ValueError(
                f"Invalid record_type '{record_type}'. "
                f"Must be one of: {self.VALID_RECORD_TYPES}"
            )

        conditions = ["session_id = ?", "user_id = ?"]
        params: list[Any] = [session_id, user_id]

        if record_type:
            conditions.append("record_type = ?")
            params.append(record_type)

        if before:
            conditions.append("timestamp <= ?")
            params.append(before)

        params.append(limit)
        sql = (
            "SELECT * FROM audit_log"
            f" WHERE {' AND '.join(conditions)}"
            " ORDER BY timestamp DESC"
            " LIMIT ?"
        )

        with self._db.cursor() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()

        return [_row_to_dict(row) for row in rows]

    def get_user_decisions(
        self,
        session_id: str,
        *,
        user_id: str,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Get recent final human decisions for a session.

        Only reusable final human resolutions are returned. Call-only grants,
        judge-authored decisions, and expired approvals cannot become
        authority for another invocation. Expiration never removes human
        denials from this guidance.

        Args:
            session_id: Session to query.
            user_id: Tenant identifier.
            limit: Max decision records to return.

        Returns:
            List of recent human decision records, newest first.
        """
        with self._db.cursor() as cur:
            cur.execute(
                f"""
                SELECT call_id, session_id, tool, args_redacted, decision,
                       user_decision, user_note, resolved_at, resolved_by,
                       risk, reasoning, evaluation_path, intention, args_hash,
                       timestamp
                FROM audit_log
                WHERE user_id = ? AND session_id = ?
                  AND record_type = 'tool_call'
                  AND user_decision IS NOT NULL
                  AND (user_decision = 'deny' OR (
                      COALESCE(classification, '') != 'critical'
                      AND evaluation_path != 'critical'
                      AND {_not_revoked_sql()}
                  ))
                  AND (expired_at IS NULL OR user_decision = 'deny')
                  AND resolved_by = 'user'
                  AND approval_scope = 'reusable'
                  AND COALESCE(user_note, '') != 'Resolved via notification action link'
                ORDER BY COALESCE(resolved_at, timestamp) DESC
                LIMIT ?
                """,
                (user_id, session_id, limit),
            )
            rows = cur.fetchall()

        return [_row_to_dict(row) for row in rows]

    def get_intent_sources(
        self, session_id: str, *, user_id: str, limit: int = 25
    ) -> list[dict[str, Any]]:
        """Get user-channel evidence without displacement by agent chatter."""
        eligible = (
            "COALESCE((args_redacted::jsonb -> 'intention_eligible')::text, 'null') != 'false'"
            if self._db.backend == "postgresql"
            else "COALESCE(json_type(args_redacted, '$.intention_eligible'), 'null') != 'false'"
        )
        with self._db.cursor() as cur:
            cur.execute(
                f"""SELECT * FROM audit_log
                WHERE user_id = ? AND session_id = ? AND (
                    (record_type = 'reasoning' AND substr(content, 1, 13) = 'User message:'
                        AND {eligible})
                    OR (record_type = 'tool_call' AND resolved_by = 'user'
                        AND user_decision IS NOT NULL AND approval_scope = 'reusable'
                        AND COALESCE(user_note, '') != 'Resolved via notification action link'
                        AND (user_decision = 'deny' OR (
                            expired_at IS NULL
                            AND COALESCE(classification, '') != 'critical'
                            AND evaluation_path != 'critical'
                            AND {_not_revoked_sql()})))
                ) ORDER BY COALESCE(resolved_at, timestamp) DESC, call_id DESC LIMIT ?""",
                (user_id, session_id, limit),
            )
            return [_row_to_dict(row) for row in cur.fetchall()]

    def find_approved_escalation(
        self,
        *,
        user_id: str,
        tool: str,
        args_hash: str,
        cutoff: str,
        human_only: bool = False,
        session_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Find a prior approved override for the same tool+args.

        Used by the evaluator for retry: if the same tool+args
        combination was approved (via escalation resolution or denial
        override) within the TTL window, the approval can be reused.

        The query is decision-agnostic — it matches any audit record
        with ``user_decision='approve'`` regardless of the original
        ``decision`` column (escalate or deny).

        Args:
            user_id: Tenant identifier.
            tool: Tool name.
            args_hash: SHA-256 hash of canonical args.
            cutoff: ISO timestamp — only consider approvals after this time.
            session_id: If supplied, restrict retry grants to this session.

        Returns:
            Audit record dict if a matching approval is found, else None.
        """
        with self._db.cursor() as cur:
            cur.execute(
                f"""
                SELECT call_id, reasoning FROM audit_log
                WHERE user_id = ? AND tool = ?
                  AND args_hash = ? AND user_decision = 'approve'
                  {"AND session_id = ?" if session_id is not None else ""}
                  AND COALESCE(classification, '') != 'critical'
                  AND evaluation_path != 'critical'
                  AND approval_scope = 'reusable'
                  AND expired_at IS NULL
                  AND {_USABLE_APPROVAL_SOURCE}
                  AND (outcome_override IS NULL OR outcome_override != ?)
                  AND (
                      resolved_by = 'user'
                      OR COALESCE(raw_decision, '') != 'deny'
                      OR COALESCE(maximum_outcome, 'deny') = 'deny'
                  )
                  AND resolved_at >= ?
                  AND {_not_revoked_sql()}
                  AND (? = FALSE OR resolved_by = 'user')
                ORDER BY resolved_at DESC
                LIMIT 1
                """,
                (
                    user_id,
                    tool,
                    args_hash,
                    *((session_id,) if session_id is not None else ()),
                    UNATTENDED_JUDGE_REVIEW,
                    cutoff,
                    human_only,
                ),
            )
            row = cur.fetchone()

        if row is None:
            return None
        return dict(row)

    def approvals_are_usable(self, call_ids: set[str], *, user_id: str) -> bool:
        """Validate every cached permission source against current audit state.

        Approval retries can cross sessions within a tenant. Missing, expired,
        or no-longer-approved sources invalidate the dependent path cache.
        Database failures propagate rather than authorizing a cache hit.
        """
        if not call_ids:
            return True
        placeholders = ", ".join("?" for _ in call_ids)
        with self._db.cursor() as cur:
            cur.execute(
                f"""
                SELECT COUNT(*) AS total FROM audit_log
                WHERE user_id = ? AND call_id IN ({placeholders})
                  AND record_type = 'tool_call'
                  AND user_decision = 'approve' AND expired_at IS NULL
                  AND COALESCE(classification, '') != 'critical'
                  AND evaluation_path != 'critical'
                  AND approval_scope = 'reusable'
                  AND {_USABLE_APPROVAL_SOURCE}
                  AND {_not_revoked_sql()}
                """,
                (user_id, *sorted(call_ids)),
            )
            return cur.fetchone()["total"] == len(call_ids)

    def expire_escalation(
        self,
        call_id: str,
        *,
        user_id: str,
        session_id: str,
        reason: str,
    ) -> dict[str, Any]:
        """Retire a guarded invocation on explicit evidence from its client.

        Expiration is independent of the evaluation and any human/judge decision.
        It may follow a raced approval, but never erases that decision. The first
        expiration wins, and repeated delivery is harmless. Age or session status
        alone cannot establish whether a client still intends to retry a call.
        """
        if reason not in {"timeout", "cancelled", "abandoned"}:
            raise ValueError(
                "Expiration reason must be timeout, cancelled, or abandoned"
            )
        if not session_id:
            raise ValueError("Expiration requires the originating session_id")
        now = datetime.now(timezone.utc).isoformat()
        with self._db.cursor() as cur:
            if self._db.backend == "postgresql":
                cur.execute(
                    "SELECT session_id FROM sessions WHERE user_id = ? AND session_id = ? FOR UPDATE",
                    (user_id, session_id),
                )
            cur.execute(
                """
                UPDATE audit_log SET expired_at = ?, expiration_reason = ?
                WHERE call_id = ? AND user_id = ? AND session_id = ?
                  AND record_type = 'tool_call' AND decision = 'escalate'
                  AND expired_at IS NULL
                """,
                (now, reason, call_id, user_id, session_id),
            )
            changed = cur.rowcount == 1
            cur.execute(
                "SELECT * FROM audit_log WHERE call_id = ? AND user_id = ? AND session_id = ?",
                (call_id, user_id, session_id),
            )
            row = cur.fetchone()
            if row is None:
                raise ApprovalNotFoundError("Approval not found in this session")
            if row["decision"] != "escalate" or row["record_type"] != "tool_call":
                raise ValueError("Only escalated tool calls can expire")
            record = _row_to_dict(row)
            if (
                changed
                and record.get("resolved_by") in {"user", "judge"}
                and record.get("user_decision") == "approve"
                and record.get("approval_scope") == "reusable"
            ):
                cur.execute(
                    "UPDATE sessions SET scope_version = scope_version + 1 "
                    "WHERE user_id = ? AND session_id = ?",
                    (user_id, session_id),
                )
        return record

    def resolve_escalation(
        self,
        call_id: str,
        user_decision: str,
        user_note: str | None = None,
        *,
        user_id: str,
        resolved_by: str = "user",
        user_note_source: str | None = None,
        judge_reasoning: str | None = None,
        judge_decision: str | None = None,
        judge_risk: str | None = None,
        pending_only: bool = False,
        approval_source_call_id: str | None = None,
        scope_versions: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        """Record a user decision on an escalated or denied tool call.

        Supports:
        - Resolving unresolved escalations (first resolution)
        - Overriding judge decisions on escalations
        - Ex-post overriding L1 denials (critical auto-deny, LLM deny)

        Human decisions (``resolved_by="user"``) are final and cannot be
        overridden.

        Args:
            call_id: The escalated or denied call to resolve.
            user_decision: "approve" or "deny".
            user_note: Optional note from the resolver.
            user_id: Tenant identifier.
            resolved_by: Who resolved: "user" (human) or "judge" (LLM judge).
            user_note_source: "user" for human text, "system" for attribution
                or generated text. Defaults to the resolver's source.
            judge_reasoning: Judge's reasoning (stored when judge resolves).
            judge_decision: Historical judge recommendation.
            judge_risk: Historical judge risk assessment.
            approval_source_call_id: Human grant used for a derived judge approval.
            scope_versions: Session and ancestor revisions observed by the Judge.
                Only Judge approvals use this guard; human overrides stay final.
            pending_only: Resolve only an unresolved escalation, without the
                normal human override of a prior judge verdict. Native
                callbacks use this to make stale buttons inert.

        ``resolved_by="integration"`` is reserved for pending-only lifecycle
        denials (withdrawal/expiry), never an approval or human precedent.

        Returns:
            Updated audit record.

        Raises:
            ValueError: If record not found, not an escalation or denial,
                or already resolved by a human user.
        """
        if user_decision not in ("approve", "deny"):
            raise ValueError(
                f"Invalid user_decision '{user_decision}'. Must be 'approve' or 'deny'."
            )
        if resolved_by not in ("user", "judge", "integration"):
            raise ValueError(
                f"Invalid resolved_by '{resolved_by}'. Must be 'user', 'judge', or 'integration'."
            )
        if resolved_by == "integration" and (
            user_decision != "deny" or not pending_only
        ):
            raise ValueError("Integration lifecycle can only deny pending escalations")
        if user_note_source is None:
            user_note_source = "user" if resolved_by == "user" else "system"
        if user_note_source not in ("user", "system"):
            raise ValueError("Invalid user_note_source")

        if resolved_by != "judge" or user_decision != "approve":
            approval_source_call_id = None
        now = datetime.now(timezone.utc).isoformat()

        record = self.get_by_call_id(call_id, user_id=user_id)
        if resolved_by != "judge" or user_decision != "approve":
            scope_versions = None
        if scope_versions is not None and (
            record["session_id"] not in scope_versions
            or any(
                not isinstance(key, str) or type(value) is not int or value < 0
                for key, value in scope_versions.items()
            )
        ):
            raise ScopeChangedError("User scope changed or its revision is unavailable")
        scope_conditions = "".join(
            " AND EXISTS (SELECT 1 FROM sessions AS scope_session "
            "WHERE scope_session.user_id = audit_log.user_id "
            "AND scope_session.session_id = ? AND scope_session.scope_version = ?)"
            for _ in (scope_versions or {})
        )
        scope_params = [
            value for pair in (scope_versions or {}).items() for value in pair
        ]
        approval_scope_versions: dict[str, int] | None = None
        policy_state = ("", False)
        policy_chain: list[dict[str, Any]] = []
        chain_conditions = ""
        chain_params: list[Any] = []
        if user_decision == "approve":
            if record.get("expired_at"):
                raise ApprovalExpiredError(
                    f"Call {call_id} expired; its invocation is no longer waiting"
                )
            with self._db.cursor() as cur:
                if scope_versions is not None:
                    _check_scope_versions(cur, user_id, scope_versions)
                policy_chain = load_session_policy_chain(
                    cur, record["session_id"], user_id=user_id
                )
            session = policy_chain[0]
            if session["status"] not in {"active", "idle"}:
                raise ValueError(
                    f"Session is {session['status']}; approval is not allowed"
                )
            if any(
                ancestor["status"] in {"suspended", "terminated"}
                for ancestor in policy_chain[1:]
            ):
                raise ValueError("Parent session is stopped; approval is not allowed")
            policy_state = (session["_policy_raw"], bool(session["agent_restricted"]))
            # Human overrides need fresh policy too; caller-supplied Judge
            # revisions are an additional inference guard, never a substitute.
            for item in policy_chain:
                chain_conditions += (
                    " AND EXISTS (SELECT 1 FROM sessions AS policy_session "
                    "WHERE policy_session.user_id = audit_log.user_id "
                    "AND policy_session.session_id = ? "
                    "AND COALESCE(policy_session.policy, '') = ? "
                    "AND policy_session.agent_restricted = ? "
                    "AND COALESCE(policy_session.parent_session_id, '') = ? "
                    "AND policy_session.scope_version = ? "
                    "AND policy_session.status NOT IN ('suspended', 'terminated'))"
                )
                chain_params.extend(
                    (
                        item["session_id"],
                        item["_policy_raw"],
                        bool(item["agent_restricted"]),
                        item.get("parent_session_id") or "",
                        item["scope_version"],
                    )
                )

        # Atomic update: conditions in WHERE prevent TOCTOU races.
        # Matches unresolved escalations/denials OR records resolved by
        # the judge (allowing human override of judge decisions). Human
        # decisions are final — resolved_by='user' is NOT matched.
        # COALESCE preserves existing judge_reasoning when the caller
        # does not provide it (i.e., human override passes None).
        with self._db.cursor() as cur:
            if self._db.backend == "postgresql":
                # Lock all observed scope rows in stable order before audit rows.
                # Every source writer follows the same session-before-audit order.
                ids = sorted(
                    {
                        record["session_id"],
                        *(scope_versions or {}),
                        *(item["session_id"] for item in policy_chain),
                    }
                )
                placeholders = ", ".join("?" for _ in ids)
                cur.execute(
                    "SELECT session_id, policy, agent_restricted, parent_session_id, scope_version, status FROM sessions "
                    f"WHERE user_id = ? AND session_id IN ({placeholders}) "
                    "ORDER BY session_id FOR UPDATE",
                    [user_id, *ids],
                )
                locked_rows = {row["session_id"]: row for row in cur.fetchall()}
                locked = locked_rows.get(record["session_id"])
                if scope_versions is not None:
                    _check_scope_versions(cur, user_id, scope_versions)
                if user_decision == "approve" and (
                    locked is None
                    or (locked["policy"] or "", bool(locked["agent_restricted"]))
                    != policy_state
                ):
                    raise ValueError(
                        "Session policy changed during approval; retry approval"
                    )
            elif scope_versions is not None:
                _check_scope_versions(cur, user_id, scope_versions)
            if user_decision == "approve":
                validate_approval_policy(
                    record,
                    session,
                    self._agent_policies.get(self._db),
                    ancestors=policy_chain[1:],
                )
            cur.execute(
                f"""
                UPDATE audit_log
                SET user_decision = ?, user_note = ?, resolved_at = ?,
                    resolved_by = ?, user_note_source = ?,
                    judge_reasoning = COALESCE(?, judge_reasoning),
                    judge_decision = COALESCE(?, judge_decision),
                    judge_risk = COALESCE(?, judge_risk),
                    effective_decision = ?, approval_source_call_id = ?
                WHERE call_id = ? AND user_id = ?
                  AND decision IN ('escalate', 'deny')
                  AND expired_at IS NULL
                  AND (user_decision IS NULL OR resolved_by = 'judge')
                  AND (? != 'approve' OR (
                      COALESCE(classification, '') != 'critical'
                      AND evaluation_path != 'critical'
                  ))
                  AND (? != 'approve' OR EXISTS (
                      SELECT 1 FROM sessions AS current_session
                      WHERE current_session.user_id = audit_log.user_id
                        AND current_session.session_id = audit_log.session_id
                        AND COALESCE(current_session.policy, '') = ?
                        AND current_session.agent_restricted = ?
                        AND current_session.status IN ('active', 'idle')
                  ))
                  AND (? = 0 OR (decision = 'escalate' AND user_decision IS NULL))
                  AND (? != 'user' OR outcome_override IS NULL OR outcome_override != ?)
                  AND (CAST(? AS TEXT) IS NULL OR EXISTS (
                      SELECT 1 FROM audit_log AS source
                      WHERE source.call_id = ? AND source.user_id = audit_log.user_id
                        AND source.session_id = audit_log.session_id
                        AND source.resolved_by = 'user'
                        AND source.user_decision = 'approve' AND source.expired_at IS NULL
                        AND source.approval_scope = 'reusable'
                        AND COALESCE(source.classification, '') != 'critical'
                        AND source.evaluation_path != 'critical'
                        AND {_not_revoked_sql("source")}
                  ))
                """
                + scope_conditions
                + chain_conditions,
                (
                    user_decision,
                    user_note,
                    now,
                    resolved_by,
                    user_note_source,
                    judge_reasoning,
                    judge_decision,
                    judge_risk,
                    user_decision,
                    approval_source_call_id,
                    call_id,
                    user_id,
                    user_decision,
                    user_decision,
                    *policy_state,
                    int(pending_only),
                    resolved_by,
                    UNATTENDED_JUDGE_REVIEW,
                    approval_source_call_id,
                    approval_source_call_id,
                    *scope_params,
                    *chain_params,
                ),
            )
            if cur.rowcount == 0:
                # Determine why the update failed for a clear error message
                cur.execute(
                    "SELECT * FROM audit_log WHERE call_id = ? AND user_id = ?",
                    (call_id, user_id),
                )
                row = cur.fetchone()
                if row is None:
                    raise ValueError(f"Call {call_id} not found")
                record = _row_to_dict(row)
                if scope_versions is not None:
                    _check_scope_versions(cur, user_id, scope_versions)
                if user_decision == "approve" and (
                    record.get("classification") == "critical"
                    or record.get("evaluation_path") == "critical"
                ):
                    raise ValueError(
                        "Hard prohibition cannot be approved; change the rule and evaluate again"
                    )
                if record.get("expired_at"):
                    raise ApprovalExpiredError(
                        f"Call {call_id} expired; its invocation is no longer waiting"
                    )
                if approval_source_call_id:
                    raise ValueError("Human approval source is no longer usable")
                if (
                    resolved_by == "user"
                    and record.get("outcome_override") == UNATTENDED_JUDGE_REVIEW
                ):
                    raise ValueError(
                        "Unattended Judge review cannot be resolved by a human"
                    )
                if record["decision"] not in ("escalate", "deny"):
                    raise ValueError(
                        f"Call {call_id} cannot be resolved "
                        f"(decision={record['decision']})"
                    )
                if record.get("user_decision"):
                    if record.get("resolved_by") == "user":
                        raise ValueError(
                            f"Call {call_id} already resolved by user "
                            f"(user_decision={record['user_decision']})"
                        )
                    raise ValueError(
                        f"Call {call_id} already resolved "
                        f"(user_decision={record['user_decision']})"
                    )
                if user_decision == "approve":
                    cur.execute(
                        "SELECT status FROM sessions WHERE user_id = ? AND session_id = ?",
                        (user_id, record["session_id"]),
                    )
                    current = cur.fetchone()
                    if current is None or current["status"] not in {"active", "idle"}:
                        raise ValueError(
                            "Session stopped during approval; evaluate again"
                        )
                    raise ValueError(
                        "Session policy changed during approval; retry approval"
                    )
                # Shouldn't reach here, but raise generic error
                raise ValueError(f"Failed to resolve call {call_id}")
            if resolved_by == "user":
                # The UPDATE below observes the current scope, including a
                # concurrent native lease claiming this call before resolution.
                cur.execute(
                    "UPDATE sessions SET scope_version = scope_version + 1 "
                    "WHERE user_id = ? AND session_id = ? AND EXISTS ("
                    "SELECT 1 FROM audit_log WHERE call_id = ? AND user_id = ? "
                    "AND (approval_scope = 'reusable' OR user_decision = 'deny'))",
                    (user_id, record["session_id"], call_id, user_id),
                )

            if user_decision == "approve":
                # Capture after the human resolution's own revision increment,
                # while the same transaction still holds every scope row.
                ids = [item["session_id"] for item in policy_chain]
                placeholders = ", ".join("?" for _ in ids)
                cur.execute(
                    "SELECT session_id, scope_version FROM sessions "
                    f"WHERE user_id = ? AND session_id IN ({placeholders})",
                    [user_id, *ids],
                )
                approval_scope_versions = {
                    item["session_id"]: item["scope_version"] for item in cur.fetchall()
                }

        resolved = self.get_by_call_id(call_id, user_id=user_id)
        if approval_scope_versions is not None:
            # Transient callback proof, never persisted or reconstructed from
            # a later audit read. Delayed learning must retain this exact scope.
            resolved["_approval_scope_versions"] = approval_scope_versions
        return resolved

    def set_judge_reasoning(
        self,
        call_id: str,
        judge_reasoning: str,
        *,
        user_id: str,
        judge_decision: str | None = None,
        judge_risk: str | None = None,
        outcome_override: str | None = None,
    ) -> None:
        """Store judge reasoning on an unresolved escalation.

        Used in advisory mode when the judge defers to a human. The
        reasoning is stored so the human can see the judge's analysis
        when reviewing the escalation.

        Idempotent: multiple calls overwrite the previous reasoning.
        Only writes to unresolved escalations — if the escalation was
        resolved between the judge's check and this write, the WHERE
        clause prevents stale writes (rowcount=0, silently ignored).

        Args:
            call_id: The escalated call.
            judge_reasoning: Judge's reasoning text.
            user_id: Tenant identifier.
            judge_decision: Historical judge recommendation.
            judge_risk: Historical judge risk assessment.
        """
        with self._db.cursor() as cur:
            cur.execute(
                """
                UPDATE audit_log
                SET judge_reasoning = ?,
                    judge_decision = COALESCE(?, judge_decision),
                    judge_risk = COALESCE(?, judge_risk),
                    outcome_override = COALESCE(?, outcome_override)
                WHERE call_id = ? AND user_id = ?
                  AND decision = 'escalate'
                  AND user_decision IS NULL
                  AND expired_at IS NULL
                """,
                (
                    judge_reasoning,
                    judge_decision,
                    judge_risk,
                    outcome_override,
                    call_id,
                    user_id,
                ),
            )

    def get_latest_reasoning(
        self,
        session_id: str,
        *,
        user_id: str,
        before_ts: str,
        before_id: str,
    ) -> dict[str, Any] | None:
        """Get the latest reasoning record before a specific audit row."""
        with self._db.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM audit_log
                WHERE session_id = ? AND user_id = ?
                  AND record_type = 'reasoning'
                  AND (
                    timestamp < ?
                    OR (timestamp = ? AND id < ?)
                  )
                ORDER BY timestamp DESC, id DESC
                LIMIT 1
                """,
                (session_id, user_id, before_ts, before_ts, before_id),
            )
            row = cur.fetchone()

        if row is None:
            return None
        return _row_to_dict(row)

    def get_recent_judge_reviews(
        self,
        session_id: str,
        *,
        user_id: str,
        before_ts: str,
        before_id: str,
        limit: int = 3,
    ) -> list[dict[str, Any]]:
        """Get recent explicit judge approvals/denials before a review point."""
        with self._db.cursor() as cur:
            cur.execute(
                f"""
                SELECT * FROM audit_log
                WHERE session_id = ? AND user_id = ?
                  AND record_type = 'tool_call'
                  AND resolved_by = 'judge'
                  AND judge_decision IN ('approve', 'deny')
                  AND (expired_at IS NULL OR judge_decision = 'deny')
                  AND (judge_decision = 'deny' OR (
                      {_USABLE_APPROVAL_SOURCE} AND {_not_revoked_sql()}))
                  AND (
                    timestamp < ?
                    OR (timestamp = ? AND id < ?)
                  )
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (session_id, user_id, before_ts, before_ts, before_id, limit),
            )
            rows = cur.fetchall()

        return [_row_to_dict(row) for row in rows]

    def get_window(
        self,
        session_id: str,
        *,
        user_id: str,
        from_ts: str,
        to_ts: str,
        record_types: set[str] | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Get audit records within a time window for a session.

        Optimized for L2 session summary generation — fetches records
        within a specific time range, optionally filtered by record type.

        Args:
            session_id: Session to query.
            user_id: Tenant identifier.
            from_ts: Window start (inclusive) as ISO timestamp.
            to_ts: Window end (inclusive) as ISO timestamp.
            record_types: Optional set of record types to include
                (e.g., {"tool_call", "reasoning"}). None = all types.
            limit: Max records to return.

        Returns:
            List of audit record dicts, ordered by timestamp ASC
            (chronological order for analysis).
        """
        conditions = [
            "session_id = ?",
            "user_id = ?",
            "timestamp >= ?",
            "timestamp <= ?",
        ]
        params: list[Any] = [session_id, user_id, from_ts, to_ts]

        if record_types:
            valid = record_types & self.VALID_RECORD_TYPES
            if not valid:
                return []
            placeholders = ", ".join("?" for _ in valid)
            conditions.append(f"record_type IN ({placeholders})")
            params.extend(sorted(valid))

        where = "WHERE " + " AND ".join(conditions)
        limit_clause = f"LIMIT {limit}" if limit > 0 else ""

        with self._db.cursor() as cur:
            cur.execute(
                f"""
                SELECT * FROM audit_log
                {where}
                ORDER BY timestamp ASC
                {limit_clause}
                """,
                params,
            )
            rows = cur.fetchall()

        return [_row_to_dict(row) for row in rows]

    def get_session_stats(
        self,
        session_id: str,
        *,
        user_id: str,
        from_ts: str | None = None,
        to_ts: str | None = None,
    ) -> dict[str, int]:
        """Get aggregated stats for a session within an optional time window.

        Returns counts of approved, denied, escalated tool calls.

        Args:
            session_id: Session to query.
            user_id: Tenant identifier.
            from_ts: Optional window start (inclusive).
            to_ts: Optional window end (inclusive).

        Returns:
            Dict with approved_count, denied_count, escalated_count, total.
        """
        conditions = [
            "session_id = ?",
            "user_id = ?",
            "record_type = 'tool_call'",
        ]
        params: list[Any] = [session_id, user_id]

        if from_ts:
            conditions.append("timestamp >= ?")
            params.append(from_ts)
        if to_ts:
            conditions.append("timestamp <= ?")
            params.append(to_ts)

        where = "WHERE " + " AND ".join(conditions)

        with self._db.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN decision = 'approve' THEN 1 ELSE 0 END) as approved,
                    SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as denied,
                    SUM(CASE WHEN decision = 'escalate' THEN 1 ELSE 0 END) as escalated
                FROM audit_log
                {where}
                """,
                params,
            )
            row = cur.fetchone()

        if row is None:
            return {
                "approved_count": 0,
                "denied_count": 0,
                "escalated_count": 0,
                "total": 0,
            }
        return {
            "approved_count": row["approved"] or 0,
            "denied_count": row["denied"] or 0,
            "escalated_count": row["escalated"] or 0,
            "total": row["total"] or 0,
        }


def _row_to_dict(row: Any) -> dict[str, Any]:
    """Convert a sqlite3.Row to a plain dict, parsing JSON fields."""
    d = dict(row)
    for field in ("intent_evidence", "evaluation_context"):
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                d[field] = None
    if d.get("args_redacted"):
        try:
            d["args_redacted"] = json.loads(d["args_redacted"])
        except (json.JSONDecodeError, TypeError):
            pass
    return d
