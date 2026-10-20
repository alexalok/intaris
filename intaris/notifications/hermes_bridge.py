"""Durable, invocation-bounded native approvals for a trusted Hermes gateway.

Only the peer-authenticated Unix transport calls this service. No HTTP agent
credential can create a native decision, and a presentation callback never
executes a tool: the adapter still waits for the Intaris audit verdict.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import secrets
import time
from collections.abc import Callable
from typing import Any

from intaris.audit import AuditStore
from intaris.db import Database
from intaris.judge import resolve_with_side_effects
from intaris.session import SessionStore

logger = logging.getLogger(__name__)


def telegram_id(value: Any, *, positive: bool = False) -> str:
    """Accept canonical numeric Telegram identities, never usernames or bools."""
    if type(value) not in (int, str):
        raise ValueError("Invalid Telegram identity")
    value = str(value)
    if not re.fullmatch(r"-?[1-9][0-9]{0,18}", value):
        raise ValueError("Invalid Telegram identity")
    if abs(int(value)) >= 2**63 or (positive and int(value) <= 0):
        raise ValueError("Invalid Telegram identity")
    return value


def _topic(value: Any) -> str | None:
    return None if value is None else telegram_id(value, positive=True)


class HermesApprovalBridge:
    """Own native leases and resolve only still-pending Intaris escalations."""

    def __init__(
        self,
        db: Database,
        *,
        clock: Callable[[], float] = time.time,
        resolution_context: dict[str, Any] | None = None,
    ) -> None:
        self._db = db
        self._audit = AuditStore(db)
        self._sessions = SessionStore(db)
        self._clock = clock
        self._context = resolution_context or {}
        self._lock = asyncio.Lock()
        with db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hermes_approval_leases (
                    lease_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL,
                    route TEXT NOT NULL,
                    message_id TEXT,
                    state TEXT NOT NULL DEFAULT 'pending',
                    UNIQUE (user_id, call_id)
                )
            """)
            cur.execute("""CREATE INDEX IF NOT EXISTS idx_hermes_approval_expiry
                ON hermes_approval_leases(state, expires_at)""")

    def _record(self, policy: dict, request: dict) -> dict:
        record = self._audit.get_by_call_id(
            request["call_id"], user_id=policy["user_id"]
        )
        if record["session_id"] != request["session_id"]:
            raise ValueError("Session does not own this call")
        session = self._sessions.get(request["session_id"], user_id=policy["user_id"])
        if (
            session.get("agent_id") != policy["agent_id"]
            or record.get("agent_id") != policy["agent_id"]
        ):
            raise ValueError("Profile does not own this call")
        return record

    def _active(self, lease: dict) -> bool:
        session = self._sessions.get(lease["session_id"], user_id=lease["user_id"])
        if session["status"] != "active":
            return False
        # Parent suspension/termination must not leave child buttons live.
        seen = {session["session_id"]}
        while session.get("parent_session_id"):
            parent = session["parent_session_id"]
            if parent in seen or len(seen) >= 32:
                return False
            seen.add(parent)
            session = self._sessions.get(parent, user_id=lease["user_id"])
            if session["status"] != "active":
                return False
        return True

    @staticmethod
    def _pending(record: dict) -> bool:
        from intaris.decision import UNATTENDED_JUDGE_REVIEW

        return (
            record.get("decision") == "escalate"
            and record.get("user_decision") is None
            and record.get("outcome_override") != UNATTENDED_JUDGE_REVIEW
        )

    @staticmethod
    def _route(policy: dict, origin: Any) -> dict | None:
        actors = policy["approver_ids"]
        if isinstance(origin, dict):
            try:
                actor = telegram_id(origin.get("user_id"), positive=True)
                chat = telegram_id(origin.get("chat_id"))
                thread = _topic(origin.get("thread_id"))
                if actor in actors:
                    return {"chat_id": chat, "thread_id": thread, "actor_ids": [actor]}
            except ValueError:
                pass
        if policy.get("fallback_chat_id"):
            return {
                "chat_id": policy["fallback_chat_id"],
                "thread_id": policy.get("fallback_thread_id"),
                "actor_ids": actors,
            }
        return None

    def _get(self, user_id: str, profile: str, lease_id: str) -> dict:
        with self._db.cursor() as cur:
            cur.execute(
                """SELECT * FROM hermes_approval_leases
                WHERE lease_id = ? AND user_id = ? AND profile = ?""",
                (lease_id, user_id, profile),
            )
            row = cur.fetchone()
        if row is None:
            raise ValueError("Unknown native approval")
        result = dict(row)
        result["route"] = json.loads(result["route"])
        return result

    def _state(self, lease: dict, state: str) -> None:
        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE hermes_approval_leases SET state = ? WHERE lease_id = ?",
                (state, lease["lease_id"]),
            )
        lease["state"] = state

    async def _resolve(
        self, lease: dict, decision: str, note: str, *, lifecycle: bool = False
    ) -> None:
        await resolve_with_side_effects(
            call_id=lease["call_id"],
            user_id=lease["user_id"],
            user_decision=decision,
            user_note=note,
            resolved_by="integration" if lifecycle else "user",
            audit_store=self._audit,
            pending_only=True,
            **self._context,
        )

    async def _retire(self, lease: dict, reason: str) -> str:
        if lease["state"].startswith("retiring:"):
            reason = lease["state"].split(":", 1)[1]
        record = self._audit.get_by_call_id(lease["call_id"], user_id=lease["user_id"])
        decision = record.get("user_decision")
        if decision:
            if record.get("resolved_by") == "integration":
                status = lease["state"].removeprefix("retiring:")
                if status in {"expired", "cancelled", "failed"}:
                    self._state(lease, status)
                    return status
            self._state(lease, decision)
            return decision
        # A withdrawn invocation is not a user approval. Persist denial so
        # neither a late native tap nor an identical retry can reuse it.
        # Persist withdrawal intent before the audit write. A failure or crash
        # leaves a recoverable, non-actionable state for the next sweep.
        self._state(lease, f"retiring:{reason}")
        if self._pending(record):
            try:
                await self._resolve(
                    lease,
                    "deny",
                    f"Native approval {reason}; invocation withdrawn",
                    lifecycle=True,
                )
            except ValueError:
                record = self._audit.get_by_call_id(
                    lease["call_id"], user_id=lease["user_id"]
                )
                if record.get("user_decision"):
                    self._state(lease, record["user_decision"])
                    return record["user_decision"]
                raise
        self._state(lease, reason)
        return reason

    def _opened(self, lease: dict, record: dict, *, new: bool) -> dict:
        args = json.dumps(record.get("args_redacted") or {}, ensure_ascii=False)
        text = (
            f"Intaris approval required\nTool: {record.get('tool', '')}\n"
            f"Call: {record['call_id']}\nSession: {record['session_id']}\n"
            f"Arguments: {args[:1600]}\n"
            f"Reason: {(record.get('judge_reasoning') or record.get('reasoning') or '')[:800]}\n"
            "Approve applies only to this pending call. Silence does not approve."
        )
        return {
            "ok": True,
            "lease_id": lease["lease_id"],
            "new": new,
            "expires_at": lease["expires_at"],
            "route": lease["route"],
            "text": text,
        }

    async def handle(self, policy: dict, profile: str, request: dict) -> dict:
        """Process one request from an already authenticated gateway/profile."""
        async with self._lock:
            try:
                return await self._handle(policy, profile, request)
            except (ValueError, KeyError, TypeError):
                return {
                    "ok": False,
                    "error": "Native approval unavailable or no longer actionable",
                }
            except Exception:
                logger.exception("Native approval failed")
                return {"ok": False, "error": "Native approval unavailable"}

    async def _handle(self, policy: dict, profile: str, request: dict) -> dict:
        op = request["op"]
        if op == "fallback_transport":
            # The socket has authenticated the gateway and runtime profile.
            # Return only its operator-selected transport, never request hints
            # or another profile's tenant/agent/approver policy. No lease yet.
            return {
                "ok": True,
                "transport_profile": (
                    policy.get("fallback_transport_profile", profile)
                    if policy.get("fallback_chat_id")
                    else None
                ),
            }
        if op == "open":
            record = self._record(policy, request)
            with self._db.cursor() as cur:
                cur.execute(
                    "SELECT lease_id FROM hermes_approval_leases WHERE user_id = ? AND call_id = ?",
                    (policy["user_id"], request["call_id"]),
                )
                row = cur.fetchone()
            if row is not None:
                lease = self._get(policy["user_id"], profile, row["lease_id"])
                if lease["state"] != "pending" or not self._pending(record):
                    raise ValueError("Already settled")
                if lease["expires_at"] <= self._clock() or not self._active(lease):
                    await self._retire(lease, "expired")
                    raise ValueError("Expired")
                return self._opened(lease, record, new=False)
            if not self._pending(record) or not self._active(record):
                raise ValueError("Call is not awaiting human review")
            remaining = request["remaining_seconds"]
            if (
                type(remaining) not in (float, int)
                or not math.isfinite(remaining)
                or remaining <= 0
            ):
                raise ValueError("Invalid approval deadline")
            route = self._route(policy, request.get("origin"))
            if route is None:
                return {"ok": True, "lease_id": None}
            lease = dict(
                lease_id=secrets.token_hex(16),
                user_id=policy["user_id"],
                profile=profile,
                session_id=request["session_id"],
                call_id=request["call_id"],
                expires_at=self._clock() + min(remaining, 600),
                route=route,
            )
            with self._db.cursor() as cur:
                # Claim scope atomically with lease creation. UI/judge decisions
                # on the same call must also remain invocation-specific.
                cur.execute(
                    """UPDATE audit_log SET approval_scope = 'call'
                    WHERE call_id = ? AND user_id = ? AND decision = 'escalate'
                      AND user_decision IS NULL""",
                    (lease["call_id"], lease["user_id"]),
                )
                if cur.rowcount != 1:
                    raise ValueError("Call already resolved")
                cur.execute(
                    """INSERT INTO hermes_approval_leases
                    (lease_id, user_id, profile, session_id, call_id, expires_at, route)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        lease["lease_id"],
                        lease["user_id"],
                        profile,
                        lease["session_id"],
                        lease["call_id"],
                        lease["expires_at"],
                        json.dumps(route),
                    ),
                )
            return self._opened(lease, record, new=True)

        lease = self._get(policy["user_id"], profile, request["lease_id"])
        record = self._record(policy, lease)
        if op == "close":
            reason = request["reason"]
            if reason not in ("completed", "cancelled", "expired", "failed"):
                raise ValueError("Invalid retirement reason")
            status = await self._retire(
                lease, "cancelled" if reason == "completed" else reason
            )
            return {"ok": True, "status": status}
        if lease["state"] != "pending" or not self._pending(record):
            raise ValueError("Already settled")
        if lease["expires_at"] <= self._clock() or not self._active(lease):
            await self._retire(lease, "expired")
            raise ValueError("Expired")
        route = lease["route"]
        if (
            telegram_id(request["chat_id"]) != route["chat_id"]
            or _topic(request.get("thread_id")) != route["thread_id"]
        ):
            raise ValueError("Wrong destination")
        if op == "fallback":
            fallback = self._route(policy, None)
            if (
                lease["message_id"] is not None
                or fallback is None
                or (fallback["chat_id"], fallback["thread_id"])
                == (route["chat_id"], route["thread_id"])
            ):
                raise ValueError("No unused fallback destination")
            # Only the trusted gateway may report a definite topic rejection.
            # Keep the same lease and deadline; never move a delivered prompt.
            with self._db.cursor() as cur:
                cur.execute(
                    """UPDATE hermes_approval_leases SET route = ?
                    WHERE lease_id = ? AND state = 'pending' AND message_id IS NULL
                      AND route = ?""",
                    (json.dumps(fallback), lease["lease_id"], json.dumps(route)),
                )
                if cur.rowcount != 1:
                    raise ValueError("Native route already changed")
            lease["route"] = fallback
            return self._opened(lease, record, new=False)
        message_id = telegram_id(request["message_id"], positive=True)
        if op == "bind":
            if lease["message_id"] is not None:
                raise ValueError("Already bound")
            with self._db.cursor() as cur:
                cur.execute(
                    "UPDATE hermes_approval_leases SET message_id = ? WHERE lease_id = ? AND message_id IS NULL",
                    (message_id, lease["lease_id"]),
                )
                if cur.rowcount != 1:
                    raise ValueError("Already bound")
            return {"ok": True}
        if op != "resolve" or lease["message_id"] != message_id:
            raise ValueError("Unknown action or message")
        actor = telegram_id(request["actor_id"], positive=True)
        if actor not in route["actor_ids"] or actor not in policy["approver_ids"]:
            raise ValueError("Unauthorized actor")
        decision = request["decision"]
        if decision not in ("approve", "deny"):
            raise ValueError("Invalid decision")
        # Claim before any asynchronous side effects; failure is never retried as
        # an approval. The audit's pending-only SQL guard arbitrates UI/judge races.
        self._state(lease, "resolving")
        await self._resolve(
            lease, decision, f"Telegram user {actor}; native call-specific approval"
        )
        self._state(lease, decision)
        return {"ok": True, "status": decision}

    async def sweep(self) -> None:
        """Fail closed on expired or abandoned calls, including after restart."""
        async with self._lock:
            with self._db.cursor() as cur:
                cur.execute(
                    """SELECT * FROM hermes_approval_leases
                    WHERE state IN ('pending', 'resolving') OR state LIKE 'retiring:%'"""
                )
                rows = [dict(row) for row in cur.fetchall()]
            for lease in rows:
                try:
                    if lease["state"].startswith("retiring:"):
                        await self._retire(lease, lease["state"].split(":", 1)[1])
                    elif lease["expires_at"] <= self._clock() or not self._active(
                        lease
                    ):
                        await self._retire(lease, "expired")
                except ValueError:
                    # Deleted sessions/audits cannot be approved. Keep other
                    # failures recoverable instead of abandoning their audit.
                    logger.debug("Native lease reconciliation deferred", exc_info=True)
                except Exception:
                    logger.exception("Native lease reconciliation failed; will retry")
