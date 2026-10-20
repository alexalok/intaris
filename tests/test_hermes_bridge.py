"""Native approvals keep tenant, callback identity and execution lifetime bound."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig
from intaris.db import Database
from intaris.session import SessionStore


@pytest.fixture
def bridge(tmp_path):
    from intaris.notifications.hermes_bridge import HermesApprovalBridge

    db = Database(DBConfig(path=str(tmp_path / "test.db")))
    sessions = SessionStore(db)
    audit = AuditStore(db)
    for user in ("owner", "other"):
        sessions.create(
            session_id="s", user_id=user, agent_id="hermes", intention="Test"
        )
        audit.insert(
            call_id=f"call-{user}",
            user_id=user,
            session_id="s",
            agent_id="hermes",
            tool="terminal",
            args_redacted={"command": "echo safe"},
            classification="WRITE",
            decision="escalate",
            risk="medium",
            reasoning="Needs a human",
            evaluation_path="llm",
            latency_ms=1,
        )
    profile = {
        "user_id": "owner",
        "agent_id": "hermes",
        "approver_ids": ["42", "43"],
        "fallback_chat_id": "-999",
        "fallback_thread_id": "9",
    }
    clock = SimpleNamespace(now=1000.0)
    service = HermesApprovalBridge(db, clock=lambda: clock.now)
    yield SimpleNamespace(
        service=service,
        db=db,
        audit=audit,
        sessions=sessions,
        profile=profile,
        clock=clock,
    )
    db.close()


def run(bridge, **req):
    return asyncio.run(bridge.service.handle(bridge.profile, "/profiles/a", req))


def open_call(bridge, **extra):
    return run(
        bridge,
        op="open",
        session_id="s",
        call_id="call-owner",
        remaining_seconds=60,
        **extra,
    )


def bind(bridge, lease):
    route = lease["route"]
    return run(
        bridge,
        op="bind",
        lease_id=lease["lease_id"],
        chat_id=route["chat_id"],
        thread_id=route["thread_id"],
        message_id="100",
    )


def decide(bridge, lease, **extra):
    fields = dict(
        op="resolve",
        lease_id=lease["lease_id"],
        decision="approve",
        actor_id="42",
        chat_id=lease["route"]["chat_id"],
        thread_id=lease["route"]["thread_id"],
        message_id="100",
    )
    fields.update(extra)
    return run(bridge, **fields)


@pytest.mark.parametrize("mapped", [False, True])
def test_fallback_transport_comes_only_from_operator_policy(bridge, mapped):
    if mapped:
        bridge.profile["fallback_transport_profile"] = "/profiles/shared"
    result = run(
        bridge,
        op="fallback_transport",
        fallback_transport_profile="/profiles/attacker",
    )
    assert result == {
        "ok": True,
        "transport_profile": "/profiles/shared" if mapped else "/profiles/a",
    }
    with bridge.db.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS count FROM hermes_approval_leases")
        assert cur.fetchone()["count"] == 0
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        is None
    )


def test_disabled_fallback_does_not_offer_a_transport(bridge):
    bridge.profile["fallback_transport_profile"] = "/profiles/shared"
    bridge.profile["fallback_chat_id"] = None
    assert run(bridge, op="fallback_transport") == {
        "ok": True,
        "transport_profile": None,
    }


def test_origin_preserves_topic_and_actor_and_deduplicates(bridge):
    origin = {"chat_id": "-123", "thread_id": "7", "user_id": "42"}
    lease = open_call(bridge, origin=origin)
    assert lease["route"] == {"chat_id": "-123", "thread_id": "7", "actor_ids": ["42"]}
    assert lease["new"] is True
    again = open_call(bridge, origin={"chat_id": "-456", "user_id": "43"})
    assert again["lease_id"] == lease["lease_id"]
    assert again["route"] == lease["route"]
    assert again["new"] is False
    assert again["expires_at"] == 1060
    assert "echo safe" in lease["text"]


@pytest.mark.parametrize(
    "origin",
    [
        None,
        {},
        {"chat_id": "-123", "user_id": "999"},
        {"chat_id": "-123", "thread_id": "bad", "user_id": "42"},
    ],
)
def test_untrusted_or_missing_origin_uses_operator_fallback(bridge, origin):
    lease = open_call(bridge, origin=origin)
    assert lease["route"] == {
        "chat_id": "-999",
        "thread_id": "9",
        "actor_ids": ["42", "43"],
    }


def test_no_route_keeps_pending_without_approval(bridge):
    bridge.profile.pop("fallback_chat_id")
    assert open_call(bridge)["lease_id"] is None
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        is None
    )


def fallback(bridge, lease, **extra):
    fields = dict(
        op="fallback",
        lease_id=lease["lease_id"],
        chat_id=lease["route"]["chat_id"],
        thread_id=lease["route"]["thread_id"],
    )
    fields.update(extra)
    return run(bridge, **fields)


def test_unavailable_origin_can_switch_once_to_operator_fallback(bridge):
    lease = open_call(
        bridge, origin={"chat_id": "-123", "thread_id": "7", "user_id": "42"}
    )
    bridge.clock.now += 10
    moved = fallback(bridge, lease, fallback_chat_id="-456")
    assert moved["ok"]
    assert moved["lease_id"] == lease["lease_id"]
    assert moved["expires_at"] == lease["expires_at"]
    assert moved["route"] == {
        "chat_id": "-999",
        "thread_id": "9",
        "actor_ids": ["42", "43"],
    }
    assert not fallback(bridge, lease)["ok"]
    assert not fallback(bridge, moved)["ok"]
    assert not bind(bridge, lease)["ok"]
    assert bind(bridge, moved)["ok"]
    assert not decide(bridge, lease)["ok"]
    assert decide(bridge, moved, actor_id="43")["ok"]


@pytest.mark.parametrize("state", ["bound", "expired", "cancelled", "resolved"])
def test_fallback_cannot_move_an_actionable_or_retired_message(bridge, state):
    lease = open_call(
        bridge, origin={"chat_id": "-123", "thread_id": "7", "user_id": "42"}
    )
    if state == "bound":
        assert bind(bridge, lease)["ok"]
    elif state == "expired":
        bridge.clock.now = lease["expires_at"]
    elif state == "cancelled":
        run(bridge, op="close", lease_id=lease["lease_id"], reason="cancelled")
    else:
        bridge.audit.resolve_escalation("call-owner", "deny", user_id="owner")
    assert not fallback(bridge, lease)["ok"]


def test_fallback_requires_configured_different_route_and_matching_origin(bridge):
    lease = open_call(
        bridge, origin={"chat_id": "-123", "thread_id": "7", "user_id": "42"}
    )
    assert not fallback(bridge, lease, thread_id="8")["ok"]
    bridge.profile.pop("fallback_chat_id")
    assert not fallback(bridge, lease)["ok"]
    bridge.profile.update(fallback_chat_id="-123", fallback_thread_id="7")
    assert not fallback(bridge, lease)["ok"]
    bridge.profile["fallback_thread_id"] = None
    moved = fallback(bridge, lease)
    assert moved["ok"]
    assert moved["route"]["thread_id"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor_id", "43"),
        ("actor_id", "999"),
        ("chat_id", "-456"),
        ("thread_id", "8"),
        ("message_id", "101"),
        ("decision", "always"),
    ],
)
def test_callback_identity_rejected_without_consuming_valid_action(
    bridge, field, value
):
    lease = open_call(
        bridge, origin={"chat_id": "-123", "thread_id": "7", "user_id": "42"}
    )
    assert bind(bridge, lease)["ok"]
    assert decide(bridge, lease, **{field: value})["ok"] is False
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        is None
    )
    assert decide(bridge, lease)["ok"]
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        == "approve"
    )
    assert decide(bridge, lease, decision="deny")["ok"] is False


def test_callback_cannot_resolve_before_message_binding(bridge):
    lease = open_call(bridge)
    assert decide(bridge, lease)["ok"] is False
    assert bind(bridge, lease)["ok"]
    assert bind(bridge, lease)["ok"] is False


def test_profile_session_and_tenant_isolation(bridge):
    assert (
        run(
            bridge,
            op="open",
            session_id="s",
            call_id="call-other",
            remaining_seconds=60,
        )["ok"]
        is False
    )
    assert (
        run(
            bridge,
            op="open",
            session_id="wrong",
            call_id="call-owner",
            remaining_seconds=60,
        )["ok"]
        is False
    )
    lease = open_call(bridge)
    assert bind(bridge, lease)["ok"]
    request = {"op": "close", "lease_id": lease["lease_id"], "reason": "cancelled"}
    assert not asyncio.run(
        bridge.service.handle(bridge.profile, "/profiles/b", request)
    )["ok"]
    bridge.profile["agent_id"] = "foreign"
    assert not open_call(bridge)["ok"]


@pytest.mark.parametrize("reason", ["cancelled", "expired", "failed", "completed"])
def test_close_pending_lease_prevents_late_approval(bridge, reason):
    lease = open_call(bridge)
    bind(bridge, lease)
    result = run(bridge, op="close", lease_id=lease["lease_id"], reason=reason)
    assert result["ok"]
    assert decide(bridge, lease)["ok"] is False
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        == "deny"
    )
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["resolved_by"]
        == "integration"
    )


def test_expiry_and_sweep_deny_pending_calls(bridge):
    lease = open_call(bridge)
    bind(bridge, lease)
    bridge.clock.now = 1060
    assert decide(bridge, lease)["ok"] is False
    asyncio.run(bridge.service.sweep())
    assert (
        run(bridge, op="close", lease_id=lease["lease_id"], reason="expired")["status"]
        == "expired"
    )
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        == "deny"
    )


@pytest.mark.parametrize("parent", [False, True])
def test_idle_session_keeps_approval_until_invocation_deadline(bridge, parent):
    target = "s"
    if parent:
        bridge.sessions.create(
            session_id="parent", user_id="owner", agent_id="hermes", intention="Test"
        )
        with bridge.db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET parent_session_id = 'parent' WHERE user_id = 'owner' AND session_id = 's'"
            )
        target = "parent"
    lease = open_call(bridge)
    assert bind(bridge, lease)["ok"]
    bridge.sessions.update_status(target, "idle", user_id="owner")
    asyncio.run(bridge.service.sweep())
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        is None
    )
    assert decide(bridge, lease)["status"] == "approve"


@pytest.mark.parametrize("status", ["completed", "suspended", "terminated"])
@pytest.mark.parametrize("parent", [False, True])
def test_stopped_session_or_parent_retires_native_lease(bridge, status, parent):
    target = "s"
    if parent:
        bridge.sessions.create(
            session_id="parent", user_id="owner", agent_id="hermes", intention="Test"
        )
        with bridge.db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET parent_session_id = 'parent' WHERE user_id = 'owner' AND session_id = 's'"
            )
        target = "parent"
    lease = open_call(bridge)
    assert bind(bridge, lease)["ok"]
    bridge.sessions.update_status(target, status, user_id="owner")
    asyncio.run(bridge.service.sweep())
    assert decide(bridge, lease)["ok"] is False
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        == "deny"
    )


def test_ui_resolution_wins_and_native_cannot_override_judge(bridge):
    lease = open_call(bridge)
    bind(bridge, lease)
    bridge.audit.resolve_escalation(
        "call-owner", "deny", user_id="owner", resolved_by="judge"
    )
    assert decide(bridge, lease)["ok"] is False
    result = run(bridge, op="close", lease_id=lease["lease_id"], reason="completed")
    assert result["status"] == "deny"
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["resolved_by"]
        == "judge"
    )


def test_terminated_session_and_service_restart_do_not_restore_buttons(bridge):
    from intaris.notifications.hermes_bridge import HermesApprovalBridge

    lease = open_call(bridge)
    bind(bridge, lease)
    bridge.service = HermesApprovalBridge(bridge.db, clock=lambda: bridge.clock.now)
    assert open_call(bridge)["new"] is False
    bridge.sessions.update_status("s", "terminated", user_id="owner")
    assert decide(bridge, lease)["ok"] is False


def test_pending_only_resolution_is_atomic_against_judge_override(bridge):
    bridge.audit.resolve_escalation(
        "call-owner", "deny", user_id="owner", resolved_by="judge"
    )
    with pytest.raises(ValueError):
        bridge.audit.resolve_escalation(
            "call-owner", "approve", user_id="owner", pending_only=True
        )
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        == "deny"
    )


@pytest.mark.parametrize("resolver", ["native", "user", "judge"])
def test_native_call_approval_never_authorizes_another_invocation(bridge, resolver):
    from intaris.evaluator import Evaluator, _compute_args_hash

    args = {"command": "echo safe"}
    with bridge.db.cursor() as cur:
        cur.execute(
            "UPDATE audit_log SET args_hash = ? WHERE call_id = ?",
            (_compute_args_hash(args), "call-owner"),
        )
    lease = open_call(bridge)
    bind(bridge, lease)
    if resolver == "native":
        assert decide(bridge, lease)["ok"]
    else:
        bridge.audit.resolve_escalation(
            "call-owner", "approve", user_id="owner", resolved_by=resolver
        )
    run(bridge, op="close", lease_id=lease["lease_id"], reason="cancelled")
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        == "approve"
    )
    llm = Mock()
    llm.generate.return_value = json.dumps(
        {
            "aligned": False,
            "risk": "medium",
            "decision": "escalate",
            "reasoning": "Needs review",
        }
    )
    evaluator = Evaluator(
        llm=llm, session_store=bridge.sessions, audit_store=bridge.audit
    )
    bridge.sessions.create(
        session_id="another",
        user_id="owner",
        agent_id="other-profile",
        intention="Other work",
    )
    for session in ("s", "another"):
        result = evaluator.evaluate(
            user_id="owner",
            session_id=session,
            agent_id="hermes",
            tool="terminal",
            args=args,
            tool_preferences={"terminal": "escalate"},
        )
        assert result["decision"] == "escalate"
    assert bridge.audit.get_user_decisions("s", user_id="owner") == []
    result = evaluator.evaluate(
        user_id="owner",
        session_id="s",
        agent_id="hermes",
        tool="terminal",
        args=args,
        minimum_outcome="escalate",
        approval_call_id="call-owner",
    )
    assert result["decision"] == "deny"


def test_failed_withdrawal_is_retried_after_restart(bridge, monkeypatch):
    from intaris.notifications.hermes_bridge import HermesApprovalBridge

    lease = open_call(bridge)
    bind(bridge, lease)
    monkeypatch.setattr(
        bridge.service,
        "_resolve",
        AsyncMock(side_effect=RuntimeError("DB unavailable")),
    )
    assert not run(bridge, op="close", lease_id=lease["lease_id"], reason="cancelled")[
        "ok"
    ]
    assert not decide(bridge, lease)["ok"]
    bridge.service = HermesApprovalBridge(bridge.db, clock=lambda: bridge.clock.now)
    asyncio.run(bridge.service.sweep())
    record = bridge.audit.get_by_call_id("call-owner", user_id="owner")
    assert record["user_decision"] == "deny"
    assert record["resolved_by"] == "integration"
    assert (
        run(bridge, op="close", lease_id=lease["lease_id"], reason="completed")[
            "status"
        ]
        == "cancelled"
    )


def test_call_only_resolution_does_not_change_session_authority(bridge):
    from intaris.judge import resolve_with_side_effects

    with bridge.db.cursor() as cur:
        cur.execute(
            "UPDATE audit_log SET evaluation_path = 'alignment' WHERE call_id = ?",
            ("call-owner",),
        )
    open_call(bridge)
    alignment, intention = Mock(), Mock()
    asyncio.run(
        resolve_with_side_effects(
            call_id="call-owner",
            user_id="owner",
            user_decision="approve",
            user_note="Approve this call",
            audit_store=bridge.audit,
            alignment_barrier=alignment,
            intention_barrier=intention,
        )
    )
    alignment.acknowledge.assert_not_called()
    intention.trigger_from_decision.assert_not_called()


def test_native_scope_claim_and_lease_creation_rollback_together(bridge, monkeypatch):
    from contextlib import contextmanager

    original = bridge.db.cursor

    class FailingCursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def __getattr__(self, name):
            return getattr(self.cursor, name)

        def execute(self, sql, params=()):
            if "INSERT INTO hermes_approval_leases" in sql:
                raise RuntimeError("Lease insert failed")
            return self.cursor.execute(sql, params)

    @contextmanager
    def failing_cursor():
        with original() as cursor:
            yield FailingCursor(cursor)

    monkeypatch.setattr(bridge.db, "cursor", failing_cursor)
    assert not open_call(bridge)["ok"]
    record = bridge.audit.get_by_call_id("call-owner", user_id="owner")
    assert record["approval_scope"] == "reusable"
    with original() as cursor:
        cursor.execute("SELECT COUNT(*) FROM hermes_approval_leases")
        assert cursor.fetchone()[0] == 0


def lease_state(bridge, lease):
    with bridge.db.cursor() as cur:
        cur.execute(
            "SELECT state FROM hermes_approval_leases WHERE lease_id = ?",
            (lease["lease_id"],),
        )
        row = cur.fetchone()
    return row["state"] if row is not None else None


@pytest.mark.parametrize(
    "outcome,status,decision,resolver",
    [
        ("completed", "approve", "approve", "user"),
        ("denied", "deny", "deny", "user"),
        ("cancelled", "cancelled", "deny", "integration"),
        ("expired", "expired", "deny", "integration"),
        ("failed", "failed", "deny", "integration"),
        ("completed_pending", "cancelled", "deny", "integration"),
    ],
)
def test_settled_leases_retained_for_grace_then_purged_without_reopening(
    bridge, outcome, status, decision, resolver
):
    from intaris.notifications.hermes_bridge import HermesApprovalBridge

    lease = open_call(bridge)
    assert bind(bridge, lease)["ok"]
    if outcome == "completed":
        assert decide(bridge, lease)["ok"]
        assert run(bridge, op="close", lease_id=lease["lease_id"], reason="completed")[
            "ok"
        ]
    elif outcome == "denied":
        assert decide(bridge, lease, decision="deny")["ok"]
    elif outcome == "expired":
        bridge.clock.now = lease["expires_at"]
        asyncio.run(bridge.service.sweep())
    else:
        reason = "completed" if outcome == "completed_pending" else outcome
        assert run(bridge, op="close", lease_id=lease["lease_id"], reason=reason)["ok"]
    assert lease_state(bridge, lease) == status
    record = bridge.audit.get_by_call_id("call-owner", user_id="owner")
    assert record["user_decision"] == decision
    assert record["resolved_by"] == resolver

    # Retention survives restart and gives late close requests one hour after
    # the original invocation deadline to observe the settled result.
    bridge.service = HermesApprovalBridge(bridge.db, clock=lambda: bridge.clock.now)
    bridge.clock.now = lease["expires_at"] + 3599
    asyncio.run(bridge.service.sweep())
    assert lease_state(bridge, lease) == status
    assert run(bridge, op="close", lease_id=lease["lease_id"], reason="completed") == {
        "ok": True,
        "status": status,
    }

    bridge.clock.now += 1
    asyncio.run(bridge.service.sweep())
    assert lease_state(bridge, lease) is None
    assert not decide(bridge, lease)["ok"]
    assert not run(bridge, op="close", lease_id=lease["lease_id"], reason="completed")[
        "ok"
    ]
    assert not open_call(bridge)["ok"]
    assert bridge.audit.get_by_call_id("call-owner", user_id="owner") == record
    assert lease_state(bridge, lease) is None


@pytest.mark.parametrize("state", ["pending", "resolving", "retiring:cancelled"])
def test_retention_keeps_failed_withdrawals_recoverable(bridge, monkeypatch, state):
    lease = open_call(bridge)
    assert bind(bridge, lease)["ok"]
    with bridge.db.cursor() as cur:
        cur.execute(
            "UPDATE hermes_approval_leases SET state = ? WHERE lease_id = ?",
            (state, lease["lease_id"]),
        )
    bridge.clock.now = lease["expires_at"] + 3600
    with monkeypatch.context() as patch:
        patch.setattr(
            bridge.service,
            "_resolve",
            AsyncMock(side_effect=RuntimeError("Audit temporarily unavailable")),
        )
        asyncio.run(bridge.service.sweep())
    assert lease_state(bridge, lease).startswith("retiring:")
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        is None
    )
    assert not decide(bridge, lease)["ok"]

    asyncio.run(bridge.service.sweep())
    record = bridge.audit.get_by_call_id("call-owner", user_id="owner")
    assert record["user_decision"] == "deny"
    assert record["resolved_by"] == "integration"
    assert lease_state(bridge, lease) is None
    assert not open_call(bridge)["ok"]


def test_retention_preserves_terminal_lease_without_a_settled_audit(bridge):
    lease = open_call(bridge)
    with bridge.db.cursor() as cur:
        cur.execute(
            "UPDATE hermes_approval_leases SET state = 'cancelled' WHERE lease_id = ?",
            (lease["lease_id"],),
        )
    bridge.clock.now = lease["expires_at"] + 3600
    asyncio.run(bridge.service.sweep())
    assert lease_state(bridge, lease) == "cancelled"
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        is None
    )
    assert not open_call(bridge)["ok"]


def test_retention_preserves_unexpired_pending_lease(bridge):
    lease = open_call(bridge)
    bridge.clock.now = lease["expires_at"] - 1
    asyncio.run(bridge.service.sweep())
    assert lease_state(bridge, lease) == "pending"
    assert open_call(bridge)["lease_id"] == lease["lease_id"]
    assert bind(bridge, lease)["ok"]
    assert decide(bridge, lease)["ok"]
