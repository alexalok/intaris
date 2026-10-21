"""Losing a cron presenter cannot decide the invocation's still-pending audit."""

import asyncio

import pytest

from tests.test_hermes_bridge import bind, decide, lease_state, open_call, run
from tests.test_hermes_bridge import bridge as bridge


def open_presentation(bridge, **extra):
    return run(
        bridge,
        op="open_presentation",
        session_id="s",
        call_id="call-owner",
        remaining_seconds=60,
        **extra,
    )


@pytest.mark.parametrize("ending", ["close", "expiry", "restart"])
def test_cron_retirement_preserves_pending_audit_and_fences_late_callbacks(
    bridge, ending
):
    from intaris.notifications.hermes_bridge import HermesApprovalBridge

    lease = open_presentation(bridge)
    assert lease["ok"] and lease["new"]
    assert bind(bridge, lease)["ok"]
    if ending == "close":
        assert run(bridge, op="close", lease_id=lease["lease_id"], reason="cancelled")[
            "ok"
        ]
    else:
        if ending == "restart":
            bridge.service = HermesApprovalBridge(
                bridge.db, clock=lambda: bridge.clock.now
            )
        bridge.clock.now += 61
        asyncio.run(bridge.service.sweep())
    assert (
        bridge.audit.get_by_call_id("call-owner", user_id="owner")["user_decision"]
        is None
    )
    assert not decide(bridge, lease)["ok"]
    assert not open_presentation(bridge)["ok"]


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_cron_callback_still_records_only_its_call_decision(bridge, decision):
    lease = open_presentation(bridge)
    assert bind(bridge, lease)["ok"]
    assert decide(bridge, lease, decision=decision) == {"ok": True, "status": decision}
    assert not decide(bridge, lease, decision=decision)["ok"]
    record = bridge.audit.get_by_call_id("call-owner", user_id="owner")
    assert record["user_decision"] == decision and record["approval_scope"] == "call"
    assert record["user_note_source"] == "system"


def test_cron_route_uses_operator_policy_even_with_valid_origin(bridge):
    lease = open_presentation(
        bridge, origin={"user_id": "42", "chat_id": "-100", "thread_id": "5"}
    )
    assert lease["ok"]
    assert lease["route"] == {
        "chat_id": "-999",
        "thread_id": "9",
        "actor_ids": ["42", "43"],
    }


@pytest.mark.parametrize("reason", ["completed", "cancelled", "expired", "failed"])
def test_cron_retired_lease_survives_restart_and_grace_until_audit_settles(
    bridge, reason
):
    from intaris.notifications.hermes_bridge import HermesApprovalBridge

    lease = open_presentation(bridge)
    assert bind(bridge, lease)["ok"]
    assert run(bridge, op="close", lease_id=lease["lease_id"], reason=reason)["ok"]
    bridge.service = HermesApprovalBridge(bridge.db, clock=lambda: bridge.clock.now)
    bridge.clock.now = lease["expires_at"] + 3600
    asyncio.run(bridge.service.sweep())
    record = bridge.audit.get_by_call_id("call-owner", user_id="owner")
    assert record["user_decision"] is None
    assert record["expired_at"] is None
    assert record["approval_scope"] == "call"
    assert lease_state(bridge, lease) is not None
    assert not open_presentation(bridge)["ok"]
    assert not open_call(bridge)["ok"]
    assert not decide(bridge, lease)["ok"]

    bridge.audit.resolve_escalation(
        "call-owner", "approve", "Use staging only", user_id="owner"
    )
    settled = bridge.audit.get_by_call_id("call-owner", user_id="owner")
    assert settled["user_note"] == "Use staging only"
    assert settled["user_note_source"] == "user"
    assert not bridge.audit.approvals_are_usable({"call-owner"}, user_id="owner")
    asyncio.run(bridge.service.sweep())
    assert lease_state(bridge, lease) is None
    assert bridge.audit.get_by_call_id("call-owner", user_id="owner") == settled
    assert not open_presentation(bridge)["ok"]
    with bridge.db.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM hermes_approval_presentations")
        assert cur.fetchone()[0] == 0


@pytest.mark.parametrize("resolved", [False, True])
@pytest.mark.parametrize("retire", ["close", "sweep"])
def test_cron_client_expiration_preserves_verdict_history_and_retires_lease(
    bridge, resolved, retire
):
    lease = open_presentation(bridge)
    assert bind(bridge, lease)["ok"]
    if resolved:
        assert decide(bridge, lease)["ok"]
    record = bridge.audit.expire_escalation(
        "call-owner", user_id="owner", session_id="s", reason="cancelled"
    )
    if retire == "close":
        assert run(
            bridge, op="close", lease_id=lease["lease_id"], reason="completed"
        ) == {"ok": True, "status": "expired"}
    else:
        asyncio.run(bridge.service.sweep())
    assert lease_state(bridge, lease) == "expired"
    assert not decide(bridge, lease)["ok"]
    assert not open_presentation(bridge)["ok"]
    bridge.clock.now = lease["expires_at"] + 3600
    asyncio.run(bridge.service.sweep())
    assert lease_state(bridge, lease) is None
    assert bridge.audit.get_by_call_id("call-owner", user_id="owner") == record
