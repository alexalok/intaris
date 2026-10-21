"""Cron presentations reuse the native transport and never impersonate a sender."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from .test_native import Context, actionable, click, native_module, until
from .test_native import harness as harness


@pytest.mark.parametrize("decision", ["a", "d"])
@pytest.mark.parametrize("shared", [False, True])
def test_cron_uses_operator_transport_and_call_specific_decision(
    harness, shared, decision
):
    h = harness
    home = "/profiles/beta" if shared else "/profiles/alpha"
    owner = native_module().NativeApprovals(home, Context()) if shared else h.native
    h.server.transport_profiles[home] = "/profiles/alpha"
    h.server.open_reply["route"]["actor_ids"] = ["8", "9"]
    request = SimpleNamespace(
        profile_home=home,
        job_id="job",
        execution_id="exec",
        session_id="hermes-root",
        external_session_id="hm-cron",
        call_id="cron-call",
        invocation_id="inv-1",
        deadline=h.budget._deadline,
    )
    try:
        assert hasattr(owner, "present_cron"), "Gateway lacks cron presentation adapter"
        with owner.present_cron(request, h.budget):
            until(lambda: actionable(h))
            opened = h.server.ops("open_presentation")[0]
            assert opened["session_id"] == "hm-cron"
            assert opened["call_id"] == "cron-call"
            assert opened["profile"] == home
            assert (
                "origin" not in opened
            )  # Even a colliding real Telegram session is not an origin.
            assert h.lookups == []
            if "presentation" in h.server.open_reply:
                assert h.app.bot.api_requests[0][0] == "sendRichMessage"
                assert (
                    h.app.bot.sends[0]["rich_message"]["html"]
                    == h.server.open_reply["presentation"]["pending"]
                )
            else:
                assert h.app.bot.sends[0]["parse_mode"] is None
            click(h, actor="8", decision=decision).result(3)
            assert h.server.status == ("approve" if decision == "a" else "deny")
            click(h, actor="8", decision=decision).result(3)
            assert len(h.server.ops("resolve")) == 1
    finally:
        if shared:
            owner.dispose()


def test_cron_wait_keeps_original_budget_even_when_presentation_unavailable(harness):
    h = harness
    requests = []

    @contextmanager
    def pending(**kwargs):
        requests.append(kwargs)
        yield

    h.native._cron = SimpleNamespace(available=False, pending=pending)
    h.native._cron_execution = lambda: SimpleNamespace(
        job_id="job", execution_id="fire"
    )
    with h.native.pending("cron-1", "audit-1", h.budget, intaris_session_id="hm-1"):
        assert requests, "Cron invocation attempted interactive presentation"
        assert requests[0]["deadline"] == h.budget._deadline
        assert requests[0]["session_id"] == "cron-1"
        assert requests[0]["external_session_id"] == "hm-1"
    assert h.server.requests == []


def test_cron_without_presentation_service_keeps_audit_wait(harness):
    h = harness
    h.native._cron = None
    h.native._cron_execution = lambda: SimpleNamespace(
        job_id="job", execution_id="fire"
    )
    with h.native.pending(
        "hermes-root", "audit-1", h.budget, intaris_session_id="hm-1"
    ):
        assert h.server.requests == []
        assert h.lookups == []


def test_presentation_deadline_requires_existing_human_budget(harness):
    from hermes_intaris.waits import WaitStopped

    budget = harness.budget
    assert budget.deadline == budget._deadline
    budget._deadline = None
    with pytest.raises(WaitStopped, match="active human-wait window"):
        _ = budget.deadline


def test_cron_profile_mismatch_never_opens(harness):
    h = harness
    request = SimpleNamespace(profile_home="/profiles/wrong")
    assert hasattr(h.native, "present_cron")
    with pytest.raises(ValueError):
        with h.native.present_cron(request, h.budget):
            pytest.fail("Wrong profile admitted")
    assert h.server.requests == []
