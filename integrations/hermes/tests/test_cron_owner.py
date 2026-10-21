"""Real Hermes execution scope and Intaris poll/native callbacks; Telegram/HTTP are simulated."""

import importlib
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from .test_native import Context, actionable, click, native_module, until
from .test_native import harness as harness


@pytest.fixture(autouse=True)
def hermes_host(monkeypatch):
    source = os.environ.get("HERMES_SOURCE")
    if not source:
        pytest.skip("HERMES_SOURCE is required for the real host contract")
    monkeypatch.syspath_prepend(source)
    modules = {
        name: importlib.import_module(name)
        for name in (
            "hermes_constants",
            "cron.approval_relay_scope",
            "cron.execution_identity",
            "gateway.session_cron",
            "hermes_cli.plugins_cron_approvals",
            "hermes_cli.profiles",
            "tools.approval_context",
            "tools.interrupt",
            "agent.deadline",
        )
    }
    return modules


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize(
    "outcome",
    [
        "approve",
        "deny",
        "cancel",
        "drain",
        "drain_before",
        "approve_then_cancel",
        "deadline",
        "client_expired",
        "ui_note",
        "system_note",
    ],
)
def test_native_cron_preserves_original_poll_and_avoids_interactive_fallback(
    hermes_host, harness, shared, outcome, monkeypatch
):
    from hermes_intaris import _poll_escalation
    from hermes_intaris.client import ApiResult
    from hermes_intaris.waits import Invocation, WaitStopped

    h = harness
    h.server.status = None
    h.server.open_reply["route"]["actor_ids"] = ["8", "9"]
    monkeypatch.setattr(
        hermes_host["tools.approval_context"], "_get_approval_timeout", lambda: 300
    )
    home = "/profiles/beta" if shared else "/profiles/alpha"
    native = native_module().NativeApprovals(home, Context()) if shared else h.native
    constants = hermes_host["hermes_constants"]
    monkeypatch.setitem(sys.modules, "agent.deadline", hermes_host["agent.deadline"])
    for name, value in vars(constants).items():
        if not hasattr(sys.modules["hermes_constants"], name):
            monkeypatch.setattr(
                sys.modules["hermes_constants"], name, value, raising=False
            )
    scopes = hermes_host["cron.approval_relay_scope"]
    identity = hermes_host["cron.execution_identity"]
    owners = hermes_host["gateway.session_cron"]
    service_class = hermes_host["hermes_cli.plugins_cron_approvals"].CronApprovalService
    profile_token = constants.set_hermes_home_override(Path(home))
    ctx = SimpleNamespace(
        plugin_id="intaris",
        _load_abandoned=False,
        on_unload=lambda fn: SimpleNamespace(dispose=lambda: None),
    )
    service = service_class(ctx)
    registration = service.register_presenter(native.present_cron)
    native._cron = service
    native._cron_execution = identity.current_cron_execution
    h.server.transport_profiles[home] = "/profiles/alpha"
    owner = SimpleNamespace(
        db=SimpleNamespace(db_path=Path(home) / "state.db"),
        runner=SimpleNamespace(_draining=outcome == "drain_before"),
        retired=False,
    )
    ended, polled, release = threading.Event(), threading.Event(), threading.Event()
    results, failures, cancellations, invocations, notes = [], [], [], [], []

    def fetch(call_id):
        assert call_id == "call"
        polled.set()
        assert release.wait(5)
        data = {"user_decision": h.server.status}
        if outcome == "client_expired":
            data.update(
                expired_at="2026-01-01T00:00:00Z", expiration_reason="cancelled"
            )
        if outcome in ("ui_note", "system_note"):
            data.update(
                user_note="Use staging only",
                resolved_by="user",
                user_note_source="user" if outcome == "ui_note" else "system",
            )
        return ApiResult(data=data)

    def run():
        token = constants.set_hermes_home_override(Path(home))
        cron_token = identity.enter_cron_execution({"id": "daily"}, "fire", {})
        owner_token = owners.bind_execution(owner, "cron-session", "daily", "fire")
        hermes_host["tools.approval_context"].set_current_session_key("cron-test")
        invocation = Invocation(ended, 10)
        invocations.append(invocation)
        try:
            with scopes.presentation_scope(ended):
                scopes.bind_agent(SimpleNamespace(session_id="cron-session"))
                profile = SimpleNamespace(
                    client=SimpleNamespace(get_audit=fetch), native_approvals=native
                )
                try:
                    result = _poll_escalation(
                        profile,
                        "call",
                        "tool",
                        invocation,
                        session_id="cron-session",
                        intaris_session_id="audit-session",
                    )
                    invocation.check()
                    notes.append(result.user_note)
                    results.append(
                        "dispatch" if result.value == "approve" else result.value
                    )
                except WaitStopped as exc:
                    cancellations.append(str(exc))
                    results.append("cancelled")
        except BaseException as exc:
            failures.append(exc)
        finally:
            invocation.close()
            owners._execution.reset(owner_token)
            identity.exit_cron_execution(cron_token)
            constants.reset_hermes_home_override(token)

    thread = threading.Thread(target=run)
    try:
        thread.start()
        assert polled.wait(5), (failures, results, cancellations)
        if outcome == "drain_before":
            assert h.app.bot.sends == []
            assert h.lookups == []
            h.server.status = "approve"
        else:
            until(lambda: actionable(h))
            assert h.lookups == []
            if outcome in (
                "approve",
                "deny",
                "approve_then_cancel",
                "deadline",
                "client_expired",
                "system_note",
            ):
                click(h, actor="8", decision="d" if outcome == "deny" else "a").result(
                    3
                )
                if outcome == "approve_then_cancel":
                    ended.set()
                elif outcome == "deadline":
                    invocations[0]._deadline = time.monotonic() - 1
            elif outcome == "cancel":
                ended.set()
            elif outcome == "ui_note":
                h.server.status = "approve"
            else:
                owner.runner._draining = True
                until(lambda: not actionable(h))
                assert h.server.status is None
                h.server.status = (
                    "approve"  # external audit decision still reaches original poll
                )
        release.set()
        thread.join(10)
        assert not thread.is_alive()
        assert failures == []
        assert results == [
            {
                "approve": "dispatch",
                "deny": "deny",
                "cancel": "cancelled",
                "drain": "dispatch",
                "drain_before": "dispatch",
                "approve_then_cancel": "cancelled",
                "deadline": "cancelled",
                "client_expired": "expired",
                "ui_note": "dispatch",
                "system_note": "dispatch",
            }[outcome]
        ]
        if outcome == "ui_note":
            assert notes == ["Use staging only"]
        elif outcome not in ("cancel", "approve_then_cancel", "deadline"):
            assert notes == [None]
        until(lambda: not actionable(h))
        if outcome != "drain_before":
            before = h.server.status
            click(h, actor="8", decision="a").result(3)
            assert h.server.status == before
        assert len(h.app.bot.sends) == (0 if outcome == "drain_before" else 1)
    finally:
        ended.set()
        release.set()
        thread.join(10)
        service.close()
        registration.dispose()
        constants.reset_hermes_home_override(profile_token)
        if shared:
            native.dispose()
