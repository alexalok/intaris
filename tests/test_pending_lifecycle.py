"""Pending approvals cannot restart stopped work."""

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig
from intaris.db import Database
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "lifecycle.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(session_id="s", user_id="u", intention="Edit files")
    audit.insert(
        call_id="pending",
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args_redacted={"path": "/work/a"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )
    yield sessions, audit
    db.close()


@pytest.mark.parametrize(
    "status", ["active", "idle", "completed", "suspended", "terminated"]
)
@pytest.mark.parametrize("resolved_by", ["user", "judge"])
@pytest.mark.parametrize("late", [False, True])
def test_only_running_sessions_can_receive_pending_approval(
    stores, monkeypatch, status, resolved_by, late
):
    import intaris.audit as module

    sessions, audit = stores

    def change():
        if status != "active":
            sessions.update_status("s", status, user_id="u")

    if late:
        validate = module.validate_approval_policy

        def race(*args, **kwargs):
            validate(*args, **kwargs)
            change()

        monkeypatch.setattr(module, "validate_approval_policy", race)
    else:
        change()
    if status in {"active", "idle"}:
        record = audit.resolve_escalation(
            "pending", "approve", user_id="u", resolved_by=resolved_by
        )
        assert record["user_decision"] == "approve"
    else:
        with pytest.raises(
            ValueError, match="Session.*(stopped|completed|suspended|terminated)"
        ):
            audit.resolve_escalation(
                "pending", "approve", user_id="u", resolved_by=resolved_by
            )
        record = audit.get_by_call_id("pending", user_id="u")
        assert record["user_decision"] is None
        assert record["effective_decision"] == "escalate"


@pytest.mark.parametrize("status", ["completed", "suspended", "terminated"])
def test_pending_denial_still_allowed_after_stop(stores, status):
    sessions, audit = stores
    sessions.update_status("s", status, user_id="u")
    assert (
        audit.resolve_escalation("pending", "deny", user_id="u")["user_decision"]
        == "deny"
    )
