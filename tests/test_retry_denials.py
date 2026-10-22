"""New exact human denials invalidate older automatic retry permission."""

import json
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig
from intaris.db import Database
from intaris.evaluator import Evaluator
from intaris.session import SessionStore


@pytest.mark.parametrize(
    "case",
    ["same", "other_args", "other_tool", "other_session", "older", "new_approval"],
)
def test_retry_uses_latest_exact_human_authority(tmp_path, case):
    db = Database(DBConfig(path=str(tmp_path / "retry.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    for session_id in ("s", "other"):
        sessions.create(session_id=session_id, user_id="u", intention="Edit files")
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(
            aligned=False, risk="medium", decision="escalate", reasoning="Needs review"
        )
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
    )
    first = evaluator.evaluate(**args)
    denied_args = {**args}
    if case == "other_args":
        denied_args["args"] = {"path": "/work/b"}
    if case == "other_tool":
        denied_args["tool"] = "delete"
    if case == "other_session":
        denied_args["session_id"] = "other"
    second = evaluator.evaluate(**denied_args)
    third = evaluator.evaluate(**args) if case == "new_approval" else None
    if case == "older":
        audit.resolve_escalation(second["call_id"], "deny", user_id="u")
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    if case != "older":
        audit.resolve_escalation(second["call_id"], "deny", user_id="u")
    if third:
        audit.resolve_escalation(third["call_id"], "approve", user_id="u")
    result = evaluator.evaluate(**args)
    assert result["decision"] == ("escalate" if case == "same" else "approve")
    if case == "same":
        assert result["path"] == "llm"
        assert (
            audit.get_by_call_id(result["call_id"], user_id="u")["decision"]
            == "escalate"
        )
    db.close()


@pytest.fixture
def denial_stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "revocation.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    for user_id, session_id in (("u", "s"), ("u", "other"), ("other", "s")):
        sessions.create(
            session_id=session_id,
            user_id=user_id,
            intention="Read and edit project files",
            details={"working_directory": "/work"},
        )
    llm = MagicMock()
    llm.generate.return_value = json.dumps(
        dict(aligned=False, risk="high", decision="escalate", reasoning="Review")
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=audit)
    yield sessions, audit, evaluator
    db.close()


def _pending_denial_record(
    audit, call_id, *, user_id="u", session_id="s", tool="edit", args_hash="exact"
):
    return audit.insert(
        call_id=call_id,
        user_id=user_id,
        session_id=session_id,
        agent_id=None,
        tool=tool,
        args_redacted={"path": f"/work/{args_hash}"},
        args_hash=args_hash,
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )


def _call_only(audit, call_id, *, user_id="u"):
    # Model the durable scope claimed by a native approval lease, without
    # invoking delivery or changing the separate bridge protocol under test.
    with audit._db.cursor() as cur:
        cur.execute(
            "UPDATE audit_log SET approval_scope = 'call' WHERE call_id = ? AND user_id = ?",
            (call_id, user_id),
        )


def _approval_and_denial(audit, case):
    _pending_denial_record(audit, "grant")
    denial_user = "other" if case == "other_tenant" else "u"
    _pending_denial_record(
        audit,
        "denial",
        user_id=denial_user,
        session_id="other" if case == "other_session" else "s",
        tool="delete" if case == "other_tool" else "edit",
        args_hash="different" if case == "other_args" else "exact",
    )
    if case == "call_only":
        _call_only(audit, "denial")
    if case == "older":
        audit.resolve_escalation("denial", "deny", user_id=denial_user)
    approved = audit.resolve_escalation("grant", "approve", user_id="u")
    if case != "older":
        audit.resolve_escalation(
            "denial",
            "deny",
            user_id=denial_user,
            resolved_by="judge" if case == "judge_denial" else "user",
        )
    if case == "same_time":
        with audit._db.cursor() as cur:
            cur.execute(
                "UPDATE audit_log SET resolved_at = ? WHERE call_id = 'denial' AND user_id = 'u'",
                (approved["resolved_at"],),
            )
    if case == "expired_denial":
        audit.expire_escalation(
            "denial", user_id="u", session_id="s", reason="cancelled"
        )


@pytest.mark.parametrize(
    "case,usable",
    [
        ("same", False),
        ("same_time", False),
        ("call_only", False),
        ("expired_denial", False),
        ("other_args", True),
        ("other_tool", True),
        ("other_session", True),
        ("other_tenant", True),
        ("judge_denial", True),
        ("older", True),
    ],
)
def test_cached_source_checks_exact_latest_human_authority(denial_stores, case, usable):
    _, audit, _ = denial_stores
    _approval_and_denial(audit, case)
    assert audit.approvals_are_usable({"grant"}, user_id="u") is usable
    # Revocation changes eligibility, not the historical human resolution.
    assert audit.get_by_call_id("grant", user_id="u")["user_decision"] == "approve"


@pytest.mark.parametrize(
    "case,contains_grant",
    [("same", False), ("call_only", False), ("older", True), ("other_args", True)],
)
def test_human_guidance_does_not_offer_revoked_approval(
    denial_stores, case, contains_grant
):
    _, audit, _ = denial_stores
    _approval_and_denial(audit, case)
    records = audit.get_user_decisions("s", user_id="u")
    assert ("grant" in {row["call_id"] for row in records}) is contains_grant
    if case != "call_only":
        assert "denial" in {row["call_id"] for row in records}


@pytest.mark.parametrize("case", ["same", "call_only", "other_args", "older"])
def test_explicit_approval_id_cannot_revive_revoked_grant(denial_stores, case):
    _, audit, evaluator = denial_stores
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"path": "/work/a"},
        minimum_outcome="escalate",
    )
    first = evaluator.evaluate(**args)
    second = evaluator.evaluate(
        **{
            **args,
            "args": {"path": "/work/b"} if case == "other_args" else args["args"],
        }
    )
    if case == "call_only":
        _call_only(audit, second["call_id"])
    if case == "older":
        audit.resolve_escalation(second["call_id"], "deny", user_id="u")
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    if case != "older":
        assert (
            evaluator.evaluate(**args, approval_call_id=first["call_id"])["decision"]
            == "approve"
        )
        audit.resolve_escalation(second["call_id"], "deny", user_id="u")
    result = evaluator.evaluate(**args, approval_call_id=first["call_id"])
    expected = "deny" if case in {"same", "call_only"} else "approve"
    assert result["decision"] == expected
    assert (
        audit.get_by_call_id(result["call_id"], user_id="u")["effective_decision"]
        == expected
    )


@pytest.mark.parametrize("scope", ["reusable", "call"])
@pytest.mark.parametrize("learning", ["before_denial", "after_denial"])
def test_exact_denial_invalidates_learned_path_permission(
    denial_stores, scope, learning
):
    _, audit, evaluator = denial_stores
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"path": "/outside/a"},
    )
    first = evaluator.evaluate(**args)
    second = evaluator.evaluate(**args)
    assert first["decision"] == second["decision"] == "escalate"
    approved = audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    next_read = {**args, "args": {"path": "/outside/b"}}
    if learning == "before_denial":
        evaluator.learn_from_approved_escalation(approved)
        assert evaluator.evaluate(**next_read)["decision"] == "approve"
    if scope == "call":
        _call_only(audit, second["call_id"])
    audit.resolve_escalation(second["call_id"], "deny", user_id="u")
    if learning == "after_denial":
        # An in-flight callback can still hold the old approved record.
        evaluator.learn_from_approved_escalation(approved)
    result = evaluator.evaluate(**next_read)
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"


@pytest.mark.parametrize("revoked", ["derived", "source"])
@pytest.mark.parametrize("scope", ["reusable", "call"])
@pytest.mark.parametrize("consumer", ["cache", "retry", "judge_history"])
def test_judge_grant_and_its_human_source_both_obey_exact_denial(
    denial_stores, revoked, scope, consumer
):
    _, audit, _ = denial_stores
    _pending_denial_record(audit, "source", args_hash="source-args")
    _pending_denial_record(audit, "derived", args_hash="derived-args")
    audit.resolve_escalation("source", "approve", user_id="u")
    audit.resolve_escalation(
        "derived",
        "approve",
        user_id="u",
        resolved_by="judge",
        judge_decision="approve",
        approval_source_call_id="source",
    )
    assert audit.approvals_are_usable({"derived"}, user_id="u")
    _pending_denial_record(audit, "denial", args_hash=f"{revoked}-args")
    if scope == "call":
        _call_only(audit, "denial")
    audit.resolve_escalation("denial", "deny", user_id="u")
    if consumer == "cache":
        assert not audit.approvals_are_usable({"derived"}, user_id="u")
    elif consumer == "retry":
        assert (
            audit.find_approved_escalation(
                user_id="u",
                session_id="s",
                tool="edit",
                args_hash="derived-args",
                cutoff="0000",
            )
            is None
        )
    else:
        assert not audit.get_recent_judge_reviews(
            "s", user_id="u", before_ts="9999", before_id="zzz"
        )
    assert audit.get_by_call_id("derived", user_id="u")["user_decision"] == "approve"


def test_unrelated_denial_preserves_derived_permission(denial_stores):
    _, audit, _ = denial_stores
    _pending_denial_record(audit, "source", args_hash="source-args")
    _pending_denial_record(audit, "derived", args_hash="derived-args")
    _pending_denial_record(audit, "denial", args_hash="unrelated")
    audit.resolve_escalation("source", "approve", user_id="u")
    audit.resolve_escalation(
        "derived",
        "approve",
        user_id="u",
        resolved_by="judge",
        judge_decision="approve",
        approval_source_call_id="source",
    )
    audit.resolve_escalation("denial", "deny", user_id="u")
    assert audit.approvals_are_usable({"source", "derived"}, user_id="u")
    assert (
        audit.find_approved_escalation(
            user_id="u",
            session_id="s",
            tool="edit",
            args_hash="derived-args",
            cutoff="0000",
        )["call_id"]
        == "derived"
    )
    assert [
        row["call_id"]
        for row in audit.get_recent_judge_reviews(
            "s", user_id="u", before_ts="9999", before_id="zzz"
        )
    ] == ["derived"]


def test_fresh_human_approval_restores_only_new_permission(denial_stores):
    _, audit, evaluator = denial_stores
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"path": "/work/a"},
        minimum_outcome="escalate",
    )
    old, denied, new = (evaluator.evaluate(**args) for _ in range(3))
    audit.resolve_escalation(old["call_id"], "approve", user_id="u")
    _call_only(audit, denied["call_id"])
    audit.resolve_escalation(denied["call_id"], "deny", user_id="u")
    audit.resolve_escalation(new["call_id"], "approve", user_id="u")
    assert (
        evaluator.evaluate(**args, approval_call_id=new["call_id"])["decision"]
        == "approve"
    )
    assert (
        evaluator.evaluate(**args, approval_call_id=old["call_id"])["decision"]
        == "deny"
    )
    assert audit.approvals_are_usable({new["call_id"]}, user_id="u")
    assert not audit.approvals_are_usable({old["call_id"]}, user_id="u")
    guidance = {row["call_id"] for row in audit.get_user_decisions("s", user_id="u")}
    assert new["call_id"] in guidance
    assert old["call_id"] not in guidance


@pytest.mark.parametrize("raced", [False, True])
def test_derived_resolution_rejects_revoked_source_atomically(
    denial_stores, monkeypatch, raced
):
    from concurrent.futures import ThreadPoolExecutor

    import intaris.audit as audit_module

    _, audit, _ = denial_stores
    _pending_denial_record(audit, "source", args_hash="source-args")
    _pending_denial_record(audit, "denial", args_hash="source-args")
    _pending_denial_record(audit, "derived", args_hash="derived-args")
    audit.resolve_escalation("source", "approve", user_id="u")
    _call_only(audit, "denial")
    if raced:
        validate = audit_module.validate_approval_policy

        def deny_during_validation(*args, **kwargs):
            validate(*args, **kwargs)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(
                    audit.resolve_escalation, "denial", "deny", user_id="u"
                ).result(timeout=5)

        monkeypatch.setattr(
            audit_module, "validate_approval_policy", deny_during_validation
        )
    else:
        audit.resolve_escalation("denial", "deny", user_id="u")
    # No scope_versions: the final UPDATE must validate the source itself.
    with pytest.raises(ValueError, match="source"):
        audit.resolve_escalation(
            "derived",
            "approve",
            user_id="u",
            resolved_by="judge",
            approval_source_call_id="source",
        )
    assert audit.get_by_call_id("derived", user_id="u")["user_decision"] is None
    assert audit.get_by_call_id("denial", user_id="u")["user_decision"] == "deny"


@pytest.mark.parametrize("decision,changed", [("deny", True), ("approve", False)])
def test_call_only_denial_advances_authority_revision(denial_stores, decision, changed):
    sessions, audit, _ = denial_stores
    _pending_denial_record(audit, "call-only")
    _call_only(audit, "call-only")
    before = sessions.get("s", user_id="u")["scope_version"]
    audit.resolve_escalation("call-only", decision, user_id="u")
    after = sessions.get("s", user_id="u")["scope_version"]
    assert (after > before) is changed
    assert sessions.get("other", user_id="u")["scope_version"] == 0
    assert sessions.get("s", user_id="other")["scope_version"] == 0


def test_call_only_denial_race_blocks_stale_judge_approval(denial_stores, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    import intaris.audit as audit_module
    from intaris.audit import ScopeChangedError

    sessions, audit, _ = denial_stores
    _pending_denial_record(audit, "denial")
    _pending_denial_record(audit, "review", args_hash="other-args")
    _call_only(audit, "denial")
    version = sessions.get("s", user_id="u")["scope_version"]
    validate = audit_module.validate_approval_policy

    def deny_after_scope_check(*args, **kwargs):
        validate(*args, **kwargs)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(audit.resolve_escalation, "denial", "deny", user_id="u").result(
                timeout=5
            )

    monkeypatch.setattr(
        audit_module, "validate_approval_policy", deny_after_scope_check
    )
    with pytest.raises(ScopeChangedError):
        audit.resolve_escalation(
            "review",
            "approve",
            user_id="u",
            resolved_by="judge",
            scope_versions={"s": version},
        )
    assert audit.get_by_call_id("review", user_id="u")["user_decision"] is None
    assert audit.get_by_call_id("denial", user_id="u")["user_decision"] == "deny"


@pytest.mark.parametrize("change", ["denial", "call_only", "message", "none"])
def test_model_learned_cache_is_bound_to_scope_revision(denial_stores, change):
    _, audit, evaluator = denial_stores
    evaluator._llm.generate.return_value = json.dumps(
        dict(aligned=True, risk="low", decision="approve", reasoning="Safe read")
    )
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"path": "/outside/a"},
    )
    first = evaluator.evaluate(**args)
    assert first["decision"] == "approve"
    assert not evaluator._approved_path_sources[("u", "s")]
    if change in {"denial", "call_only"}:
        pending = evaluator.evaluate(**args, minimum_outcome="escalate")
        if change == "call_only":
            _call_only(audit, pending["call_id"])
        audit.resolve_escalation(pending["call_id"], "deny", user_id="u")
    elif change == "message":
        audit.insert(
            call_id="stop",
            user_id="u",
            session_id="s",
            agent_id=None,
            tool=None,
            args_redacted=None,
            classification=None,
            evaluation_path="reasoning",
            decision="approve",
            risk=None,
            reasoning=None,
            latency_ms=0,
            record_type="reasoning",
            content="User message: Stop reading /outside",
        )
    evaluator._llm.generate.return_value = json.dumps(
        dict(
            aligned=False,
            risk="high",
            decision="escalate",
            reasoning="Review current scope",
        )
    )
    result = evaluator.evaluate(**args)
    assert result["decision"] == ("approve" if change == "none" else "escalate")
    assert result["path"] == ("fast" if change == "none" else "llm")


def _cache_session_chain(sessions):
    sessions.create(session_id="grandparent", user_id="u", intention="Read project")
    sessions.create(
        session_id="parent",
        user_id="u",
        intention="Read project",
        parent_session_id="grandparent",
    )
    sessions.create(
        session_id="child",
        user_id="u",
        intention="Read project",
        parent_session_id="parent",
        details={"working_directory": "/work"},
    )


def _read_restriction(audit, session_id):
    audit.insert(
        call_id=f"restriction-{session_id}",
        user_id="u",
        session_id=session_id,
        agent_id=None,
        tool=None,
        args_redacted=None,
        classification=None,
        evaluation_path="reasoning",
        decision="approve",
        risk=None,
        reasoning=None,
        latency_ms=0,
        record_type="reasoning",
        content="User message: Stop reading files outside /work",
    )


@pytest.mark.parametrize("restriction", ["session", "grandparent"])
@pytest.mark.parametrize("learning", ["before_message", "after_message"])
def test_human_path_cache_respects_later_user_restriction(
    denial_stores, restriction, learning
):
    sessions, audit, evaluator = denial_stores
    if restriction == "grandparent":
        _cache_session_chain(sessions)
    session_id = "child" if restriction == "grandparent" else "s"
    args = dict(
        user_id="u",
        session_id=session_id,
        agent_id=None,
        tool="read",
        args={"path": "/outside/a"},
    )
    pending = evaluator.evaluate(**args)
    assert pending["decision"] == "escalate"
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    another_read = {**args, "args": {"path": "/outside/b"}}
    if learning == "before_message":
        evaluator.learn_from_approved_escalation(approved)
        assert evaluator.evaluate(**another_read)["decision"] == "approve"
    _read_restriction(audit, "grandparent" if restriction == "grandparent" else "s")
    if learning == "after_message":
        evaluator.learn_from_approved_escalation(approved)
    result = evaluator.evaluate(**another_read)
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"
    assert (
        audit.get_by_call_id(pending["call_id"], user_id="u")["user_decision"]
        == "approve"
    )


def test_current_human_grant_learns_with_post_resolution_ancestor_snapshot(
    denial_stores,
):
    sessions, audit, evaluator = denial_stores
    _cache_session_chain(sessions)
    args = dict(
        user_id="u",
        session_id="child",
        agent_id=None,
        tool="read",
        args={"path": "/outside/a"},
    )
    pending = evaluator.evaluate(**args)
    before = {
        session_id: sessions.get(session_id, user_id="u")["scope_version"]
        for session_id in ("child", "parent", "grandparent")
    }
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    assert approved["_approval_scope_versions"] == {
        "child": before["child"] + 1,
        "parent": before["parent"],
        "grandparent": before["grandparent"],
    }
    assert "_approval_scope_versions" not in audit.get_by_call_id(
        pending["call_id"], user_id="u"
    )
    evaluator.learn_from_approved_escalation(approved)
    result = evaluator.evaluate(**{**args, "args": {"path": "/outside/b"}})
    assert result["decision"] == "approve"
    assert result["path"] == "fast"


@pytest.mark.parametrize("record_source", ["legacy", "reloaded"])
def test_human_grant_without_transaction_snapshot_cannot_seed_path_cache(
    denial_stores, record_source
):
    _, audit, evaluator = denial_stores
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"path": "/outside/a"},
    )
    pending = evaluator.evaluate(**args)
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    if record_source == "reloaded":
        approved = audit.get_by_call_id(pending["call_id"], user_id="u")
    else:
        approved = {
            key: value
            for key, value in approved.items()
            if key != "_approval_scope_versions"
        }
    assert "_approval_scope_versions" not in approved
    evaluator.learn_from_approved_escalation(approved)
    result = evaluator.evaluate(**{**args, "args": {"path": "/outside/b"}})
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"


def test_human_approval_snapshot_precedes_post_commit_user_message(
    denial_stores, monkeypatch
):
    from contextlib import contextmanager

    sessions, audit, evaluator = denial_stores
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"path": "/outside/a"},
    )
    pending = evaluator.evaluate(**args)
    version = sessions.get("s", user_id="u")["scope_version"]
    real_cursor = audit._db.cursor
    injected = False

    @contextmanager
    def user_message_after_commit():
        nonlocal injected
        with real_cursor() as cur:
            yield cur
        if not injected:
            with real_cursor() as cur:
                cur.execute(
                    "SELECT user_decision FROM audit_log WHERE call_id = ? AND user_id = 'u'",
                    (pending["call_id"],),
                )
                row = cur.fetchone()
            if row["user_decision"] == "approve":
                injected = True
                _read_restriction(audit, "s")

    # Inject after the approval transaction commits, before resolve returns.
    # A snapshot captured by a later read would silently include the restriction.
    monkeypatch.setattr(audit._db, "cursor", user_message_after_commit)
    approved = audit.resolve_escalation(pending["call_id"], "approve", user_id="u")
    assert injected
    assert approved["_approval_scope_versions"] == {"s": version + 1}
    assert sessions.get("s", user_id="u")["scope_version"] == version + 2
    evaluator.learn_from_approved_escalation(approved)
    result = evaluator.evaluate(**{**args, "args": {"path": "/outside/b"}})
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"


def test_resolution_side_effects_carry_snapshot_only_to_path_learning(denial_stores):
    import asyncio

    from intaris.judge import resolve_with_side_effects

    _, audit, evaluator = denial_stores
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"path": "/outside/a"},
    )
    pending = evaluator.evaluate(**args)
    resolved = asyncio.run(
        resolve_with_side_effects(
            call_id=pending["call_id"],
            user_id="u",
            user_decision="approve",
            audit_store=audit,
            evaluator=evaluator,
        )
    )
    assert resolved["user_decision"] == "approve"
    assert "_approval_scope_versions" not in resolved
    assert "_approval_scope_versions" not in audit.get_by_call_id(
        pending["call_id"], user_id="u"
    )
    result = evaluator.evaluate(**{**args, "args": {"path": "/outside/b"}})
    assert result["decision"] == "approve"
    assert result["path"] == "fast"
