"""New authenticated scope notes must supersede mechanical old approvals."""

import json
from types import SimpleNamespace

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig
from intaris.db import Database
from intaris.decision import EvaluationResult
from intaris.evaluator import Evaluator, _compute_args_hash
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "scope-notes.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    for user_id, session_id in (("u", "s"), ("u", "other"), ("other", "s")):
        sessions.create(
            session_id=session_id, user_id=user_id, intention="Edit project files"
        )
    yield db, sessions, audit
    db.close()


def resolve(
    stores,
    call_id,
    *,
    path="/work/a",
    tool="edit",
    decision="approve",
    note=None,
    user_id="u",
    session_id="s",
    resolved_by="user",
    note_source=None,
    call_only=False,
):
    db, _, audit = stores
    args = {"path": path}
    audit.insert(
        call_id=call_id,
        session_id=session_id,
        user_id=user_id,
        agent_id=None,
        tool=tool,
        args_redacted=args,
        args_hash=_compute_args_hash(args),
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )
    if call_only:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE audit_log SET approval_scope = 'call' WHERE user_id = ? AND call_id = ?",
                (user_id, call_id),
            )
    return audit.resolve_escalation(
        call_id,
        decision,
        user_id=user_id,
        user_note=note,
        resolved_by=resolved_by,
        user_note_source=note_source,
    )


def evaluate(
    stores,
    *,
    backend="llm",
    risk="medium",
    verdict="deny",
    preference=False,
    approval_id=None,
    path="/work/a",
):
    _, sessions, audit = stores
    result = dict(
        aligned=verdict == "approve",
        risk=risk,
        decision=verdict,
        reasoning="Current scope assessed",
    )
    evaluator = Evaluator(
        llm=SimpleNamespace(generate=lambda *args, **kwargs: json.dumps(result)),
        jev=SimpleNamespace(
            evaluate_tool_call=lambda **kwargs: EvaluationResult(**result)
        )
        if backend == "jev"
        else None,
        session_store=sessions,
        audit_store=audit,
    )
    return evaluator.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args={"path": path},
        tool_preferences={"edit": "escalate"} if preference else None,
        minimum_outcome="escalate" if approval_id else None,
        approval_call_id=approval_id,
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("risk", ["medium", "high"])
@pytest.mark.parametrize("decision", ["approve", "deny"])
@pytest.mark.parametrize("other_tool", ["edit", "write"])
def test_new_human_note_requires_current_assessment(
    stores, backend, risk, decision, other_tool
):
    resolve(stores, "grant")
    resolve(
        stores,
        "note",
        path="/other/b",
        tool=other_tool,
        decision=decision,
        note="Do not edit /work/a anymore.",
    )
    result = evaluate(stores, backend=backend, risk=risk)
    assert result["decision"] != "approve"
    assert result["path"] == "llm"
    record = stores[2].get_by_call_id(result["call_id"], user_id="u")
    assert any(s["id"] == "note" for s in record["intent_evidence"]["sources"])


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_preference_retry_cannot_skip_new_human_note(stores, decision):
    resolve(stores, "grant")
    resolve(
        stores,
        "note",
        path="/other/b",
        decision=decision,
        note="Do not edit /work/a anymore.",
    )
    assert evaluate(stores, preference=True)["decision"] == "escalate"


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("verdict", ["deny", "escalate", "approve"])
def test_new_note_uses_model_outcome_without_old_grant_override(
    stores, backend, explicit, verdict
):
    resolve(stores, "grant")
    resolve(
        stores,
        "note",
        path="/other/b",
        decision="approve",
        note="Only docs may change; keep /work/a unchanged.",
    )
    result = evaluate(
        stores,
        backend=backend,
        verdict=verdict,
        approval_id="grant" if explicit else None,
    )
    assert result["decision"] == ("approve" if verdict == "approve" else "escalate")
    assert result["path"] == "llm"


@pytest.mark.parametrize(
    "case",
    [
        "older_note",
        "grant_note",
        "other_session",
        "other_tenant",
        "call_only",
        "system_note",
        "judge_note",
        "empty_note",
        "blank_note",
        "no_note",
        "bare_denial",
        "new_exact_approval",
    ],
)
def test_exact_retry_preserves_unrelated_or_older_grants(stores, case):
    if case == "older_note":
        resolve(
            stores, "note", path="/other/b", decision="deny", note="Old restriction"
        )
    resolve(
        stores,
        "grant",
        note="Approve this exact edit" if case == "grant_note" else None,
    )
    if case not in {"older_note", "grant_note"}:
        kwargs = dict(path="/other/b", note="Do not edit /work/a anymore.")
        if case == "other_session":
            kwargs["session_id"] = "other"
        elif case == "other_tenant":
            kwargs["user_id"] = "other"
        elif case == "call_only":
            kwargs["call_only"] = True
        elif case == "system_note":
            kwargs["note_source"] = "system"
        elif case == "judge_note":
            kwargs["resolved_by"] = "judge"
        elif case in {"empty_note", "blank_note", "no_note", "bare_denial"}:
            kwargs["note"] = {
                "empty_note": "",
                "blank_note": "  ",
                "no_note": None,
                "bare_denial": None,
            }[case]
            kwargs["decision"] = "deny" if case == "bare_denial" else "approve"
        resolve(stores, "note", **kwargs)
        if case == "new_exact_approval":
            resolve(stores, "latest")
    result = evaluate(stores)
    assert result["decision"] == "approve"
    assert result["path"] == "fast"


def test_equal_timestamp_different_note_does_not_prove_unchanged_scope(stores):
    approved = resolve(stores, "grant")
    resolve(stores, "note", path="/other/b", decision="deny", note="Stop edits")
    with stores[0].cursor() as cur:
        cur.execute(
            "UPDATE audit_log SET resolved_at = ? WHERE call_id = 'note'",
            (approved["resolved_at"],),
        )
    result = evaluate(stores)
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"


def test_current_but_unrelated_note_can_still_be_approved_by_model(stores):
    resolve(stores, "grant")
    resolve(stores, "note", path="/other/b", note="Do not touch /other/secrets.")
    result = evaluate(stores, verdict="approve")
    assert result["decision"] == "approve"
    assert result["path"] == "llm"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["auto", "advisory"])
@pytest.mark.parametrize("verdict", ["deny", "defer", "approve"])
async def test_judge_cannot_restore_precedent_over_newer_human_note(
    stores, mode, verdict
):
    from intaris.config import JudgeConfig
    from intaris.judge import JudgeReviewer

    _, sessions, audit = stores
    resolve(stores, "grant")
    resolve(
        stores,
        "note",
        path="/other/b",
        note="Only docs may change; keep /work/a unchanged.",
    )
    # Pending sibling bypasses exact-retry selection but matches the older grant's family.
    audit.insert(
        call_id="pending",
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args_redacted={"path": "/work/b"},
        args_hash=_compute_args_hash({"path": "/work/b"}),
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )
    model = SimpleNamespace(
        _timeout_ms=15000,
        generate=lambda *args, **kwargs: json.dumps(
            dict(
                decision=verdict,
                confidence="high",
                risk="medium",
                reasoning="Current scope assessed",
            )
        ),
    )
    evaluator = Evaluator(llm=model, session_store=sessions, audit_store=audit)
    reviewer = JudgeReviewer(
        config=JudgeConfig(mode=mode),
        llm=model,
        audit_store=audit,
        session_store=sessions,
        evaluator=evaluator,
    )
    await reviewer.review_and_resolve(call_id="pending", user_id="u", session_id="s")
    row = audit.get_by_call_id("pending", user_id="u")
    if verdict == "approve":
        assert row["user_decision"] == "approve"
        assert row["approval_source_call_id"] is None
    else:
        assert row["user_decision"] == (None if mode == "advisory" else "deny")


@pytest.mark.parametrize(
    "case", ["own_note", "older_note", "system_note", "bare_decision"]
)
def test_precedent_keeps_selected_grant_without_new_human_scope(stores, case):
    if case == "older_note":
        resolve(stores, "note", path="/other/b", note="Old constraint")
    resolve(
        stores, "grant", note="Project edits allowed" if case == "own_note" else None
    )
    if case in {"system_note", "bare_decision"}:
        resolve(
            stores,
            "note",
            path="/other/b",
            note="System attribution" if case == "system_note" else None,
            note_source="system" if case == "system_note" else None,
        )
    result = evaluate(stores, path="/work/b")
    assert result["decision"] == "approve"
    assert result["path"] == "llm"


def test_derived_judge_timestamp_does_not_hide_intervening_human_note(stores):
    resolve(stores, "grant")
    resolve(stores, "note", path="/other/b", note="Do not edit /work/a anymore.")
    _, _, audit = stores
    audit.insert(
        call_id="derived",
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="edit",
        args_redacted={"path": "/work/a"},
        args_hash=_compute_args_hash({"path": "/work/a"}),
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Old mechanical grant",
        latency_ms=0,
    )
    audit.resolve_escalation(
        "derived",
        "approve",
        user_id="u",
        resolved_by="judge",
        approval_source_call_id="grant",
    )
    result = evaluate(stores)
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"


def test_explicit_old_id_considers_new_parent_scope_note(stores):
    _, sessions, _ = stores
    sessions.create(
        session_id="child", user_id="u", intention="Edit files", parent_session_id="s"
    )
    resolve(stores, "grant", session_id="child")
    resolve(stores, "note", path="/other/b", note="Do not edit /work/a anymore.")
    # Exercise the same evaluator using the child session rather than test helper's root.
    evaluator = Evaluator(
        llm=SimpleNamespace(
            generate=lambda *args, **kwargs: json.dumps(
                dict(
                    aligned=False,
                    risk="medium",
                    decision="deny",
                    reasoning="Parent restriction",
                )
            )
        ),
        session_store=sessions,
        audit_store=stores[2],
    )
    result = evaluator.evaluate(
        user_id="u",
        session_id="child",
        agent_id=None,
        tool="edit",
        args={"path": "/work/a"},
        minimum_outcome="escalate",
        approval_call_id="grant",
    )
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"
