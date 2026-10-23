"""Read fast paths must not conceal current user and ancestor scope."""

import json
from unittest.mock import MagicMock

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig
from intaris.db import Database
from intaris.decision import EvaluationResult
from intaris.evaluator import Evaluator
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "read-scope.db")))
    sessions, audit = SessionStore(db), AuditStore(db)
    sessions.create(
        user_id="u",
        session_id="s",
        intention="Investigate project",
        details={"working_directory": "/work"},
    )
    llm, jev = MagicMock(), MagicMock()
    yield db, sessions, audit, llm, jev
    db.close()


def source(
    audit,
    text,
    *,
    session_id="s",
    user_id="u",
    metadata=None,
    call_id="source",
    user=True,
):
    audit.insert(
        call_id=call_id,
        session_id=session_id,
        user_id=user_id,
        agent_id=None,
        tool=None,
        args_redacted=metadata,
        classification=None,
        evaluation_path="reasoning",
        decision="approve",
        risk=None,
        reasoning=None,
        latency_ms=0,
        record_type="reasoning",
        content=("User message: " if user else "Agent reasoning: ") + text,
    )


def model(stores, backend, *, approve):
    _, sessions, audit, llm, jev = stores
    verdict = dict(
        aligned=approve,
        risk="low" if approve else "high",
        decision="approve" if approve else "deny",
        reasoning="Current evidence reviewed",
    )
    llm.generate.return_value = json.dumps(verdict)
    jev.evaluate_tool_call.return_value = EvaluationResult(**verdict)
    return Evaluator(
        llm=llm,
        jev=jev if backend == "jev" else None,
        session_store=sessions,
        audit_store=audit,
    )


def call(evaluator, tool="read", path="/work/docs/private.txt"):
    args = {"filePath": path} if tool == "read" else {"command": f"cat {path}"}
    return evaluator.evaluate(
        user_id="u", session_id="s", agent_id=None, tool=tool, args=args
    )


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("tool", ["read", "terminal"])
@pytest.mark.parametrize("scope", ["own", "parent", "grandparent"])
@pytest.mark.parametrize("approve", [False, True])
def test_current_sources_reach_read_evaluator(stores, backend, tool, scope, approve):
    db, sessions, audit, llm, jev = stores
    scope_id = "s"
    if scope != "own":
        sessions.create(user_id="u", session_id="grandparent", intention="Work")
        sessions.create(
            user_id="u",
            session_id="parent",
            intention="Work",
            parent_session_id="grandparent",
        )
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET parent_session_id = ? WHERE user_id = ? AND session_id = ?",
                ("parent", "u", "s"),
            )
        scope_id = scope
    text = (
        "Answer already established; read /work/docs/private.txt for supporting evidence."
        if approve
        else "Do not read /work/docs/private.txt."
    )
    source(audit, text, session_id=scope_id)
    evaluator = model(stores, backend, approve=approve)
    result = call(evaluator, tool)
    assert result["decision"] == ("approve" if approve else "deny")
    assert result["path"] == "llm"
    assert text in str(
        jev.evaluate_tool_call.call_args if backend == "jev" else llm.generate.call_args
    )
    assert audit.get_by_call_id(result["call_id"], user_id="u")["intent_evidence"]


@pytest.mark.parametrize(
    "irrelevant", ["none", "agent", "ineligible", "session", "tenant"]
)
def test_unrestricted_reads_keep_fast_path(stores, irrelevant):
    _, sessions, audit, llm, jev = stores
    kwargs = {}
    if irrelevant == "agent":
        kwargs["user"] = False
    elif irrelevant == "ineligible":
        kwargs["metadata"] = {"intention_eligible": False}
    elif irrelevant == "session":
        sessions.create(user_id="u", session_id="other", intention="Work")
        kwargs["session_id"] = "other"
    elif irrelevant == "tenant":
        sessions.create(user_id="other", session_id="s", intention="Work")
        kwargs["user_id"] = "other"
    if irrelevant != "none":
        source(audit, "Do not read /work/docs/private.txt.", **kwargs)
    result = call(model(stores, "llm", approve=False))
    assert result["decision"] == "approve"
    assert result["path"] == "fast"
    llm.generate.assert_not_called()
    jev.evaluate_tool_call.assert_not_called()


@pytest.mark.parametrize("signal", ["user_intention", "pending_source"])
def test_user_scope_without_available_source_cannot_fast_approve(stores, signal):
    db, sessions, _, llm, _ = stores
    if signal == "user_intention":
        sessions.update_session(
            "s",
            user_id="u",
            intention="Do not read private files",
            intention_source="user",
        )
    else:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET latest_user_message_seq = ? WHERE user_id = ? AND session_id = ?",
                (1, "u", "s"),
            )
    result = call(model(stores, "llm", approve=False))
    assert result["decision"] == "deny"
    llm.generate.assert_called_once()


def test_cached_parent_directory_is_not_permission_for_restricted_sibling(stores):
    _, sessions, audit, llm, _ = stores
    source(audit, "Read /shared/public.txt, but do not read /shared/private.txt.")
    evaluator = model(stores, "llm", approve=True)
    assert call(evaluator, path="/shared/public.txt")["decision"] == "approve"
    llm.generate.return_value = json.dumps(
        dict(aligned=False, risk="high", decision="deny", reasoning="Excluded target")
    )
    result = call(evaluator, path="/shared/private.txt")
    assert result["decision"] == "deny"
    assert result["path"] == "llm"
    assert llm.generate.call_count == 2


def test_new_user_message_racing_fast_path_prevents_approval(stores, monkeypatch):
    _, _, audit, _, _ = stores
    evaluator = model(stores, "llm", approve=True)
    original = audit.insert

    def insert(**kwargs):
        if kwargs.get("tool") == "read" and kwargs.get("decision") == "approve":
            source(audit, "Stop reading private files.", call_id="late")
        return original(**kwargs)

    monkeypatch.setattr(audit, "insert", insert)
    result = call(evaluator)
    assert result["decision"] == "escalate"
    assert (
        audit.get_by_call_id(result["call_id"], user_id="u")["decision"] == "escalate"
    )


def grant(
    audit,
    *,
    call_id="grant",
    path="/work/docs/public.txt",
    note=None,
    decision="approve",
):
    from intaris.evaluator import _compute_args_hash

    audit.insert(
        call_id=call_id,
        session_id="s",
        user_id="u",
        agent_id=None,
        tool="read",
        args_redacted={"filePath": path},
        args_hash=_compute_args_hash({"filePath": path}),
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=0,
    )
    return audit.resolve_escalation(call_id, decision, user_id="u", user_note=note)


@pytest.mark.parametrize("outside", [False, True])
@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_human_scope_note_cannot_be_overridden_by_same_directory_precedent(
    stores, outside, backend
):
    _, _, audit, llm, jev = stores
    directory = "/outside/docs" if outside else "/work/docs"
    grant(audit, path=directory + "/public.txt", note="Only public; never private.")
    evaluator = model(stores, backend, approve=False)
    verdict = dict(
        aligned=False,
        risk="medium",
        decision="deny",
        reasoning="Excluded by human scope note",
    )
    llm.generate.return_value = json.dumps(verdict)
    jev.evaluate_tool_call.return_value = EvaluationResult(**verdict)
    result = call(evaluator, path=directory + "/private.txt")
    assert result["decision"] != "approve"
    assert result["path"] == "llm"


@pytest.mark.parametrize("scope", ["user_intention", "pending_source"])
def test_old_exact_grant_cannot_skip_missing_current_source_review(stores, scope):
    db, sessions, audit, llm, _ = stores
    grant(audit, path="/work/docs/private.txt")
    if scope == "user_intention":
        sessions.update_session(
            "s",
            user_id="u",
            intention="Do not read private files",
            intention_source="user",
        )
    else:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET latest_user_message_seq = 1 WHERE session_id = 's' AND user_id = 'u'"
            )
    result = call(model(stores, "llm", approve=False))
    assert result["decision"] == "deny"
    llm.generate.assert_called_once()


@pytest.mark.parametrize("older", ["message", "note", "denial"])
def test_newest_bare_approval_does_not_hide_earlier_user_scope(stores, older):
    _, _, audit, llm, _ = stores
    if older == "message":
        source(audit, "Не читай приватные файлы.")
    else:
        grant(
            audit,
            call_id="older",
            note="Only public; never private." if older == "note" else None,
            decision="deny" if older == "denial" else "approve",
        )
    grant(audit, call_id="newest", path="/work/docs/other.txt")
    current = audit.get_intent_sources(
        "s", user_id="u", limit=1, include_bare_approvals=False
    )
    assert current[0]["call_id"] != "newest"
    result = call(model(stores, "llm", approve=False))
    assert result["decision"] == "deny"
    llm.generate.assert_called_once()


@pytest.mark.parametrize("note", [None, "", "  "])
def test_bare_human_approval_preserves_unrestricted_read_fast_path(stores, note):
    _, _, audit, llm, _ = stores
    grant(audit, note=note)
    result = call(model(stores, "llm", approve=False))
    assert result["decision"] == "approve"
    assert result["path"] == "fast"
    llm.generate.assert_not_called()


def test_oversized_user_source_still_requires_read_review(stores):
    from intaris.intent_evidence import MAX_SOURCE_CHARS

    _, _, audit, llm, _ = stores
    source(audit, "Do not read private files. " + "x" * MAX_SOURCE_CHARS)
    result = call(model(stores, "llm", approve=False))
    assert result["decision"] == "deny"
    assert not audit.get_by_call_id(result["call_id"], user_id="u")["intent_evidence"][
        "complete"
    ]
    llm.generate.assert_called_once()


def test_explicit_old_approval_cannot_replace_current_read_scope_review(stores):
    _, _, audit, llm, _ = stores
    grant(audit, path="/work/docs/private.txt")
    source(audit, "Do not read /work/docs/private.txt anymore.")
    evaluator = model(stores, "llm", approve=False)
    llm.generate.return_value = json.dumps(
        dict(
            aligned=False, risk="medium", decision="deny", reasoning="Newer restriction"
        )
    )
    result = evaluator.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"filePath": "/work/docs/private.txt"},
        minimum_outcome="escalate",
        approval_call_id="grant",
    )
    assert result["decision"] != "approve"
    assert result["path"] == "llm"


@pytest.mark.parametrize("parent", [False, True])
@pytest.mark.parametrize("preference", [False, True])
@pytest.mark.parametrize(
    "change", ["none", "message", "ancestor", "cwd", "note", "incomplete"]
)
def test_explicit_fresh_read_grant_requires_unchanged_scope(
    stores, parent, preference, change
):
    db, sessions, audit, llm, _ = stores
    if parent:
        sessions.create(user_id="u", session_id="parent", intention="Read project")
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET parent_session_id = 'parent' WHERE user_id = 'u' AND session_id = 's'"
            )
    source(audit, "Inspect project docs; gather supporting evidence.")
    evaluator = model(stores, "llm", approve=False)
    llm.generate.return_value = json.dumps(
        dict(
            aligned=False,
            risk="medium",
            decision="escalate",
            reasoning="Review current scope",
        )
    )
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="read",
        args={"filePath": "docs/private.txt"},
        minimum_outcome="escalate",
        context={"working_directory": "/work"},
    )
    if preference:
        args["tool_preferences"] = {"read": "escalate"}
    first = evaluator.evaluate(**args)
    assert first["decision"] == "escalate"
    assert audit.get_by_call_id(first["call_id"], user_id="u")["intent_evidence"]
    note = "Only if this file contains no credentials." if change == "note" else None
    audit.resolve_escalation(first["call_id"], "approve", user_id="u", user_note=note)
    if change == "message":
        source(audit, "Do not read private files anymore.", call_id="newer")
    elif change == "ancestor":
        if parent:
            source(
                audit, "Read public files only.", session_id="parent", call_id="newer"
            )
        else:
            sessions.update_session(
                "s",
                user_id="u",
                intention="Read public files only",
                intention_source="user",
            )
    elif change == "cwd":
        args["context"] = {"working_directory": "/secret"}
    elif change == "incomplete":
        evidence = audit.get_by_call_id(first["call_id"], user_id="u")[
            "intent_evidence"
        ]
        evidence["complete"] = False
        with db.cursor() as cur:
            cur.execute(
                "UPDATE audit_log SET intent_evidence = ? WHERE call_id = ? AND user_id = 'u'",
                (json.dumps(evidence), first["call_id"]),
            )
    result = evaluator.evaluate(**args, approval_call_id=first["call_id"])
    assert result["decision"] == ("approve" if change == "none" else "escalate")


@pytest.mark.parametrize("tool", ["files:inspect", "skill_view_raw"])
@pytest.mark.parametrize("parent", [False, True])
def test_internal_read_identity_keeps_explicit_id_scope_guard(stores, tool, parent):
    db, sessions, audit, llm, _ = stores
    if parent:
        sessions.create(user_id="u", session_id="parent", intention="Inspect docs")
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET parent_session_id = 'parent' WHERE user_id = 'u' AND session_id = 's'"
            )
    source(audit, "Inspect docs.")
    evaluator = model(stores, "llm", approve=False)
    llm.generate.return_value = json.dumps(
        dict(
            aligned=False, risk="medium", decision="escalate", reasoning="Review scope"
        )
    )
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool=tool,
        args={"path": "/outside/docs/private.txt"},
        minimum_outcome="escalate",
        trusted_readonly=tool == "files:inspect",
    )
    first = evaluator.evaluate(**args)
    assert first["decision"] == "escalate"
    audit.resolve_escalation(first["call_id"], "approve", user_id="u")
    source(
        audit,
        "Do not inspect private docs.",
        session_id="parent" if parent else "s",
        call_id="newer",
    )
    result = evaluator.evaluate(**args, approval_call_id=first["call_id"])
    assert result["decision"] == "escalate"


@pytest.mark.parametrize("backend", ["llm", "jev"])
def test_metadata_read_outside_project_keeps_human_note_constraints(stores, backend):
    _, _, audit, llm, jev = stores
    evaluator = model(stores, backend, approve=False)
    verdict = dict(
        aligned=False, risk="medium", decision="escalate", reasoning="Review scope"
    )
    llm.generate.return_value = json.dumps(verdict)
    jev.evaluate_tool_call.return_value = EvaluationResult(**verdict)
    args = dict(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool="files:inspect",
        args={"path": "/outside/docs/public.txt"},
        trusted_readonly=True,
    )
    first = evaluator.evaluate(**args)
    audit.resolve_escalation(
        first["call_id"],
        "approve",
        user_id="u",
        user_note="Only public; never private.",
    )
    result = evaluator.evaluate(
        **{**args, "args": {"path": "/outside/docs/private.txt"}}
    )
    assert result["decision"] == "escalate"


@pytest.mark.parametrize("backend", ["llm", "jev"])
@pytest.mark.parametrize("tool", ["files:inspect", "skill_view_raw"])
def test_internal_read_supporting_evidence_still_approves(stores, backend, tool):
    _, _, audit, _, _ = stores
    source(audit, "Read supporting docs even though answer is established.")
    evaluator = model(stores, backend, approve=True)
    result = evaluator.evaluate(
        user_id="u",
        session_id="s",
        agent_id=None,
        tool=tool,
        args={"path": "/outside/docs/guide.md"},
        trusted_readonly=tool == "files:inspect",
    )
    assert result["decision"] == "approve"
    assert result["path"] == "llm"
