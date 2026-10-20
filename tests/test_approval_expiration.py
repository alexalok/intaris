"""Approval lifecycle regression tests using real database transactions."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from intaris.audit import AuditStore
from intaris.config import DBConfig
from intaris.db import Database
from intaris.session import SessionStore


@pytest.fixture
def store(tmp_path):
    db = Database(DBConfig(path=str(tmp_path / "audit.db")))
    SessionStore(db).create(user_id="tenant", session_id="session", intention="Test")
    store = AuditStore(db)
    store.insert(
        call_id="call",
        user_id="tenant",
        session_id="session",
        agent_id="hermes",
        tool="terminal",
        args_redacted={"command": "pwd"},
        args_hash="hash",
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Needs approval",
        latency_ms=1,
    )
    yield store
    db.close()


def expire(store, reason="timeout", **kwargs):
    return store.expire_escalation(
        "call",
        user_id=kwargs.get("user_id", "tenant"),
        session_id=kwargs.get("session_id", "session"),
        reason=reason,
    )


def test_expiration_preserves_evaluation_and_is_idempotent(store):
    before = store.get_by_call_id("call", user_id="tenant")
    result = expire(store)
    assert result["expired_at"]
    assert result["expiration_reason"] == "timeout"
    for field in (
        "decision",
        "reasoning",
        "effective_decision",
        "user_decision",
        "resolved_at",
        "resolved_by",
    ):
        assert result[field] == before[field]
    assert expire(store, "cancelled") == result
    assert (
        store.query(user_id="tenant", decision="escalate", resolved=False)["total"] == 0
    )
    closed = store.query(user_id="tenant", decision="escalate", resolved=True)
    assert closed["total"] == 1
    assert closed["items"][0]["expiration_reason"] == "timeout"


@pytest.mark.parametrize("resolver", ["user", "judge"])
def test_late_resolution_cannot_revive_expired_invocation(store, resolver):
    expire(store)
    with pytest.raises(ValueError, match="expired"):
        store.resolve_escalation(
            "call", "approve", user_id="tenant", resolved_by=resolver
        )
    assert store.get_by_call_id("call", user_id="tenant")["user_decision"] is None


@pytest.mark.parametrize("resolver", ["user", "judge"])
def test_expiration_after_raced_approval_keeps_history_but_disables_reuse(
    store, resolver
):
    approved = store.resolve_escalation(
        "call", "approve", user_id="tenant", resolved_by=resolver
    )
    expired = expire(store, "cancelled")
    assert expired["user_decision"] == "approve"
    assert expired["resolved_at"] == approved["resolved_at"]
    assert expired["resolved_by"] == resolver
    assert expired["expired_at"]
    assert (
        store.find_approved_escalation(
            user_id="tenant", tool="terminal", args_hash="hash", cutoff="2000"
        )
        is None
    )
    with pytest.raises(ValueError, match="expired"):
        store.resolve_escalation("call", "deny", user_id="tenant")


@pytest.mark.parametrize("scope", [{"user_id": "other"}, {"session_id": "other"}])
def test_expiration_requires_matching_tenant_and_session(store, scope):
    with pytest.raises(ValueError):
        expire(store, **scope)
    assert store.get_by_call_id("call", user_id="tenant").get("expired_at") is None
    assert store.query(user_id="tenant", resolved=False)["total"] == 1


def test_old_and_completed_session_approvals_do_not_expire_without_signal(store):
    with store._db.cursor() as cur:
        cur.execute("UPDATE audit_log SET timestamp = '2000-01-01'")
        cur.execute("UPDATE sessions SET status = 'completed'")
    assert (
        store.query(user_id="tenant", decision="escalate", resolved=False)["total"] == 1
    )
    assert (
        store.resolve_escalation("call", "approve", user_id="tenant")["user_decision"]
        == "approve"
    )


def test_resolution_expiration_race_is_terminal(store):
    barrier = Barrier(2)

    def resolve():
        barrier.wait()
        try:
            store.resolve_escalation("call", "approve", user_id="tenant")
            return "approved"
        except ValueError as exc:
            assert "expired" in str(exc)
            return "expired"

    def retire():
        barrier.wait()
        return expire(store)

    with ThreadPoolExecutor(max_workers=2) as pool:
        approval = pool.submit(resolve)
        expiration = pool.submit(retire)
        assert expiration.result()["expired_at"]
        assert approval.result() in {"approved", "expired"}
    final = store.get_by_call_id("call", user_id="tenant")
    assert final["expired_at"]
    assert store.query(user_id="tenant", resolved=False)["total"] == 0
    assert (
        store.find_approved_escalation(
            user_id="tenant", tool="terminal", args_hash="hash", cutoff="2000"
        )
        is None
    )


def test_expiration_rejects_non_escalation_and_invalid_reason(store):
    with pytest.raises(ValueError):
        expire(store, "guessed_from_age")
    with store._db.cursor() as cur:
        cur.execute("UPDATE audit_log SET decision='approve'")
    with pytest.raises(ValueError):
        expire(store)


def test_inline_judge_result_cannot_approve_expired_invocation(store):
    from intaris.judge import _effective_outcome_from_record

    store.resolve_escalation("call", "approve", user_id="tenant", resolved_by="judge")
    record = expire(store)
    outcome = _effective_outcome_from_record(record)
    assert outcome.decision == "deny"
    assert "expired" in outcome.reasoning.lower()
    assert outcome.record["user_decision"] == "approve"


def test_schema_upgrade_keeps_legacy_pending_records(tmp_path):
    import sqlite3
    from unittest.mock import MagicMock

    from intaris.db import _SCHEMA_SQL_SQLITE

    path = str(tmp_path / "legacy.db")
    with sqlite3.connect(path) as conn:
        conn.executescript(_SCHEMA_SQL_SQLITE)
        # Emulate an installation that predates expiration columns.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
        for column in ("expired_at", "expiration_reason", "approval_source_call_id"):
            if column in columns:
                conn.execute(f"ALTER TABLE audit_log DROP COLUMN {column}")
        conn.execute(
            "INSERT INTO sessions (user_id, session_id, intention, created_at, updated_at) VALUES ('u','s','Test','2000','2000')"
        )
        conn.execute(
            "INSERT INTO audit_log (id, call_id, user_id, session_id, timestamp, decision, evaluation_path, latency_ms) VALUES ('id','legacy','u','s','2000','escalate','llm',1)"
        )
    for _ in range(2):
        db = Database(DBConfig(path=path))
        record = AuditStore(db).get_by_call_id("legacy", user_id="u")
        assert record["expired_at"] is None
        assert record["expiration_reason"] is None
        assert AuditStore(db).query(user_id="u", resolved=False)["total"] == 1
        db.close()
    conn = MagicMock()
    conn.cursor.return_value.fetchone.return_value = None
    db = Database.__new__(Database)
    db._migrate_pg(conn)
    sql = [call.args[0] for call in conn.cursor.return_value.execute.call_args_list]
    for column in ("expired_at", "expiration_reason", "approval_source_call_id"):
        assert f"ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS {column} TEXT" in sql


@pytest.mark.asyncio
async def test_resolution_superseded_by_expiry_returns_history_without_side_effects(
    store, monkeypatch
):
    from types import SimpleNamespace

    from intaris.judge import resolve_with_side_effects

    resolve = store.resolve_escalation

    def raced_resolution(*args, **kwargs):
        record = resolve(*args, **kwargs)
        expire(store)
        return record

    monkeypatch.setattr(store, "resolve_escalation", raced_resolution)
    effects = []
    result = await resolve_with_side_effects(
        call_id="call",
        user_id="tenant",
        user_decision="approve",
        audit_store=store,
        evaluator=SimpleNamespace(learn_from_approved_escalation=effects.append),
        event_bus=SimpleNamespace(publish=effects.append),
    )
    assert result["expired_at"]
    assert result["user_decision"] == "approve"
    assert effects == []


@pytest.mark.asyncio
async def test_judge_does_not_send_stale_escalation_notification(store):
    from types import SimpleNamespace

    from intaris.config import JudgeConfig
    from intaris.judge import JudgeReviewer

    notifications = []

    async def notify(**kwargs):
        notifications.append(kwargs)

    reviewer = JudgeReviewer(
        llm=None,
        config=JudgeConfig(mode="advisory"),
        audit_store=store,
        session_store=SessionStore(store._db),
        evaluator=None,
        notification_dispatcher=SimpleNamespace(notify=notify),
    )
    expire(store)
    await reviewer._send_escalation_notification(
        call_id="call", user_id="tenant", session_id="session"
    )
    assert notifications == []


@pytest.mark.asyncio
async def test_mcp_retry_executes_approved_call_but_never_reuses_expired_approval(
    store,
):
    from types import SimpleNamespace

    from mcp.types import CallToolResult, TextContent

    from intaris.evaluator import Evaluator
    from intaris.mcp.proxy import MCPProxy

    executed = []

    async def call_tool(**kwargs):
        executed.append(kwargs["arguments"])
        return CallToolResult(content=[TextContent(type="text", text="saved")])

    async def connect(**kwargs):
        return SimpleNamespace(call_tool=call_tool)

    sessions = SessionStore(store._db)
    proxy = MCPProxy(
        connection_manager=SimpleNamespace(get_or_connect=connect),
        evaluator=Evaluator(llm=None, session_store=sessions, audit_store=store),
        session_store=sessions,
        audit_store=store,
        server_store=SimpleNamespace(
            get_all_tool_preferences=lambda **kw: {"files:save": "escalate"},
            get_server=lambda **kw: {
                "name": "files",
                "transport": "streamable-http",
                "url": "https://example.test/mcp",
            },
        ),
    )

    async def call(value):
        return await proxy.call_tool_rest(
            user_id="tenant",
            agent_id="client",
            session_id="session",
            server_name="files",
            tool_name="save",
            arguments={"value": value},
        )

    waiting = await call("live")
    assert waiting["decision"] == "escalate"
    assert not store.get_by_call_id(waiting["call_id"], user_id="tenant")["expired_at"]
    assert executed == []
    store.resolve_escalation(waiting["call_id"], "approve", user_id="tenant")
    assert (await call("live"))["decision"] == "approve"
    assert executed == [{"value": "live"}]
    abandoned = await call("abandoned")
    store.resolve_escalation(abandoned["call_id"], "approve", user_id="tenant")
    store.expire_escalation(
        abandoned["call_id"], user_id="tenant", session_id="session", reason="abandoned"
    )
    assert (await call("abandoned"))["decision"] == "escalate"
    assert executed == [{"value": "live"}]


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_expired_human_approval_cannot_be_authoritative_precedent(store, decision):
    from intaris.judge import _apply_authoritative_user_precedent

    store.resolve_escalation("call", decision, user_id="tenant")
    assert store.get_user_decisions("session", user_id="tenant")
    expire(store)
    decisions = store.get_user_decisions("session", user_id="tenant")
    # Abandonment removes grants, but does not erase a human's refusal.
    assert [row["user_decision"] for row in decisions] == (
        [] if decision == "approve" else ["deny"]
    )
    verdict, confidence, _, _ = _apply_authoritative_user_precedent(
        decision="deny",
        confidence="medium",
        reasoning="Unaligned operation",
        tool="terminal",
        args_redacted={"command": "pwd"},
        risk="medium",
        user_decisions=decisions,
    )
    assert (verdict, confidence) == ("deny", "medium")
    assert store.get_by_call_id("call", user_id="tenant")["user_decision"] == decision


@pytest.mark.parametrize("consumer", ["evaluator", "judge"])
@pytest.mark.parametrize("derived", [False, True])
def test_expired_approval_history_is_not_presented_as_scope_guidance(
    store, consumer, derived
):
    from intaris.judge import _build_judge_prompt
    from intaris.prompts import build_evaluation_user_prompt

    store.resolve_escalation(
        "call", "approve", user_id="tenant", user_note="Allow this operation"
    )
    if derived:
        store.insert(
            call_id="derived",
            user_id="tenant",
            session_id="session",
            agent_id="hermes",
            tool="terminal",
            args_redacted={"command": "pwd"},
            classification="write",
            evaluation_path="llm",
            decision="escalate",
            risk="medium",
            reasoning="Review",
            latency_ms=1,
        )
        store.resolve_escalation(
            "derived",
            "approve",
            user_id="tenant",
            resolved_by="judge",
            approval_source_call_id="call",
            user_note="Allow this operation",
        )
    expire(store)
    kwargs = dict(
        intention="Test",
        policy=None,
        recent_history=store.get_recent("session", user_id="tenant"),
        session_stats={},
        tool="terminal",
        agent_id=None,
    )
    if consumer == "evaluator":
        prompt = build_evaluation_user_prompt(args={}, **kwargs)
    else:
        prompt = _build_judge_prompt(
            args_redacted={},
            evaluator_reasoning="Review",
            evaluator_risk="medium",
            evaluation_path="llm",
            **kwargs,
        )
    assert "[expired]" in prompt
    assert "escalate→user:approve" not in prompt
    assert "Allow this operation" not in prompt
    if derived:
        assert "derived judge approval; not independent permission" in prompt


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_expired_judge_approval_is_not_soft_precedent(store, decision):
    store.resolve_escalation(
        "call",
        decision,
        user_id="tenant",
        resolved_by="judge",
        judge_decision=decision,
    )
    expire(store)
    records = store.get_recent_judge_reviews(
        "session", user_id="tenant", before_ts="9999", before_id="zzz"
    )
    assert [row["judge_decision"] for row in records] == (
        [] if decision == "approve" else ["deny"]
    )


@pytest.mark.parametrize("learning", ["resolved", "late", "retry", "precedent"])
def test_expired_approval_cannot_survive_as_a_cached_path_permission(store, learning):
    import json
    from types import SimpleNamespace

    from intaris.evaluator import Evaluator

    sessions = SessionStore(store._db)
    sessions.create(
        user_id="tenant",
        session_id="paths",
        intention="Test",
        details={"working_directory": "/workspace/project"},
    )
    responses = []

    def evaluate_llm(*args, **kwargs):
        responses.append(args)
        return json.dumps(
            {
                "aligned": False,
                "risk": "medium" if learning == "precedent" else "high",
                "decision": "escalate",
                "reasoning": "Needs fresh permission",
            }
        )

    evaluator = Evaluator(
        llm=SimpleNamespace(generate=evaluate_llm),
        session_store=sessions,
        audit_store=store,
    )

    def evaluate(file):
        return evaluator.evaluate(
            user_id="tenant",
            session_id="paths",
            agent_id="hermes",
            tool="read",
            args={"file_path": file},
        )

    first = evaluate("/outside/file.txt")
    assert first["decision"] == "escalate"
    approved = store.resolve_escalation(first["call_id"], "approve", user_id="tenant")
    if learning == "resolved":
        evaluator.learn_from_approved_escalation(approved)
    elif learning in {"retry", "precedent"}:
        # A restarted/other evaluator has no local resolution callback cache.
        filename = (
            "/outside/other.txt" if learning == "precedent" else "/outside/file.txt"
        )
        assert evaluate(filename)["decision"] == "approve"
    if learning != "late":
        assert evaluator._check_approved_paths(
            "tenant", "paths", ["/outside/file.txt"], "/workspace/project"
        )
    store.expire_escalation(
        first["call_id"], user_id="tenant", session_id="paths", reason="cancelled"
    )
    if learning == "late":
        # The resolution caller can already hold a stale pre-expiration record.
        evaluator.learn_from_approved_escalation(approved)
    result = evaluate("/outside/file.txt")
    assert result["decision"] == "escalate"
    assert result["path"] == "llm"
    assert (
        store.get_by_call_id(first["call_id"], user_id="tenant")["user_decision"]
        == "approve"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("consumer", ["evaluator", "judge"])
async def test_precedent_expired_during_inference_does_not_override_result(
    store, consumer
):
    import json
    from types import SimpleNamespace

    from intaris.config import JudgeConfig
    from intaris.evaluator import Evaluator
    from intaris.judge import JudgeReviewer

    sessions = SessionStore(store._db)
    store.resolve_escalation("call", "approve", user_id="tenant")

    def generate(*args, **kwargs):
        expire(store)
        result = {
            "risk": "medium",
            "decision": "deny",
            "reasoning": "Needs fresh permission",
        }
        result.update(
            {"aligned": False} if consumer == "evaluator" else {"confidence": "high"}
        )
        return json.dumps(result)

    llm = SimpleNamespace(generate=generate)
    if consumer == "evaluator":
        evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=store)
        result = evaluator._llm_evaluate(
            session=sessions.get("session", user_id="tenant"),
            tool="terminal",
            args_redacted={"command": "pwd"},
            agent_id="hermes",
        )
        assert result.decision == "escalate"
    else:
        store.insert(
            call_id="new-call",
            user_id="tenant",
            session_id="session",
            agent_id="hermes",
            tool="terminal",
            args_redacted={"command": "pwd"},
            classification="write",
            evaluation_path="llm",
            decision="escalate",
            risk="medium",
            reasoning="Needs review",
            latency_ms=1,
        )
        reviewer = JudgeReviewer(
            llm=llm,
            config=JudgeConfig(mode="auto"),
            audit_store=store,
            session_store=sessions,
            evaluator=None,
        )
        await reviewer._do_review(
            call_id="new-call", user_id="tenant", session_id="session"
        )
        assert (
            store.get_by_call_id("new-call", user_id="tenant")["user_decision"]
            == "deny"
        )


@pytest.mark.parametrize("invalid", ["missing", "tenant", "expired", "revoked"])
def test_cached_path_grants_require_every_source_to_remain_usable(store, invalid):
    from intaris.evaluator import Evaluator

    store.resolve_escalation("call", "approve", user_id="tenant", resolved_by="judge")
    evaluator = Evaluator(
        llm=None, session_store=SessionStore(store._db), audit_store=store
    )
    user_id = "other" if invalid == "tenant" else "tenant"
    evaluator._approve_path_prefix(
        user_id, "session", "/outside", approval_call_id="call"
    )
    if invalid == "missing":
        # A second grant covered by the same prefix must retain its dependency.
        evaluator._approve_path_prefix(
            user_id, "session", "/outside/sub", approval_call_id="missing"
        )
    elif invalid == "expired":
        expire(store)
    elif invalid == "revoked":
        store.resolve_escalation("call", "deny", user_id="tenant", resolved_by="user")
    assert not evaluator._check_approved_paths(
        user_id, "session", ["/outside/file"], "/project"
    )


def test_cache_source_eviction_discards_dependent_permissions(store, monkeypatch):
    import intaris.evaluator as module

    monkeypatch.setattr(module, "_MAX_APPROVED_PATHS_PER_SESSION", 2)
    evaluator = module.Evaluator(
        llm=None, session_store=SessionStore(store._db), audit_store=store
    )
    for name in ("first", "second", "third"):
        store.insert(
            call_id=name,
            user_id="tenant",
            session_id="session",
            agent_id="hermes",
            tool="read",
            args_redacted={"file_path": f"/{name}/file"},
            classification="write",
            evaluation_path="llm",
            decision="escalate",
            risk="high",
            reasoning="Needs review",
            latency_ms=1,
        )
        store.resolve_escalation(name, "approve", user_id="tenant")
        evaluator._approve_path_prefix(
            "tenant", "session", f"/{name}", approval_call_id=name
        )
    assert not evaluator._check_approved_paths(
        "tenant", "session", ["/first/file"], "/project"
    )
    store.expire_escalation(
        "first", user_id="tenant", session_id="session", reason="timeout"
    )
    assert evaluator._check_approved_paths(
        "tenant", "session", ["/third/file"], "/project"
    )


@pytest.mark.timeout(5)
def test_cache_changed_during_source_validation_cannot_use_stale_snapshot(
    store, monkeypatch
):
    from intaris.evaluator import Evaluator

    store.resolve_escalation("call", "approve", user_id="tenant")
    evaluator = Evaluator(
        llm=None, session_store=SessionStore(store._db), audit_store=store
    )
    evaluator._approve_path_prefix(
        "tenant", "session", "/outside", approval_call_id="call"
    )
    validate = store.approvals_are_usable

    def concurrent_clear(*args, **kwargs):
        result = validate(*args, **kwargs)
        # Also verifies that DB work does not hold the global cache lock.
        evaluator.clear_approved_paths("tenant", "session")
        return result

    monkeypatch.setattr(store, "approvals_are_usable", concurrent_clear)
    assert not evaluator._check_approved_paths(
        "tenant", "session", ["/outside/file"], "/project"
    )


def test_cache_source_lookup_failure_never_authorizes_read(store, monkeypatch):
    from intaris.evaluator import Evaluator

    store.resolve_escalation("call", "approve", user_id="tenant")
    evaluator = Evaluator(
        llm=None, session_store=SessionStore(store._db), audit_store=store
    )
    evaluator._approve_path_prefix(
        "tenant", "session", "/outside", approval_call_id="call"
    )

    def unavailable(*args, **kwargs):
        raise RuntimeError("DB unavailable")

    monkeypatch.setattr(store, "approvals_are_usable", unavailable)
    with pytest.raises(RuntimeError, match="DB unavailable"):
        evaluator._check_approved_paths(
            "tenant", "session", ["/outside/file"], "/project"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("reuse", ["cache", "retry"])
async def test_judge_derived_permissions_retain_original_human_source(store, reuse):
    import json
    from types import SimpleNamespace

    from intaris.config import JudgeConfig
    from intaris.evaluator import Evaluator
    from intaris.judge import JudgeReviewer

    sessions = SessionStore(store._db)
    sessions.create(
        user_id="tenant",
        session_id="paths",
        intention="Test",
        details={"working_directory": "/project"},
    )
    llm = SimpleNamespace(
        generate=lambda *args, **kwargs: json.dumps(
            {
                "aligned": False,
                "decision": "escalate",
                "risk": "high",
                "reasoning": "Review",
            }
        )
    )
    evaluator = Evaluator(llm=llm, session_store=sessions, audit_store=store)

    def evaluate(path):
        return evaluator.evaluate(
            user_id="tenant",
            session_id="paths",
            agent_id="hermes",
            tool="read",
            args={"file_path": path},
        )

    first = evaluate("/outside/first.txt")
    store.resolve_escalation(first["call_id"], "approve", user_id="tenant")
    second = evaluate("/outside/second.txt")
    assert second["decision"] == "escalate"
    reviewer = JudgeReviewer(
        llm=SimpleNamespace(
            generate=lambda *args, **kwargs: json.dumps(
                {
                    "decision": "deny",
                    "risk": "medium",
                    "confidence": "high",
                    "reasoning": "Unaligned",
                }
            )
        ),
        config=JudgeConfig(mode="auto"),
        audit_store=store,
        session_store=sessions,
        evaluator=evaluator,
    )
    await reviewer._do_review(
        call_id=second["call_id"], user_id="tenant", session_id="paths"
    )
    judged = store.get_by_call_id(second["call_id"], user_id="tenant")
    assert judged["user_decision"] == "approve"
    assert "authoritative precedent" in judged["judge_reasoning"]
    store.expire_escalation(
        first["call_id"], user_id="tenant", session_id="paths", reason="cancelled"
    )
    # This is reuse eligibility, not inferred abandonment of B's active waiter.
    still_issued = store.get_by_call_id(second["call_id"], user_id="tenant")
    assert still_issued["user_decision"] == "approve"
    assert still_issued["expired_at"] is None
    assert not store.get_recent_judge_reviews(
        "paths", user_id="tenant", before_ts="9999", before_id="zzz"
    )
    if reuse == "retry":
        evaluator.clear_approved_paths("tenant", "paths")
    path = "/outside/second.txt" if reuse == "retry" else "/outside/third.txt"
    assert evaluate(path)["decision"] == "escalate"
    # An independent, final human resolution of B supersedes its derived grant.
    store.resolve_escalation(second["call_id"], "approve", user_id="tenant")
    assert evaluate("/outside/second.txt")["decision"] == "approve"


@pytest.mark.parametrize(
    "invalid", ["missing", "expired", "judge", "session", "tenant"]
)
def test_derived_resolution_requires_current_final_human_source(store, invalid):
    resolved_by = "judge" if invalid == "judge" else "user"
    store.resolve_escalation(
        "call", "approve", user_id="tenant", resolved_by=resolved_by
    )
    if invalid == "expired":
        expire(store)
    user = "other" if invalid == "tenant" else "tenant"
    session = "other" if invalid == "session" else "session"
    if user != "tenant" or session != "session":
        SessionStore(store._db).create(
            user_id=user, session_id=session, intention="Test"
        )
    store.insert(
        call_id="derived",
        user_id=user,
        session_id=session,
        agent_id="hermes",
        tool="terminal",
        args_redacted={"command": "pwd"},
        classification="write",
        evaluation_path="llm",
        decision="escalate",
        risk="medium",
        reasoning="Review",
        latency_ms=1,
    )
    with pytest.raises(ValueError, match="source"):
        store.resolve_escalation(
            "derived",
            "approve",
            user_id=user,
            resolved_by="judge",
            approval_source_call_id="missing" if invalid == "missing" else "call",
        )
    assert store.get_by_call_id("derived", user_id=user)["user_decision"] is None
