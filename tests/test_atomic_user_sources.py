"""Atomic user-message evidence across independent database connections."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from intaris.api.analysis import submit_reasoning
from intaris.api.deps import SessionContext
from intaris.api.schemas import ReasoningRequest
from intaris.audit import AuditStore, ScopeChangedError
from intaris.config import DBConfig, EventStoreConfig
from intaris.db import Database
from intaris.events.store import EventStore
from intaris.session import SessionStore


@pytest.fixture
def stores(tmp_path, monkeypatch):
    config = DBConfig(backend="sqlite", path=str(tmp_path / "sources.db"))
    writer = Database(config)
    SessionStore(writer).create(session_id="s", user_id="u", intention="Maintain files")
    reader = Database(config)
    monkeypatch.setattr("intaris.server._get_db", lambda: writer)
    events = EventStore(
        EventStoreConfig(
            enabled=True, backend="filesystem", filesystem_path=str(tmp_path / "events")
        )
    )
    barrier = SimpleNamespace(
        trigger=AsyncMock(), wait=AsyncMock(), invalidate=MagicMock()
    )
    state = SimpleNamespace(event_store=events, intention_barrier=barrier)
    request = Request({"type": "http", "app": SimpleNamespace(state=state)})
    yield SimpleNamespace(
        writer=writer, reader=reader, events=events, barrier=barrier, request=request
    )
    writer.close()
    reader.close()


def append_message(stores, *, content="Stop editing files", eligible=True, user_id="u"):
    return stores.events.append(
        user_id,
        "s",
        [
            {
                "type": "user_message",
                "data": {"content": content, "intention_eligible": eligible},
            }
        ],
    )[0]


def submit(stores, *, user_id="u", content=None, wait=False):
    return asyncio.run(
        submit_reasoning(
            ReasoningRequest(
                session_id="s",
                from_events=content is None,
                content=content or "",
                wait_for_intention=wait,
                wait_timeout_ms=200,
            ),
            stores.request,
            SessionContext(user_id=user_id, agent_id=None, user_bound=True),
        )
    )


def intercept_inserts(monkeypatch, db, before_insert):
    original = db.cursor

    class Cursor:
        def __init__(self, inner):
            self.inner = inner

        def execute(self, sql, params=None):
            if "INSERT INTO audit_log" in sql:
                before_insert()
            return self.inner.execute(sql, params)

        def __getattr__(self, name):
            return getattr(self.inner, name)

    @contextmanager
    def cursor():
        with original() as inner:
            yield Cursor(inner)

    monkeypatch.setattr(db, "cursor", cursor)


def test_event_source_and_scope_publish_in_one_transaction(stores, monkeypatch):
    """Another worker sees old scope until the complete source transaction commits."""
    seq = append_message(stores)
    entered, release = threading.Event(), threading.Event()

    def pause():
        entered.set()
        assert release.wait(5), "Reader did not release source writer"

    intercept_inserts(monkeypatch, stores.writer, pause)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(submit, stores)
        try:
            assert entered.wait(5), "Source writer did not reach audit insert"
            observed = SessionStore(stores.reader).get("s", user_id="u")
            sources = AuditStore(stores.reader).get_intent_sources("s", user_id="u")
        finally:
            release.set()
        response = future.result(timeout=5)

    assert observed["latest_user_message_seq"] is None
    assert observed["scope_version"] == 0
    assert observed["user_message_observed"] == 0
    assert sources == []
    committed = SessionStore(stores.reader).get("s", user_id="u")
    assert committed["latest_user_message_seq"] == seq
    assert committed["scope_version"] == 1
    assert committed["user_message_observed"] == 1
    assert (
        AuditStore(stores.reader).get_by_call_id(response.call_id, user_id="u")[
            "args_redacted"
        ]["source_event_seq"]
        == seq
    )

    with pytest.raises(ScopeChangedError):
        AuditStore(stores.reader).insert(
            call_id="raced-approval",
            user_id="u",
            session_id="s",
            agent_id=None,
            tool="edit",
            args_redacted={"path": "/work/file"},
            classification="write",
            evaluation_path="llm",
            decision="approve",
            risk="low",
            reasoning="Old scope",
            latency_ms=0,
            scope_versions={"s": observed["scope_version"]},
        )


@pytest.mark.parametrize("eligible", [True, False])
def test_source_insert_failure_rolls_back_observation(stores, monkeypatch, eligible):
    append_message(stores, eligible=eligible)

    def fail():
        raise RuntimeError("injected audit insert failure")

    intercept_inserts(monkeypatch, stores.writer, fail)
    with pytest.raises(HTTPException) as error:
        submit(stores)
    assert error.value.status_code == 500
    session = SessionStore(stores.reader).get("s", user_id="u")
    assert session["latest_user_message_seq"] is None
    assert session["last_event_seq"] == 0
    assert session["scope_version"] == 0
    assert session["user_message_observed"] == 0
    assert AuditStore(stores.reader).get_recent("s", user_id="u") == []
    stores.barrier.trigger.assert_not_called()
    stores.barrier.invalidate.assert_not_called()


@pytest.mark.parametrize("eligible", [True, False])
def test_repeated_event_source_is_idempotent(stores, eligible):
    seq = append_message(stores, eligible=eligible)
    first = submit(stores)
    version = SessionStore(stores.reader).get("s", user_id="u")["scope_version"]
    again = submit(stores, wait=True)
    assert again.call_id == first.call_id
    assert SessionStore(stores.reader).get("s", user_id="u")["scope_version"] == version
    assert len(AuditStore(stores.reader).get_recent("s", user_id="u")) == 1
    if eligible:
        stores.barrier.trigger.assert_awaited_once_with(
            "u", "s", context=None, source_event_seq=seq
        )
        stores.barrier.wait.assert_awaited_once_with("u", "s", timeout_override=0.2)
    else:
        stores.barrier.trigger.assert_not_called()
        stores.barrier.invalidate.assert_called_once_with("u", "s")


def test_same_event_sequence_remains_tenant_scoped(stores):
    SessionStore(stores.writer).create(
        session_id="s", user_id="other", intention="Maintain files"
    )
    append_message(stores)
    append_message(stores, user_id="other", content="Read only")
    first = submit(stores)
    other = submit(stores, user_id="other")
    assert first.call_id != other.call_id
    assert len(AuditStore(stores.reader).get_intent_sources("s", user_id="u")) == 1
    assert len(AuditStore(stores.reader).get_intent_sources("s", user_id="other")) == 1
    assert SessionStore(stores.reader).get("s", user_id="u")["scope_version"] == 1
    assert SessionStore(stores.reader).get("s", user_id="other")["scope_version"] == 1


def test_direct_message_marks_observation_in_source_transaction(stores, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = stores.writer.cursor

    @contextmanager
    def pause_after_commit():
        inserted = False

        class Cursor:
            def __init__(self, inner):
                self.inner = inner

            def execute(self, sql, params=None):
                nonlocal inserted
                inserted = inserted or "INSERT INTO audit_log" in sql
                return self.inner.execute(sql, params)

            def __getattr__(self, name):
                return getattr(self.inner, name)

        with original() as inner:
            yield Cursor(inner)
        if inserted:
            entered.set()
            assert release.wait(5)

    monkeypatch.setattr(stores.writer, "cursor", pause_after_commit)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(submit, stores, content="User message: Stop editing")
        try:
            assert entered.wait(5)
            observed = SessionStore(stores.reader).get("s", user_id="u")
            sources = AuditStore(stores.reader).get_intent_sources("s", user_id="u")
        finally:
            release.set()
        future.result(timeout=5)
    assert len(sources) == 1
    assert observed["user_message_observed"] == 1
    assert observed["scope_version"] == 1


@pytest.mark.parametrize("eligible", [True, False])
def test_stale_event_delivery_does_not_cancel_newer_barrier(
    stores, monkeypatch, eligible
):
    from intaris.events.resolve import resolve_last_user_message

    append_message(stores, content="Earlier request", eligible=eligible)
    stale = resolve_last_user_message(stores.events, "u", "s")
    latest_seq = append_message(stores, content="Do not edit files")
    latest = submit(stores)
    version = SessionStore(stores.reader).get("s", user_id="u")["scope_version"]
    stores.barrier.trigger.reset_mock()
    stores.barrier.invalidate.reset_mock()
    monkeypatch.setattr(
        "intaris.events.resolve.resolve_last_user_message", lambda *args: stale
    )
    response = submit(stores)
    assert response.call_id == ""
    assert SessionStore(stores.reader).get("s", user_id="u")["scope_version"] == version
    assert (
        SessionStore(stores.reader).get("s", user_id="u")["latest_user_message_seq"]
        == latest_seq
    )
    records = AuditStore(stores.reader).get_recent("s", user_id="u")
    assert [record["call_id"] for record in records] == [latest.call_id]
    stores.barrier.trigger.assert_not_called()
    stores.barrier.invalidate.assert_not_called()


def test_concurrent_duplicate_sources_share_one_record(stores, monkeypatch):
    """Competing workers serialize source deduplication on the session row."""
    from intaris.events.resolve import resolve_last_user_message

    append_message(stores)
    rendezvous = threading.Barrier(2)

    def resolve(*args):
        resolved = resolve_last_user_message(*args)
        rendezvous.wait(timeout=5)
        return resolved

    monkeypatch.setattr("intaris.events.resolve.resolve_last_user_message", resolve)
    # Each endpoint uses a distinct Database instance, not shared transaction state.
    endpoints = threading.local()
    monkeypatch.setattr("intaris.server._get_db", lambda: endpoints.db)

    def run(db):
        endpoints.db = db
        return submit(stores)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, db) for db in (stores.writer, stores.reader)]
        responses = [future.result(timeout=5) for future in futures]
    assert responses[0].call_id == responses[1].call_id
    assert len(AuditStore(stores.reader).get_recent("s", user_id="u")) == 1
    assert SessionStore(stores.reader).get("s", user_id="u")["scope_version"] == 1
    stores.barrier.trigger.assert_awaited_once()


@pytest.mark.parametrize("seq", [0, -1, True, "1"])
def test_invalid_event_source_sequence_cannot_become_untracked_authority(stores, seq):
    with pytest.raises(ValueError, match="source_event_seq"):
        AuditStore(stores.writer).insert(
            call_id="invalid-source",
            user_id="u",
            session_id="s",
            agent_id=None,
            tool=None,
            args_redacted={"source_event_seq": seq},
            classification=None,
            evaluation_path="reasoning",
            decision="approve",
            risk=None,
            reasoning=None,
            latency_ms=0,
            record_type="reasoning",
            content="User message: Edit files",
        )
    assert SessionStore(stores.reader).get("s", user_id="u")["scope_version"] == 0
    assert AuditStore(stores.reader).get_recent("s", user_id="u") == []


@pytest.mark.parametrize("state_source", ["allocation", "reconciliation"])
def test_pending_event_pointer_gets_new_revision_when_source_arrives(
    stores, state_source
):
    sessions = SessionStore(stores.writer)
    if state_source == "allocation":
        stores.events.set_session_store(sessions)
    seq = append_message(stores)
    if state_source == "reconciliation":
        stores.events.set_session_store(sessions)
        stores.events.reconcile_session_user_message_state()
    pending = SessionStore(stores.reader).get("s", user_id="u")
    assert pending["latest_user_message_seq"] == seq
    assert pending["scope_version"] == 1
    assert AuditStore(stores.reader).get_intent_sources("s", user_id="u") == []
    submit(stores)
    ready = SessionStore(stores.reader).get("s", user_id="u")
    assert ready["scope_version"] == 2
    assert ready["latest_user_message_seq"] == seq
    sources = AuditStore(stores.reader).get_intent_sources("s", user_id="u")
    assert [record["args_redacted"]["source_event_seq"] for record in sources] == [seq]


def test_direct_source_coexists_with_projected_event(stores):
    seq = append_message(stores)
    event_response = submit(stores)
    direct = submit(stores, content="User message: Read only, no edits")
    session = SessionStore(stores.reader).get("s", user_id="u")
    assert session["latest_user_message_seq"] == seq
    assert session["scope_version"] == 2
    sources = AuditStore(stores.reader).get_intent_sources("s", user_id="u")
    assert {record["call_id"] for record in sources} == {
        event_response.call_id,
        direct.call_id,
    }
    assert any(
        (record["args_redacted"] or {}).get("source_event_seq") == seq
        for record in sources
    )


def test_approval_before_source_insert_cannot_observe_advanced_empty_scope(
    stores, monkeypatch
):
    """Reproduce an approval committing inside the original two-transaction gap."""
    append_message(stores)
    entered, release = threading.Event(), threading.Event()
    original = AuditStore.insert

    def pause_source(self, **kwargs):
        if kwargs.get("record_type") == "reasoning":
            entered.set()
            assert release.wait(5)
        return original(self, **kwargs)

    monkeypatch.setattr(AuditStore, "insert", pause_source)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(submit, stores)
        try:
            assert entered.wait(5)
            before = SessionStore(stores.reader).get("s", user_id="u")
            assert AuditStore(stores.reader).get_intent_sources("s", user_id="u") == []
            approval = AuditStore(stores.reader).insert(
                call_id="before-message",
                user_id="u",
                session_id="s",
                agent_id=None,
                tool="edit",
                args_redacted={"path": "/work/file"},
                classification="write",
                evaluation_path="llm",
                decision="approve",
                risk="low",
                reasoning="Old scope",
                latency_ms=0,
                scope_versions={"s": before["scope_version"]},
            )
        finally:
            release.set()
        future.result(timeout=5)
    assert approval["decision"] == "approve"
    assert before["latest_user_message_seq"] is None
    assert before["scope_version"] == 0
    assert SessionStore(stores.reader).get("s", user_id="u")["scope_version"] == 1


def test_existing_legacy_source_can_repair_missing_event_pointer(stores):
    """Replays preserve source identity while restoring pre-migration session state."""
    seq = append_message(stores)
    first = submit(stores)
    with stores.writer.cursor() as cur:
        cur.execute(
            "UPDATE sessions SET latest_user_message_seq = NULL, last_event_seq = 0, "
            "user_message_observed = FALSE, scope_version = 0 "
            "WHERE user_id = ? AND session_id = ?",
            ("u", "s"),
        )
    replay = submit(stores)
    assert replay.call_id == first.call_id
    session = SessionStore(stores.reader).get("s", user_id="u")
    assert session["latest_user_message_seq"] == seq
    assert session["last_event_seq"] == seq
    assert session["scope_version"] == 1
    assert session["user_message_observed"] == 1


@pytest.mark.parametrize("eligible", [True, False])
def test_projection_lookup_distinguishes_eligibility_from_missing(stores, eligible):
    seq = append_message(stores, eligible=eligible)
    response = submit(stores)
    audit = AuditStore(stores.reader)
    before = SessionStore(stores.reader).get("s", user_id="u")
    projection = audit.get_user_message_projection("s", user_id="u", event_seq=seq)
    assert projection["call_id"] == response.call_id
    assert projection["args_redacted"]["source_event_seq"] == seq
    assert projection["args_redacted"]["intention_eligible"] is eligible
    assert (
        audit.get_user_message_projection("s", user_id="u", event_seq=seq + 1) is None
    )
    assert (
        audit.get_user_message_projection("s", user_id="other", event_seq=seq) is None
    )
    assert (
        audit.get_user_message_projection("other", user_id="u", event_seq=seq) is None
    )
    assert SessionStore(stores.reader).get("s", user_id="u") == before
    assert bool(audit.get_intent_sources("s", user_id="u")) is eligible


@pytest.mark.parametrize("event_seq", [None, 0, -1, True, 1.0, "1"])
def test_projection_lookup_rejects_invalid_sequence(stores, event_seq):
    with pytest.raises(ValueError, match="event_seq"):
        AuditStore(stores.reader).get_user_message_projection(
            "s", user_id="u", event_seq=event_seq
        )


@pytest.mark.parametrize("stored_seq", [None, 0, -1, True, 1.0, "1"])
def test_projection_lookup_ignores_malformed_stored_sequence(stores, stored_seq):
    import json

    seq = append_message(stores, eligible=False)
    response = submit(stores)
    with stores.writer.cursor() as cur:
        cur.execute(
            "UPDATE audit_log SET args_redacted = ? WHERE user_id = ? AND call_id = ?",
            (
                json.dumps(
                    {"source_event_seq": stored_seq, "intention_eligible": False}
                ),
                "u",
                response.call_id,
            ),
        )
    assert (
        AuditStore(stores.reader).get_user_message_projection(
            "s", user_id="u", event_seq=seq
        )
        is None
    )


@pytest.mark.parametrize(
    ("record_type", "content"),
    [
        ("reasoning", "Agent reasoning: not a user message"),
        ("checkpoint", "User message: not reasoning"),
    ],
)
def test_projection_lookup_requires_user_message_reasoning(
    stores, record_type, content
):
    audit = AuditStore(stores.writer)
    audit.insert(
        call_id="non-user-record",
        user_id="u",
        session_id="s",
        agent_id=None,
        tool=None,
        args_redacted={"source_event_seq": 1, "intention_eligible": False},
        classification=None,
        evaluation_path="reasoning",
        decision="approve",
        risk=None,
        reasoning=None,
        latency_ms=0,
        record_type=record_type,
        content=content,
    )
    assert (
        AuditStore(stores.reader).get_user_message_projection(
            "s", user_id="u", event_seq=1
        )
        is None
    )
