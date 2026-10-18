"""Native presentation shares the original invocation's identity and wait budget."""

from contextlib import contextmanager

import pytest

from . import test_waits
from .test_waits import Transport, invocation

adapter = test_waits.adapter
host = test_waits.host


@pytest.mark.parametrize("cancel", [False, True])
def test_native_presentation_cannot_dispatch_and_closes_with_wait(
    adapter, host, monkeypatch, cancel
):
    observations = []

    class Presenter:
        @contextmanager
        def pending(self, session_id, call_id, active, *, intaris_session_id):
            observations.append((session_id, call_id, intaris_session_id))
            assert host.pending["gateway-A"] == 1
            assert 0 < active.remaining_seconds <= 300
            try:
                yield
            finally:
                observations.append("closed")

    adapter.profile.native_approvals = Presenter()
    transport = Transport("escalate")
    with invocation(adapter, transport, monkeypatch) as run:
        assert observations == [("session-A", "c1", "intaris-A")]
        assert adapter.calls == []
        if cancel:
            host.interrupted.add(run.thread.ident)
            assert run.done.wait(1)
        else:
            transport.release.set()
            assert run.done.wait(1)
    assert observations[-1] == "closed"
    assert len(adapter.calls) == (0 if cancel else 1)
