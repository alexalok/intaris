"""Keep asynchronous adapter cleanup inside each test's mocked HTTP lifetime."""

import threading

import pytest


@pytest.fixture(autouse=True)
def finish_expiration_reports(monkeypatch):
    yield
    # Depend on monkeypatch so HTTP remains controlled until queued work drains.
    for thread in threading.enumerate():
        if thread.name == "intaris-expire":
            thread.join(10)
            assert not thread.is_alive(), "expiration worker outlived HTTP fixture"
