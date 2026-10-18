"""Cooperative cancellation for an Intaris-guarded Hermes invocation.

Only HTTP operations run on helper threads. The original tool handler always
stays on the Hermes worker, where its interruption and tool context remain valid.
"""

from __future__ import annotations

import contextvars
import math
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")
_CHECK_INTERVAL_S = 0.1


@dataclass
class _SharedWindow:
    deadline: float
    pending: int = 0


_windows: dict[str, _SharedWindow] = {}
_windows_lock = threading.Lock()


@contextmanager
def _shared_deadline(key: str, timeout_s: float) -> Iterator[float]:
    """Bound overlapping adapter waits by one host accounting allowance.

    Hermes coalesces overlapping windows with the same key, even after the
    first waiter leaves. Keep that window's original deadline until every
    adapter waiter has left; a staggered arrival cannot renew its allowance.
    """
    with _windows_lock:
        window = _windows.get(key)
        if window is None:
            window = _windows[key] = _SharedWindow(time.monotonic() + timeout_s)
        window.pending += 1
    try:
        yield window.deadline
    finally:
        with _windows_lock:
            window.pending -= 1
            if not window.pending:
                del _windows[key]


class WaitStopped(Exception):
    """The invocation must not dispatch, including when fail-open is enabled."""


class Invocation:
    """Own cancellation checks and a single approval budget for one invocation."""

    def __init__(self, ended: threading.Event | None, timeout_s: float) -> None:
        self._ended = ended
        self._closed = threading.Event()
        self._timeout_s = timeout_s
        self._deadline: float | None = None
        self._stopped: str | None = None
        self._label = "approval"
        self._check_lock = threading.Lock()
        self._owner_tid = threading.get_ident()
        self._acting_for_tid: int | None = None
        self._is_thread_interrupted: Callable[[int | None], bool] | None = None
        try:
            from tools.interrupt import is_interrupted
        except ImportError:
            is_interrupted = None
        self._is_interrupted = is_interrupted
        if is_interrupted is not None:
            try:
                from tools.interrupt import acting_for_tid, is_thread_interrupted
            except ImportError:
                pass
            else:
                # Callback/to_thread workers do not inherit the tool owner's
                # identity. Pin both public Hermes cancellation identities now.
                self._acting_for_tid = acting_for_tid.get()
                self._is_thread_interrupted = is_thread_interrupted

    def close(self) -> None:
        """Retire this invocation without cancelling its whole Hermes session."""
        self._closed.set()

    @property
    def remaining_seconds(self) -> float:
        """Remaining established human-wait budget; never grant a new window."""
        self.check()
        if self._deadline is None:
            raise WaitStopped("Native approval requires an active human-wait window")
        return max(0.0, self._deadline - time.monotonic())

    def check(self) -> None:
        """Latch cancellation before accepting a result or dispatching a tool."""
        with self._check_lock:
            if self._stopped is None:
                if self._closed.is_set():
                    self._stopped = "CANCELLED: Intaris invocation already completed"
                elif self._ended is not None and self._ended.is_set():
                    self._stopped = "CANCELLED: Hermes session ended"
                else:
                    try:
                        if self._interrupted():
                            self._stopped = "CANCELLED: Hermes interrupted or abandoned this invocation"
                    except WaitStopped as exc:
                        self._stopped = str(exc)
                    if (
                        self._stopped is None
                        and self._deadline is not None
                        and time.monotonic() >= self._deadline
                    ):
                        self._stopped = f"APPROVAL WAIT TIMEOUT ({self._label})"
            if self._stopped:
                raise WaitStopped(self._stopped)

    def _interrupted(self) -> bool:
        if self._is_thread_interrupted is not None and (
            self._is_thread_interrupted(self._owner_tid)
            or self._is_thread_interrupted(self._acting_for_tid)
        ):
            return True
        if threading.get_ident() == self._owner_tid:
            # Preserve the execution thread's current context check too.
            return self._is_interrupted is not None and self._is_interrupted()
        if self._is_thread_interrupted is None:
            raise WaitStopped(
                "Cannot safely check cancellation: Hermes owner-thread API unavailable"
            )
        return False

    def sleep(self, seconds: float) -> None:
        """Wait in interruptible slices, bounded by the invocation's deadline."""
        end = time.monotonic() + seconds
        while True:
            self.check()
            remaining = end - time.monotonic()
            if remaining <= 0:
                return
            self._wait_slice(min(remaining, _CHECK_INTERVAL_S))

    def _wait_slice(self, seconds: float) -> None:
        if self._ended is not None:
            self._ended.wait(seconds)
        else:
            time.sleep(seconds)

    def request(self, operation: Callable[[], T]) -> T:
        """Observe cancellation even while urllib is blocked in transport.

        urllib's own socket timeout still applies. A detached request can finish
        later, but has no path to dispatch a tool or publish its stale result.
        """
        self.check()
        done = threading.Event()
        values: list[T] = []
        errors: list[BaseException] = []

        def run() -> None:
            try:
                values.append(operation())
            except BaseException as exc:
                errors.append(exc)
            finally:
                done.set()

        thread = threading.Thread(
            target=contextvars.copy_context().run,
            args=(run,),
            name="intaris-http",
            daemon=True,
        )
        thread.start()
        while not done.wait(_CHECK_INTERVAL_S):
            self.check()
        self.check()
        if errors:
            raise errors[0]
        return values[0]

    @contextmanager
    def human_wait(self, label: str) -> Iterator[Callable[[], None]]:
        """Register genuine human wait with Hermes, and always close accounting."""
        self.check()
        if self._is_interrupted is None or self._ended is None:
            raise WaitStopped(
                "Cannot safely wait: Hermes interruption/session context unavailable"
            )
        try:
            from tools.approval_context import get_current_session_key
            from tools.approval_human_wait import (
                HUMAN_WAIT_MARGIN_S,
                activity_heartbeat,
                human_wait_ceiling,
                human_wait_window,
            )

            key = get_current_session_key()
            # Hermes clamps every open accounting window. End at its approval
            # timeout, leaving its safety margin for cancellation/cleanup.
            host_timeout = float(human_wait_ceiling()) - HUMAN_WAIT_MARGIN_S
            if not key or not math.isfinite(host_timeout) or host_timeout <= 0:
                raise ValueError("no finite, positive Hermes approval budget")
        except (ImportError, ValueError, TypeError) as exc:
            raise WaitStopped(
                f"Cannot safely wait: Hermes human-wait APIs unavailable ({exc})"
            ) from exc

        self._label = label
        if self._deadline is None:
            timeout = host_timeout
            if self._timeout_s > 0:
                timeout = min(timeout, self._timeout_s)
            self._deadline = time.monotonic() + timeout
        with _shared_deadline(key, host_timeout) as shared_deadline:
            self._deadline = min(self._deadline, shared_deadline)
            heartbeat = activity_heartbeat("Intaris approval")
            with human_wait_window(key):
                self.check()
                yield heartbeat
                self.check()
