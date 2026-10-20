"""Cooperative cancellation for an Intaris-guarded Hermes invocation.

Only HTTP operations run on helper threads. The original tool handler always
stays on the Hermes worker, where its interruption and tool context remain valid.
"""

from __future__ import annotations

import contextvars
import logging
import math
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TypeVar

logger = logging.getLogger(__name__)

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

    def __init__(self, message: str, reason: str = "abandoned") -> None:
        super().__init__(message)
        self.reason = reason


class Invocation:
    """Own cancellation checks and a single approval budget for one invocation."""

    def __init__(self, ended: threading.Event | None, timeout_s: float) -> None:
        self._ended = ended
        self._closed = threading.Event()
        self._timeout_s = timeout_s
        self._deadline: float | None = None
        self._stopped: str | None = None
        self._stop_reason = "cancelled"
        self._label = "approval"
        try:
            from tools.interrupt import is_interrupted
        except ImportError:
            is_interrupted = None
        self._is_interrupted = is_interrupted

    def close(self) -> None:
        """Retire this invocation without cancelling its whole Hermes session."""
        self._closed.set()

    def check(self) -> None:
        """Latch cancellation before accepting a result or dispatching a tool."""
        if self._stopped is None:
            if self._closed.is_set():
                self._stopped = "CANCELLED: Intaris invocation already completed"
            elif self._ended is not None and self._ended.is_set():
                self._stopped = "CANCELLED: Hermes session ended"
            elif self._is_interrupted is not None and self._is_interrupted():
                self._stopped = (
                    "CANCELLED: Hermes interrupted or abandoned this invocation"
                )
            elif self._deadline is not None and time.monotonic() >= self._deadline:
                self._stopped = f"APPROVAL WAIT TIMEOUT ({self._label})"
                self._stop_reason = "timeout"
        if self._stopped:
            raise WaitStopped(self._stopped, reason=self._stop_reason)

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

    def request(
        self,
        operation: Callable[[], T],
        *,
        on_abandoned: Callable[[T, str], None] | None = None,
    ) -> T:
        """Observe cancellation even while urllib is blocked in transport.

        A detached result can only reach the optional cleanup callback, never
        dispatch. The callback must be nonblocking. A locked handoff covers both
        completion before cancellation and completion after the waiter leaves.
        """
        self.check()
        done = threading.Event()
        handoff = threading.Lock()
        values: list[T] = []
        errors: list[BaseException] = []
        abandoned_reason: str | None = None

        def abandon(value: T, reason: str) -> None:
            if on_abandoned is not None:
                try:
                    on_abandoned(value, reason)
                except Exception:
                    logger.exception("[intaris] Detached request cleanup failed")

        def run() -> None:
            try:
                value = operation()
                with handoff:
                    values.append(value)
                    reason = abandoned_reason
                if reason is not None:
                    abandon(value, reason)
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
        try:
            while not done.wait(_CHECK_INTERVAL_S):
                self.check()
            self.check()
            if errors:
                raise errors[0]
            return values[0]
        except BaseException as exc:
            with handoff:
                abandoned_reason = (
                    exc.reason if isinstance(exc, WaitStopped) else "abandoned"
                )
                completed = bool(values)
            if completed:
                abandon(values[0], abandoned_reason)
            raise

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
