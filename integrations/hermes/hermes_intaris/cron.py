"""Optional Hermes canonical cron presentation adapter; no decision RPC proxy."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from .waits import WaitStopped


class RelayInvocation:
    """Use the gateway's bound execution lifetime with native wait semantics."""

    def __init__(self, lifetime: Any) -> None:
        self._lifetime = lifetime

    def check(self) -> None:
        try:
            self._lifetime.check()
        except RuntimeError as exc:
            reason = getattr(self._lifetime, "reason", None)
            message = (
                "APPROVAL WAIT TIMEOUT (cron)"
                if reason == "expired"
                else "CANCELLED: cron invocation ended"
            )
            raise WaitStopped(message) from exc

    @property
    def remaining_seconds(self) -> float:
        try:
            return self._lifetime.remaining_seconds
        except RuntimeError:
            self.check()
            raise

    def request(self, operation: Any) -> Any:
        self.check()
        result = operation()
        self.check()
        return result


@contextmanager
def present_cron(native: Any, request: Any, lifetime: Any):
    if request.profile_home != native.home:
        raise ValueError("Cron approval profile mismatch")
    # Never look up request.session_id as a Telegram session. It identifies the
    # canonical execution, not an admitted sender, even if identifiers collide.
    with native._pending_local(
        request.session_id,
        request.call_id,
        RelayInvocation(lifetime),
        intaris_session_id=request.external_session_id,
        policy_fallback=True,
    ):
        yield
