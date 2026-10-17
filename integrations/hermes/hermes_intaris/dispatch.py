"""Profile-owned terminal dispatch guards for the pinned Hermes registry contract.

The coordinator lives on the registry instance, so independent plugin imports
share one shim. Source registrations are never replaced or modified.
"""

from __future__ import annotations

import contextvars
import inspect
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)
_COORDINATOR_ATTR = "_intaris_dispatch_coordinator"


def blocked(reason: str) -> str:
    """Return a safety error without entering Hermes' fail-open middleware path."""
    return json.dumps({"error": f"[intaris] Tool execution blocked: {reason}"})


class DispatchView:
    """Give the native dispatcher exactly one invocation-local entry."""

    def __init__(self, registry: Any, entry: Any, scope: str) -> None:
        self.registry, self.entry, self.scope = registry, entry, scope

    def get_entry(self, name: str, *, scope: str | None = None) -> Any:
        """Return the captured entry, never a second live registry lookup."""
        if name != self.entry.name or scope not in (None, self.scope):
            return None
        return self.entry

    def __getattr__(self, name: str) -> Any:
        return getattr(self.registry, name)


@dataclass(eq=False)
class DispatchOwner:
    """One profile generation's registration and guard factory."""

    coordinator: Any
    profile: Any
    make_entry: Callable
    disposed: bool = False

    def dispose(self) -> None:
        """Retire this owner without releasing another generation's shim."""
        self.coordinator.dispose(self)

    def reserve(self) -> Any:
        """Retain interception throughout the downstream middleware call."""
        return self.coordinator.reserve(self)


@dataclass(eq=False)
class _Reservation:
    owner: DispatchOwner
    active: bool = True


class _DispatchCoordinator:
    version = 1

    def __init__(self, registry: Any, current_home: Callable[[], str]) -> None:
        saved = registry.dispatch
        if not inspect.ismethod(saved) or saved.__self__ is not registry:
            raise RuntimeError(
                "Hermes requires an unmodified bound registry dispatcher"
            )
        self.registry, self.saved, self.current_home = registry, saved, current_home
        self.lock = registry._lock
        self.had_attribute = "dispatch" in vars(registry)
        self.previous_attribute = vars(registry).get("dispatch")
        self.owners: dict[str, list[DispatchOwner]] = {}
        self.reservations = 0
        self.binding = contextvars.ContextVar(
            "intaris_dispatch_reservation", default=None
        )
        # Store one stable callable identity for installation/restoration checks.
        self.shim = self.dispatch

    def current_owner(self, home: str) -> DispatchOwner | None:
        owners = self.owners.get(home, [])
        return owners[-1] if owners else None

    @contextmanager
    def reserve(self, owner: DispatchOwner) -> Iterator[None]:
        with self.lock:
            prior = self.binding.get()
            profile = owner.profile
            if (
                owner.disposed
                or self.current_owner(profile.home) is not owner
                or not profile.active
                or not profile.ready
                or self.current_home() != profile.home
                or self.registry.dispatch is not self.shim
                or (
                    prior is not None and (not prior.active or prior.owner is not owner)
                )
            ):
                raise RuntimeError("Intaris dispatch generation is unavailable")
            reservation = _Reservation(owner)
            self.reservations += 1
        token = self.binding.set(reservation)
        try:
            yield
        finally:
            self.binding.reset(token)
            with self.lock:
                reservation.active = False
                self.reservations -= 1
                self._restore_if_unused()

    def dispose(self, owner: DispatchOwner) -> None:
        with self.lock:
            if owner.disposed:
                return
            owner.disposed = True
            owners = self.owners.get(owner.profile.home, [])
            if owner in owners:
                owners.remove(owner)
            if not owners:
                self.owners.pop(owner.profile.home, None)
            self._restore_if_unused()

    def _restore_if_unused(self) -> None:
        if self.owners or self.reservations:
            return
        # A different component may have replaced/wrapped dispatch. Never undo it.
        if self.registry.dispatch is self.shim:
            if self.had_attribute:
                self.registry.dispatch = self.previous_attribute
            else:
                del self.registry.dispatch
            if getattr(self.registry, _COORDINATOR_ATTR, None) is self:
                delattr(self.registry, _COORDINATOR_ATTR)

    def _dispatch_reserved(
        self, reservation: _Reservation, name: str, args: dict, scope: str, kwargs: dict
    ) -> Any:
        owner = reservation.owner
        profile = owner.profile
        if (
            not reservation.active
            or owner.disposed
            or not profile.active
            or not profile.ready
            or profile.home != scope
            or self.current_home() != scope
        ):
            return blocked("profile changed or unloaded")
        # Hermes routes these names outside registry.dispatch in model_tools.
        if name.startswith("connectors__"):
            return blocked("virtual connector arguments cannot be guarded")
        source = self.registry.get_entry(name, scope=scope)
        if source is None:
            return blocked("no registry handler; cannot guard final arguments")
        entry = owner.make_entry(source, scope)
        view = DispatchView(self.registry, entry, scope)
        # Calling the bound saved method would ignore the invocation-local view.
        return self.saved.__func__(view, name, args, scope=scope, **kwargs)

    def dispatch(
        self, name: str, args: dict, *, scope: str | None = None, **kwargs: Any
    ) -> Any:
        try:
            home = self.current_home()
            effective_scope = str(Path(scope).expanduser().resolve()) if scope else home
            reservation = self.binding.get()
            if reservation is not None:
                return self._dispatch_reserved(
                    reservation, name, args, effective_scope, kwargs
                )
            with self.lock:
                owner = self.current_owner(effective_scope)
                ambient_owner = self.current_owner(home)
            if effective_scope != home and (
                owner is not None or ambient_owner is not None
            ):
                return blocked("dispatch scope conflicts with active profile")
            if owner is None:
                return self.saved(name, args, scope=scope, **kwargs)
            with self.reserve(owner):
                return self._dispatch_reserved(
                    self.binding.get(), name, args, effective_scope, kwargs
                )
        except Exception as exc:
            # Do not expose provider exception text, which may contain secrets.
            logger.error("[intaris] Dispatch guard failed (%s)", type(exc).__name__)
            return blocked("safety guard failed")


def install_dispatch_guard(
    registry: Any, profile: Any, make_entry: Callable, current_home: Callable[[], str]
) -> DispatchOwner:
    """Install/reuse one coordinator under the actual registry's mutation lock."""
    with registry._lock:
        coordinator = getattr(registry, _COORDINATOR_ATTR, None)
        if coordinator is None:
            coordinator = _DispatchCoordinator(registry, current_home)
            setattr(registry, _COORDINATOR_ATTR, coordinator)
            registry.dispatch = coordinator.shim
        elif coordinator.version != 1 or registry.dispatch is not coordinator.shim:
            raise RuntimeError("Hermes registry dispatcher changed outside Intaris")
        owner = DispatchOwner(coordinator, profile, make_entry)
        coordinator.owners.setdefault(profile.home, []).append(owner)
        return owner
