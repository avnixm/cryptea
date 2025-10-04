"""Runtime enforcement for strict offline mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

try:  # pragma: no cover - optional dependency
    from gi.repository import Gio  # type: ignore[import]
except (ImportError, ValueError):  # pragma: no cover - fallback for headless tests
    Gio = None  # type: ignore[assignment]

from . import config


class OfflineViolation(RuntimeError):
    """Raised when network availability is detected during offline build."""


@dataclass
class OfflineStatus:
    """Container describing the runtime offline posture."""

    network_available: bool
    sandbox_enforced: bool
    message: str


class OfflineGuard:
    """Ensures the application stays within offline-only constraints."""

    def __init__(self) -> None:
        self._monitor: Optional[Any] = None

    def _ensure_monitor(self) -> Any:
        if self._monitor is None:
            if Gio is None:
                self._monitor = _NullNetworkMonitor()
            else:
                self._monitor = Gio.NetworkMonitor.get_default()
        return self._monitor

    def status(self) -> OfflineStatus:
        monitor = self._ensure_monitor()
        has_network = bool(monitor and monitor.get_network_available())
        sandbox_enforced = not has_network
        message = (
            "Offline build verified (no network permission detected)."
            if sandbox_enforced
            else "Network availability detected — sandbox may be misconfigured."
        )
        return OfflineStatus(
            network_available=has_network,
            sandbox_enforced=sandbox_enforced,
            message=message,
        )

    def enforce(self) -> None:
        if not config.OFFLINE_BUILD:
            return
        current_status = self.status()
        if not current_status.network_available:
            return
        if config.SUPPRESS_SANDBOX_WARNING:
            return
        raise OfflineViolation(current_status.message)


class _NullNetworkMonitor:
    """Fallback monitor used when Gio isn't available."""

    def get_network_available(self) -> bool:
        return False


__all__ = ["OfflineGuard", "OfflineStatus", "OfflineViolation"]
