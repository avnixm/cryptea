"""Runtime configuration with offline defaults.

This module is overwritten at build time when Meson generates
``build_config.py``. When running from a source checkout, we default to the
strict offline posture as well.
"""

from __future__ import annotations

import os


def _truthy_env(name: str, default: str = "0") -> bool:
    value = os.getenv(name, default)
    return value not in {"0", "false", "False"}


OFFLINE_BUILD: bool = _truthy_env("OFFLINE_BUILD", "1")
DEV_PROFILE_ENABLED: bool = _truthy_env("DEV_PROFILE_ENABLED", "0")
SUPPRESS_SANDBOX_WARNING: bool = _truthy_env(
    "CTF_HELPER_SUPPRESS_SANDBOX_WARNING",
    "1" if DEV_PROFILE_ENABLED else "0",
)

APP_ID = "org.example.CTFHelper"
APP_NAME = "Cryptea"
APP_VERSION = "0.1.0"

try:  # pragma: no cover - optional override generated at build time
    from . import build_config as _generated  # type: ignore
except ImportError:  # pragma: no cover - development fallback
    _generated = None

if _generated:
    OFFLINE_BUILD = bool(_generated.OFFLINE_BUILD)
    DEV_PROFILE_ENABLED = bool(_generated.DEV_PROFILE_ENABLED)
    SUPPRESS_SANDBOX_WARNING = bool(
        getattr(_generated, "SUPPRESS_SANDBOX_WARNING", SUPPRESS_SANDBOX_WARNING)
    )
    APP_ID = getattr(_generated, "APP_ID", APP_ID)
    APP_NAME = getattr(_generated, "APP_NAME", APP_NAME)
    APP_VERSION = getattr(_generated, "APP_VERSION", APP_VERSION)
