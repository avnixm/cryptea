"""Helpers for resolving XDG data/config/cache locations."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Literal

GLib = None
try:  # pragma: no cover - fallback for test environments without GTK
    gi_repository = importlib.import_module("gi.repository")
    GLib = getattr(gi_repository, "GLib")
except (ImportError, AttributeError, ValueError):  # pragma: no cover - test fallback
    GLib = None

APP_NAMESPACE = "cryptea"


def _ensure(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _xdg_base(name: str, fallback: str) -> Path:
    if GLib is not None:
        getter = getattr(GLib, f"get_user_{name}_dir")
        return Path(getter()) / APP_NAMESPACE
    env_var = {
        "data": "XDG_DATA_HOME",
        "config": "XDG_CONFIG_HOME",
        "cache": "XDG_CACHE_HOME",
    }[name]
    base = os.environ.get(env_var)
    if not base:
        base = os.path.join(Path.home(), fallback)
    return Path(base) / APP_NAMESPACE


def user_data_dir() -> Path:
    return _ensure(_xdg_base("data", ".local/share"))


def user_config_dir() -> Path:
    return _ensure(_xdg_base("config", ".config"))


def user_cache_dir() -> Path:
    return _ensure(_xdg_base("cache", ".cache"))


def log_dir() -> Path:
    return _ensure(user_data_dir() / "logs")


def snapshots_dir() -> Path:
    return _ensure(user_data_dir() / "snapshots")


def db_path() -> Path:
    return user_data_dir() / "db.sqlite3"


def help_dir() -> Path:
    return _ensure(user_data_dir() / "help")


def templates_dir() -> Path:
    return _ensure(user_data_dir() / "templates")


def runtime_path(kind: Literal["data", "config", "cache"]) -> Path:
    if kind == "data":
        return user_data_dir()
    if kind == "config":
        return user_config_dir()
    if kind == "cache":
        return user_cache_dir()
    msg = f"unknown runtime path kind: {kind}"
    raise ValueError(msg)
