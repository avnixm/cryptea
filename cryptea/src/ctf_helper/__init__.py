"""Cryptea core package."""

from __future__ import annotations

__all__ = ["run"]


def run() -> None:
    from .application import run as _run

    _run()
