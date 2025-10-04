#!/usr/bin/env python3
"""Helper entry point to run Cryptea from a source checkout."""

from __future__ import annotations

import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

os.environ.setdefault("CTF_HELPER_SUPPRESS_SANDBOX_WARNING", "1")

from ctf_helper.application import run  # type: ignore[import]


if __name__ == "__main__":  # pragma: no cover - manual entry point
    run()
