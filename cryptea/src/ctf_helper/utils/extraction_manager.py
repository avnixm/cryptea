"""Shared helpers for managing extracted files and directories."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, Optional


class ExtractionManager:
    """Utility for preparing extraction directories and recording metadata."""

    def __init__(self, base_dir: Optional[str] = None, prefix: str = "extract_") -> None:
        if base_dir and base_dir.strip():
            root = Path(base_dir).expanduser()
        else:
            root = Path(tempfile.mkdtemp(prefix=prefix))
        root.mkdir(parents=True, exist_ok=True)
        self.root = root

    def subdir(self, name: str) -> Path:
        """Return/create a sub-directory beneath the root."""
        path = self.root / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def record(path: Path, *, method: str, extra: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        """Build a metadata record for an extracted file."""
        info: Dict[str, object] = {
            "path": str(path),
            "name": path.name,
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "method": method,
        }
        if extra:
            info.update(extra)
        return info

