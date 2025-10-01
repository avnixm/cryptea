"""Offline file inspection helpers."""

from __future__ import annotations

import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Dict, List

from ..base import ToolResult


class FileInspectorTool:
    name = "File Inspector"
    description = "Summarise metadata, hashes, and magic bytes for a local file."
    category = "Forensics"

    def run(self, file_path: str) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        with path.open("rb") as handle:
            raw = handle.read()
        info: Dict[str, object] = {
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "mimetype": mimetypes.guess_type(path.name)[0],
            "md5": hashlib.md5(raw).hexdigest(),
            "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "leading_bytes": raw[:32].hex(),
        }
        body = json.dumps(info, indent=2)
        return ToolResult(title=f"Metadata for {path.name}", body=body, mime_type="application/json")
