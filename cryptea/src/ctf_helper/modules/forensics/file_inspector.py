"""Offline file inspection helpers."""

from __future__ import annotations

import hashlib
import json
import math
import mimetypes
import tarfile
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from ..base import ToolResult


class FileInspectorTool:
    name = "File Inspector"
    description = "Summarise metadata, hashes, and magic bytes for a local file."
    category = "Forensics"

    def run(
        self,
        file_path: str,
        preview_bytes: str = "256",
        include_entropy: str = "false",
        include_strings: str = "false",
        strings_min_length: str = "4",
        strings_limit: str = "15",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        data = path.read_bytes()

        stats = path.stat()
        preview_len = max(0, int(preview_bytes or "0"))
        preview_slice = data[:preview_len] if preview_len else b""

        info: Dict[str, object] = {
            "path": str(path.resolve()),
            "name": path.name,
            "size_bytes": stats.st_size,
            "permissions": oct(stats.st_mode & 0o777),
            "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
            "mimetype": mimetypes.guess_type(path.name)[0],
            "hashes": {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            "signatures": self._signature_hints(data),
            "preview": {
                "bytes": preview_len,
                "hex": preview_slice.hex(),
                "ascii": preview_slice.decode("latin-1", errors="replace"),
            },
        }

        if self._truthy(include_entropy):
            info["entropy"] = round(self._shannon_entropy(data), 4)

        if self._truthy(include_strings):
            strings_payload = self._strings_preview(
                data,
                min_length=max(1, int(strings_min_length or "4")),
                limit=max(0, int(strings_limit or "0")),
            )
            if strings_payload:
                info["strings_preview"] = strings_payload

        archive_summary = self._archive_listing(path)
        if archive_summary:
            info["archive"] = archive_summary

        body = json.dumps(info, indent=2)
        return ToolResult(title=f"Metadata for {path.name}", body=body, mime_type="application/json")

    def _signature_hints(self, data: bytes) -> List[str]:
        signatures = []
        magic_map = {
            b"\x7fELF": "ELF executable",
            b"MZ": "PE executable",
            b"PK\x03\x04": "ZIP archive",
            b"\x89PNG\r\n\x1a\n": "PNG image",
            b"GIF87a": "GIF image",
            b"GIF89a": "GIF image",
            b"%PDF": "PDF document",
            b"\xff\xd8\xff": "JPEG image",
            b"\x1f\x8b\x08": "GZIP archive",
        }
        for magic, label in magic_map.items():
            if data.startswith(magic):
                signatures.append(label)
        if not signatures:
            signatures.append("Unknown/opaque")
        return signatures

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((count / total) * math.log2(count / total) for count in counts.values())

    def _strings_preview(self, data: bytes, *, min_length: int, limit: int) -> List[str]:
        results: List[str] = []
        current: bytearray = bytearray()
        for byte in data:
            if 32 <= byte <= 126:
                current.append(byte)
            else:
                if len(current) >= min_length:
                    results.append(current.decode("ascii", errors="ignore"))
                current.clear()
        if len(current) >= min_length:
            results.append(current.decode("ascii", errors="ignore"))
        if limit > 0:
            results = results[:limit]
        return results

    def _archive_listing(self, path: Path) -> Dict[str, object] | None:
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    members = archive.namelist()
                    return {"member_count": len(members), "members": members[:20]}
            if tarfile.is_tarfile(path):
                with tarfile.open(path) as archive:
                    members = archive.getmembers()
                    return {
                        "member_count": len(members),
                        "members": [member.name for member in members[:20]],
                    }
        except (OSError, tarfile.ReadError, zipfile.BadZipFile):
            return {"error": "Archive detected but couldn't be read"}
        return None

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
