"""Generate simple filesystem timelines."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from ..base import ToolResult


class TimelineBuilderTool:
    """Builds lightweight timelines from local directories or files."""

    name = "Timeline Builder"
    description = "Enumerate files, capture timestamps, and export CSV or JSON timelines."
    category = "Forensics"

    def run(
        self,
        target_path: str,
        max_entries: str = "500",
        include_directories: str = "true",
        output_format: str = "csv",
        include_hashes: str = "false",
    ) -> ToolResult:
        path = Path(target_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        limit = max(1, int(max_entries or "500"))
        include_dirs = self._truthy(include_directories)
        fmt = (output_format or "csv").strip().lower()
        include_hash = self._truthy(include_hashes)

        entries, truncated, notes = self._collect_entries(path, limit=limit, include_dirs=include_dirs, include_hashes=include_hash)
        if fmt not in {"csv", "json"}:
            fmt = "csv"

        if fmt == "json":
            payload = {
                "target": str(path.resolve()),
                "entries": entries,
                "truncated": truncated,
                "notes": notes,
            }
            body = json.dumps(payload, indent=2)
            mime = "application/json"
        else:
            body = self._entries_to_csv(entries)
            if truncated:
                body += "\n# Timeline truncated; increase the entry limit for more results."
            for note in notes:
                body += f"\n# NOTE: {note}"
            mime = "text/csv"

        title = f"Timeline for {path.name or path}".strip()
        return ToolResult(title=title, body=body, mime_type=mime)

    # ------------------------------------------------------------------
    # Collection helpers
    # ------------------------------------------------------------------
    def _collect_entries(
        self,
        path: Path,
        *,
        limit: int,
        include_dirs: bool,
        include_hashes: bool,
    ) -> Tuple[List[Dict[str, object]], bool, List[str]]:
        entries: List[Dict[str, object]] = []
        notes: List[str] = []

        def _add_entry(candidate: Path) -> None:
            try:
                entry = self._build_entry(candidate, include_hashes=include_hashes)
            except OSError as exc:
                notes.append(f"Skipped {candidate}: {exc}")
                return
            entries.append(entry)

        if path.is_file():
            _add_entry(path)
        else:
            iterator = path.rglob("*")
            for candidate in iterator:
                if candidate.is_dir() and not include_dirs:
                    continue
                _add_entry(candidate)

        entries.sort(key=lambda item: (item.get("modified") or "", item.get("path") or ""))
        truncated = len(entries) > limit
        if truncated:
            entries = entries[:limit]
        return entries, truncated, notes

    def _build_entry(self, candidate: Path, *, include_hashes: bool) -> Dict[str, object]:
        stat = candidate.stat()
        entry: Dict[str, object] = {
            "path": str(candidate.resolve()),
            "name": candidate.name,
            "type": "directory" if candidate.is_dir() else "file",
            "size_bytes": stat.st_size if candidate.is_file() else 0,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
            "created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
        }
        if include_hashes and candidate.is_file():
            entry["sha256"] = self._hash_file(candidate)
        return entry

    def _entries_to_csv(self, entries: List[Dict[str, object]]) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["path", "type", "size_bytes", "modified", "accessed", "created", "sha256"])
        for item in entries:
            writer.writerow(
                [
                    item.get("path", ""),
                    item.get("type", ""),
                    item.get("size_bytes", ""),
                    item.get("modified", ""),
                    item.get("accessed", ""),
                    item.get("created", ""),
                    item.get("sha256", ""),
                ]
            )
        return buffer.getvalue().strip()

    def _hash_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        chunk_size = 1 << 20
        with path.open("rb") as fh:
            while chunk := fh.read(chunk_size):
                digest.update(chunk)
        return digest.hexdigest()

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
