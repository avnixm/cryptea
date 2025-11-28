"""Generate simple filesystem timelines."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import subprocess
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
        extract_mace: str = "false",
        extract_exif: str = "false",
    ) -> ToolResult:
        path = Path(target_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        limit = max(1, int(max_entries or "500"))
        include_dirs = self._truthy(include_directories)
        fmt = (output_format or "csv").strip().lower()
        include_hash = self._truthy(include_hashes)
        extract_mace_timestamps = self._truthy(extract_mace)
        extract_exif_timestamps = self._truthy(extract_exif)

        entries, truncated, notes = self._collect_entries(
            path,
            limit=limit,
            include_dirs=include_dirs,
            include_hashes=include_hash,
            extract_mace=extract_mace_timestamps,
            extract_exif=extract_exif_timestamps,
        )
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
        extract_mace: bool = False,
        extract_exif: bool = False,
    ) -> Tuple[List[Dict[str, object]], bool, List[str]]:
        entries: List[Dict[str, object]] = []
        notes: List[str] = []

        def _add_entry(candidate: Path) -> None:
            try:
                entry = self._build_entry(
                    candidate,
                    include_hashes=include_hashes,
                    extract_mace=extract_mace,
                    extract_exif=extract_exif,
                )
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

    def _build_entry(
        self,
        candidate: Path,
        *,
        include_hashes: bool,
        extract_mace: bool = False,
        extract_exif: bool = False,
    ) -> Dict[str, object]:
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
        
        # Extract MACE timestamps (NTFS)
        if extract_mace and candidate.is_file():
            mace_timestamps = self._extract_mace_timestamps(candidate)
            if mace_timestamps:
                entry["mace_timestamps"] = mace_timestamps
        
        # Extract EXIF timestamps (images)
        if extract_exif and candidate.is_file():
            exif_timestamps = self._extract_exif_timestamps(candidate)
            if exif_timestamps:
                entry["exif_timestamps"] = exif_timestamps
        
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

    def _extract_mace_timestamps(self, path: Path) -> Optional[Dict[str, str]]:
        """Extract MACE (Modified, Accessed, Created, Entry) timestamps from NTFS."""
        # MACE timestamps are stored in NTFS $STANDARD_INFORMATION and $FILE_NAME attributes
        # This is a simplified extraction - full implementation would parse NTFS structures
        
        try:
            # Use stat to get basic timestamps (on Linux, these may reflect MACE-like info)
            stat = path.stat()
            
            # Note: On non-NTFS filesystems, we can't get true MACE timestamps
            # This is a placeholder that would need NTFS parsing libraries for full support
            # For now, return enhanced stat timestamps with labels
            
            mace: Dict[str, str] = {
                "M_Modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "A_Accessed": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
                "C_Created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                "E_Entry": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),  # Entry time same as created on non-NTFS
            }
            
            # Try to use exiftool for better NTFS timestamp extraction if available
            exiftool_path = self._resolve_exiftool()
            if exiftool_path:
                try:
                    proc = subprocess.run(
                        [
                            exiftool_path,
                            "-j",
                            "-FileModifyDate",
                            "-FileAccessDate",
                            "-FileCreateDate",
                            "-DateCreated",
                            str(path),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if proc.returncode == 0 and proc.stdout:
                        exif_data = json.loads(proc.stdout)
                        if exif_data and len(exif_data) > 0:
                            data = exif_data[0]
                            if "FileModifyDate" in data:
                                mace["M_Modified"] = data["FileModifyDate"]
                            if "FileAccessDate" in data:
                                mace["A_Accessed"] = data["FileAccessDate"]
                            if "FileCreateDate" in data or "DateCreated" in data:
                                created = data.get("FileCreateDate") or data.get("DateCreated")
                                if created:
                                    mace["C_Created"] = created
                except Exception:
                    pass
            
            return mace
        except Exception:
            return None

    def _extract_exif_timestamps(self, path: Path) -> Optional[Dict[str, str]]:
        """Extract EXIF timestamps from image metadata."""
        # Check if file is an image
        ext = path.suffix.lower()
        if ext not in [".jpg", ".jpeg", ".png", ".tiff", ".tif", ".heic", ".cr2", ".nef"]:
            return None
        
        exiftool_path = self._resolve_exiftool()
        if not exiftool_path:
            # Fallback: try Python exifread if available
            try:
                import exifread
                with path.open("rb") as f:
                    tags = exifread.process_file(f)
                    
                    exif_times: Dict[str, str] = {}
                    # Common EXIF date/time fields
                    date_fields = [
                        ("DateTime", "DateTime"),
                        ("DateTimeOriginal", "DateTimeOriginal"),
                        ("DateTimeDigitized", "DateTimeDigitized"),
                        ("EXIF DateTimeOriginal", "DateTimeOriginal"),
                        ("EXIF DateTimeDigitized", "DateTimeDigitized"),
                    ]
                    
                    for field, label in date_fields:
                        if field in tags:
                            value = str(tags[field])
                            if value and value != "0000:00:00 00:00:00":
                                exif_times[label] = value
                    
                    if exif_times:
                        return exif_times
            except ImportError:
                pass
            
            return None
        
        try:
            proc = subprocess.run(
                [
                    exiftool_path,
                    "-j",
                    "-DateTime",
                    "-DateTimeOriginal",
                    "-DateTimeDigitized",
                    "-CreateDate",
                    "-ModifyDate",
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                exif_data = json.loads(proc.stdout)
                if exif_data and len(exif_data) > 0:
                    data = exif_data[0]
                    exif_times: Dict[str, str] = {}
                    
                    # Extract timestamp fields
                    timestamp_fields = [
                        "DateTime",
                        "DateTimeOriginal",
                        "DateTimeDigitized",
                        "CreateDate",
                        "ModifyDate",
                    ]
                    
                    for field in timestamp_fields:
                        if field in data:
                            value = data[field]
                            if value and str(value).strip() != "":
                                exif_times[field] = str(value)
                    
                    return exif_times if exif_times else None
        except Exception:
            pass
        
        return None

    def _resolve_exiftool(self) -> Optional[str]:
        """Resolve exiftool command path."""
        import shutil
        path = shutil.which("exiftool")
        return path if path else None
