"""Offline-friendly memory dump heuristics."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from ..base import ToolResult


class MemoryAnalyzerTool:
    """Provide lightweight signal from large memory images without volatility."""

    name = "Memory Analyzer"
    description = "Scan memory dumps for entropy, suspicious strings, and embedded artefacts."
    category = "Forensics"

    def run(
        self,
        file_path: str,
        strings_limit: str = "200",
        keywords: str = "flag,password,secret",
        include_hashes: str = "false",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        sample_limit = max(10, int(strings_limit or "200"))
        keyword_tokens = [token.strip() for token in (keywords or "").split(",") if token.strip()]
        include_hash = self._truthy(include_hashes)
        summary = self._analyze_memory(path, sample_limit=sample_limit, keywords=keyword_tokens, include_hashes=include_hash)
        body = json.dumps(summary, indent=2)
        title = f"Memory insights for {path.name}"
        return ToolResult(title=title, body=body, mime_type="application/json")

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------
    def _analyze_memory(
        self,
        path: Path,
        *,
        sample_limit: int,
        keywords: List[str],
        include_hashes: bool,
    ) -> Dict[str, object]:
        stats = path.stat()
        keyword_map = {token.lower(): token for token in keywords}
        keyword_hits: Dict[str, List[Dict[str, object]]] = {token: [] for token in keyword_map}
        strings_sample: List[Dict[str, object]] = []
        flag_candidates: List[Dict[str, object]] = []
        notes: List[str] = []

        counts: Counter[int] = Counter()
        total_bytes = 0
        chunk_size = 1 << 20
        min_length = 4
        string_buffer = bytearray()
        current_start = 0
        offset = 0
        total_strings = 0
        flag_regex = re.compile(r"flag\{[^\}]{0,120}\}", re.IGNORECASE)

        signature_map: Dict[bytes, str] = {
            b"MZ": "Embedded PE header",
            b"\x7fELF": "Embedded ELF binary",
            b"PK\x03\x04": "ZIP archive header",
            b"SCCA": "Possible Windows registry hive",
            b"\x89PNG\r\n\x1a\n": "Embedded PNG image",
            b"\x1f\x8b\x08": "GZIP stream",
        }
        max_signature_len = max((len(sig) for sig in signature_map), default=0)
        signature_hits: Dict[tuple[int, str], Dict[str, object]] = {}
        signature_tail = b""

        hashers = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()] if include_hashes else []

        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                counts.update(chunk)
                total_bytes += len(chunk)
                if hashers:
                    for hasher in hashers:
                        hasher.update(chunk)

                combined = signature_tail + chunk
                for pattern, label in signature_map.items():
                    start = 0
                    while True:
                        idx = combined.find(pattern, start)
                        if idx == -1:
                            break
                        absolute = offset - len(signature_tail) + idx
                        key = (absolute, label)
                        if key not in signature_hits and len(signature_hits) < 64:
                            signature_hits[key] = {"offset": absolute, "signature": label}
                        start = idx + 1
                if max_signature_len > 1:
                    signature_tail = combined[-(max_signature_len - 1) :]
                else:
                    signature_tail = b""

                for i, byte in enumerate(chunk):
                    if 32 <= byte <= 126:
                        if not string_buffer:
                            current_start = offset + i
                        string_buffer.append(byte)
                    else:
                        total_strings = self._finalise_string(
                            string_buffer,
                            current_start,
                            total_strings,
                            sample_limit,
                            keyword_map,
                            keyword_hits,
                            flag_candidates,
                            flag_regex,
                            min_length,
                            strings_sample,
                        )
                offset += len(chunk)

        total_strings = self._finalise_string(
            string_buffer,
            current_start,
            total_strings,
            sample_limit,
            keyword_map,
            keyword_hits,
            flag_candidates,
            flag_regex,
            min_length,
            strings_sample,
        )

        entropy = self._entropy(counts, total_bytes)
        top_bytes = [
            {"byte": f"0x{value:02x}", "count": count, "frequency": round(count / total_bytes, 6)}
            for value, count in counts.most_common(8)
        ] if total_bytes else []

        keyword_payload = {
            keyword_map[key]: hits
            for key, hits in keyword_hits.items()
            if hits
        }

        if entropy > 7.5:
            notes.append("High entropy suggests packed or compressed regions.")
        if flag_candidates:
            notes.append("Potential flag strings detected; inspect the candidates section.")
        if not strings_sample:
            notes.append("No ASCII strings identified with the current minimum length.")

        analysis: Dict[str, object] = {
            "entropy": round(entropy, 4),
            "byte_histogram_top": top_bytes,
            "strings_total": total_strings,
            "string_sample": strings_sample,
            "string_sample_truncated": total_strings > len(strings_sample),
            "keyword_hits": keyword_payload,
            "flag_candidates": flag_candidates,
            "embedded_signatures": list(signature_hits.values()),
        }
        if not analysis["keyword_hits"]:
            analysis.pop("keyword_hits")
        if not analysis["flag_candidates"]:
            analysis.pop("flag_candidates")
        if not analysis["embedded_signatures"]:
            analysis.pop("embedded_signatures")

        payload: Dict[str, object] = {
            "file": str(path.resolve()),
            "size_bytes": stats.st_size,
            "modified": datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat(),
            "analysis": analysis,
        }
        if notes:
            payload["notes"] = notes
        if include_hashes and hashers:
            payload["hashes"] = {
                "md5": hashers[0].hexdigest(),
                "sha1": hashers[1].hexdigest(),
                "sha256": hashers[2].hexdigest(),
            }
        return payload

    def _finalise_string(
        self,
        buffer: bytearray,
        start_offset: int,
        total_strings: int,
        sample_limit: int,
        keyword_map: Dict[str, str],
        keyword_hits: Dict[str, List[Dict[str, object]]],
        flag_candidates: List[Dict[str, object]],
        flag_regex: re.Pattern[str],
        min_length: int,
        strings_sample: List[Dict[str, object]],
    ) -> int:
        if len(buffer) < min_length:
            buffer.clear()
            return total_strings
        value = buffer.decode("ascii", errors="ignore")
        buffer.clear()
        total_strings += 1
        if len(strings_sample) < sample_limit:
            strings_sample.append({"offset": start_offset, "value": value})
        lower_value = value.lower()
        for key, label in keyword_map.items():
            if key and key in lower_value:
                hits = keyword_hits.setdefault(key, [])
                if len(hits) < sample_limit:
                    hits.append({"offset": start_offset, "value": value})
        for match in flag_regex.finditer(value):
            if len(flag_candidates) < sample_limit * 2:
                flag_candidates.append({"offset": start_offset + match.start(), "value": match.group()})
        return total_strings

    def _entropy(self, counts: Counter[int], total: int) -> float:
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
