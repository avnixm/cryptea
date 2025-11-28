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
        detect_processes: str = "false",
        detect_injected_code: str = "false",
        detect_decrypted: str = "false",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        sample_limit = max(10, int(strings_limit or "200"))
        keyword_tokens = [token.strip() for token in (keywords or "").split(",") if token.strip()]
        include_hash = self._truthy(include_hashes)
        detect_proc = self._truthy(detect_processes)
        detect_inject = self._truthy(detect_injected_code)
        detect_decrypt = self._truthy(detect_decrypted)
        
        summary = self._analyze_memory(
            path,
            sample_limit=sample_limit,
            keywords=keyword_tokens,
            include_hashes=include_hash,
            detect_processes=detect_proc,
            detect_injected_code=detect_inject,
            detect_decrypted=detect_decrypt,
        )
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
        detect_processes: bool = False,
        detect_injected_code: bool = False,
        detect_decrypted: bool = False,
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
        
        # Add advanced detection features
        if detect_processes:
            processes = self._detect_processes(path)
            if processes:
                payload["processes"] = processes
        
        if detect_injected_code:
            injected = self._detect_injected_code(path)
            if injected:
                payload["injected_code"] = injected
        
        if detect_decrypted:
            decrypted = self._detect_decrypted_content(path)
            if decrypted:
                payload["decrypted_content"] = decrypted
        
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

    def _detect_processes(self, path: Path) -> Dict[str, object]:
        """Detect running processes from memory structures."""
        processes: List[Dict[str, object]] = []
        
        # Windows EPROCESS structure signatures
        # EPROCESS typically contains process name, PID, parent PID
        epprocess_patterns = [
            b".exe\x00",  # Executable name
            b"cmd.exe",
            b"explorer.exe",
            b"notepad.exe",
            b"winlogon.exe",
            b"lsass.exe",
            b"svchost.exe",
        ]
        
        # Linux task_struct patterns (process name)
        linux_process_patterns = [
            b"/bin/sh",
            b"/bin/bash",
            b"init",
            b"systemd",
            b"sshd",
            b"apache2",
            b"nginx",
        ]
        
        chunk_size = 1 << 20  # 1MB chunks
        offset = 0
        process_names_found: Dict[str, List[int]] = {}
        
        with path.open("rb") as fh:
            while offset < min(100 * (1 << 20), path.stat().st_size):  # Scan first 100MB
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                
                # Search for Windows process names
                for pattern in epprocess_patterns:
                    idx = 0
                    while True:
                        idx = chunk.find(pattern, idx)
                        if idx == -1:
                            break
                        name = pattern.rstrip(b"\x00").decode("ascii", errors="ignore")
                        absolute_offset = offset + idx
                        if name not in process_names_found:
                            process_names_found[name] = []
                        if len(process_names_found[name]) < 10:
                            process_names_found[name].append(absolute_offset)
                        idx += len(pattern)
                
                # Search for Linux process names
                for pattern in linux_process_patterns:
                    idx = 0
                    while True:
                        idx = chunk.find(pattern, idx)
                        if idx == -1:
                            break
                        name = pattern.decode("ascii", errors="ignore")
                        absolute_offset = offset + idx
                        if name not in process_names_found:
                            process_names_found[name] = []
                        if len(process_names_found[name]) < 10:
                            process_names_found[name].append(absolute_offset)
                        idx += len(pattern)
                
                offset += len(chunk)
        
        # Convert to process list
        for name, offsets in list(process_names_found.items())[:50]:
            processes.append({
                "name": name,
                "offsets": offsets[:5],  # First 5 occurrences
                "occurrence_count": len(offsets),
                "confidence": "medium" if len(offsets) > 1 else "low",
            })
        
        return {
            "count": len(processes),
            "processes": processes,
            "note": "Process detection based on executable name signatures. Use Volatility for detailed analysis.",
        }

    def _detect_injected_code(self, path: Path) -> Dict[str, object]:
        """Detect shellcode and injected malicious code patterns."""
        injected_regions: List[Dict[str, object]] = []
        
        chunk_size = 64 * 1024  # 64KB chunks for analysis
        offset = 0
        min_region_size = 512
        
        with path.open("rb") as fh:
            while offset < min(500 * (1 << 20), path.stat().st_size):  # Scan first 500MB
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                
                # Calculate entropy for chunk
                entropy = self._entropy(Counter(chunk), len(chunk))
                
                # Check for common shellcode patterns
                shellcode_patterns = [
                    b"\x90" * 10,  # NOP sled
                    b"\x48\x31\xc0",  # xor rax, rax (x64)
                    b"\x31\xc0",  # xor eax, eax (x32)
                    b"\xeb\xfe",  # Infinite loop
                    b"\xcd\x80",  # int 0x80 (Linux syscall)
                    b"\x0f\x05",  # syscall (x64)
                ]
                
                has_shellcode_pattern = False
                for pattern in shellcode_patterns:
                    if pattern in chunk:
                        has_shellcode_pattern = True
                        break
                
                # High entropy + shellcode pattern = likely injected code
                if entropy > 7.0 and has_shellcode_pattern:
                    injected_regions.append({
                        "offset": offset,
                        "size": len(chunk),
                        "entropy": round(entropy, 2),
                        "indicators": ["high_entropy", "shellcode_pattern"],
                        "confidence": "high" if entropy > 7.5 else "medium",
                    })
                elif entropy > 7.8:  # Very high entropy (likely encrypted/compressed)
                    injected_regions.append({
                        "offset": offset,
                        "size": len(chunk),
                        "entropy": round(entropy, 2),
                        "indicators": ["very_high_entropy"],
                        "confidence": "medium",
                        "note": "Very high entropy may indicate encrypted payload or packed code",
                    })
                
                offset += chunk_size
        
        # Merge nearby regions
        merged_regions: List[Dict[str, object]] = []
        for region in injected_regions[:30]:  # Limit to 30
            if not merged_regions:
                merged_regions.append(region)
                continue
            
            last = merged_regions[-1]
            last_offset_val = last.get("offset", 0)
            last_size_val = last.get("size", 0)
            current_offset_val = region.get("offset", 0)
            
            last_offset = int(str(last_offset_val)) if last_offset_val is not None else 0
            last_size = int(str(last_size_val)) if last_size_val is not None else 0
            current_offset = int(str(current_offset_val)) if current_offset_val is not None else 0
            region_size_val = region.get("size", 0)
            region_size = int(str(region_size_val)) if region_size_val is not None else 0
            
            # If regions are close, merge them
            if current_offset - (last_offset + last_size) < chunk_size:
                last["size"] = (current_offset + region_size) - last_offset
                if "indicators" in last and "indicators" in region:
                    indicators_list_val = last.get("indicators", [])
                    region_indicators_val = region.get("indicators", [])
                    if isinstance(indicators_list_val, list) and isinstance(region_indicators_val, list):
                        indicators_list_val.extend(region_indicators_val)
            else:
                merged_regions.append(region)
        
        return {
            "count": len(merged_regions),
            "regions": merged_regions[:20],
            "note": "Injected code detection based on entropy and shellcode pattern analysis",
        }

    def _detect_decrypted_content(self, path: Path) -> Dict[str, object]:
        """Detect decrypted content that wouldn't appear on disk."""
        decrypted_candidates: List[Dict[str, object]] = []
        
        # Patterns that suggest decrypted data
        decrypted_indicators = [
            (b"BEGIN PRIVATE KEY", "RSA private key"),
            (b"BEGIN PUBLIC KEY", "RSA public key"),
            (b"BEGIN CERTIFICATE", "X.509 certificate"),
            (b"-----BEGIN", "PEM encoded data"),
            (b"<html>", "HTML content"),
            (b"<!DOCTYPE", "HTML/XML document"),
            (b"<?xml", "XML document"),
            (b"{\"", "JSON data"),
            (b"SELECT ", "SQL query"),
            (b"FROM ", "SQL query"),
            (b"CREATE TABLE", "SQL DDL"),
        ]
        
        chunk_size = 1 << 20  # 1MB
        offset = 0
        max_candidates = 30
        
        with path.open("rb") as fh:
            while offset < min(200 * (1 << 20), path.stat().st_size):  # First 200MB
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                
                for pattern, label in decrypted_indicators:
                    if len(decrypted_candidates) >= max_candidates:
                        break
                    
                    idx = chunk.find(pattern)
                    if idx != -1:
                        # Extract surrounding context
                        start = max(0, idx - 100)
                        end = min(len(chunk), idx + 500)
                        context = chunk[start:end]
                        
                        # Check if it looks like decrypted plaintext
                        printable_ratio = sum(1 for b in context if 32 <= b < 127) / len(context)
                        
                        if printable_ratio > 0.8:  # High printable content
                            absolute_offset = offset + idx
                            decrypted_candidates.append({
                                "offset": absolute_offset,
                                "type": label,
                                "pattern": pattern.decode("ascii", errors="ignore"),
                                "printable_ratio": round(printable_ratio, 2),
                                "sample": context[:200].decode("utf-8", errors="replace")[:100],
                                "confidence": "high" if printable_ratio > 0.9 else "medium",
                            })
                
                offset += len(chunk)
                if len(decrypted_candidates) >= max_candidates:
                    break
        
        return {
            "count": len(decrypted_candidates),
            "candidates": decrypted_candidates,
            "note": "Decrypted content detection based on plaintext pattern matching",
        }
