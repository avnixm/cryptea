"""Aggregate binary metadata via system tooling."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List

from ..base import ToolResult


class BinaryInspector:
    name = "PE/ELF Inspector"
    description = "Collect headers, sections, symbols, and security flags using local toolchain programs."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        include_sections: str = "true",
        include_symbols: str = "true",
        include_checksec: str = "true",
        include_file: str = "true",
        include_headers: str = "true",
        include_segments: str = "false",
        include_dynamic: str = "false",
        include_libraries: str = "false",
        include_strings: str = "false",
        strings_min_length: str = "4",
        max_lines: str = "400",
    ) -> ToolResult:
        target = Path(file_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        limit = self._safe_int(max_lines, default=400, minimum=50, maximum=2000)
        string_min = self._safe_int(strings_min_length, default=4, minimum=2, maximum=32)

        snippets: List[str] = []
        if self._truthy(include_file):
            snippets.append(
                self._run_tool("file", ["file", str(target)], limit=limit, fallback="file utility not found")
            )
        if self._truthy(include_headers):
            snippets.append(self._collect_headers(target, limit))
        if self._truthy(include_segments):
            snippets.append(self._collect_segments(target, limit))
        if self._truthy(include_sections):
            snippets.append(self._collect_sections(target, limit))
        if self._truthy(include_symbols):
            snippets.append(self._collect_symbols(target, limit))
        if self._truthy(include_dynamic):
            snippets.append(self._collect_dynamic(target, limit))
        if self._truthy(include_checksec):
            snippets.append(self._collect_checksec(target, limit))
        if self._truthy(include_libraries):
            snippets.append(self._collect_libraries(target, limit))
        if self._truthy(include_strings):
            snippets.append(self._collect_strings(target, string_min, limit))

        body = "\n\n".join(filter(None, snippets)) or "(no data collected)"
        return ToolResult(title=f"Inspector results for {target.name}", body=body)

    def _collect_headers(self, target: Path, limit: int) -> str:
        if shutil.which("readelf"):
            return self._run_tool("readelf -h", ["readelf", "-h", str(target)], limit=limit)
        if shutil.which("objdump"):
            return self._run_tool("objdump -f", ["objdump", "-f", str(target)], limit=limit)
        return "Headers: readelf/objdump not found"

    def _collect_segments(self, target: Path, limit: int) -> str:
        if shutil.which("readelf"):
            return self._run_tool("readelf -l", ["readelf", "-l", str(target)], limit=limit)
        return "Segments: readelf not found"

    def _collect_sections(self, target: Path, limit: int) -> str:
        if shutil.which("readelf"):
            return self._run_tool("readelf -S", ["readelf", "-S", str(target)], limit=limit)
        if shutil.which("objdump"):
            return self._run_tool("objdump -h", ["objdump", "-h", str(target)], limit=limit)
        return "Sections: readelf/objdump not found"

    def _collect_symbols(self, target: Path, limit: int) -> str:
        outputs: List[str] = []
        if shutil.which("nm"):
            outputs.append(self._run_tool("nm -g", ["nm", "-g", str(target)], limit=limit))
            outputs.append(self._run_tool("nm -D", ["nm", "-D", str(target)], limit=limit))
        elif shutil.which("objdump"):
            outputs.append(self._run_tool("objdump -t", ["objdump", "-t", str(target)], limit=limit))
        else:
            return "Symbols: nm/objdump not found"
        return "\n\n".join(filter(None, outputs))

    def _collect_dynamic(self, target: Path, limit: int) -> str:
        if shutil.which("readelf"):
            return self._run_tool("readelf -d", ["readelf", "-d", str(target)], limit=limit)
        if shutil.which("objdump"):
            return self._run_tool("objdump -p", ["objdump", "-p", str(target)], limit=limit)
        return "Dynamic section: readelf/objdump not found"

    def _collect_checksec(self, target: Path, limit: int) -> str:
        if shutil.which("checksec"):
            return self._run_tool("checksec", ["checksec", "--file", str(target)], limit=limit)
        if shutil.which("hardening-check"):
            return self._run_tool("hardening-check", ["hardening-check", str(target)], limit=limit)
        return "Security flags: checksec/hardening-check not found"

    def _collect_libraries(self, target: Path, limit: int) -> str:
        if shutil.which("ldd"):
            return self._run_tool("ldd", ["ldd", str(target)], limit=limit)
        if shutil.which("otool"):
            return self._run_tool("otool -L", ["otool", "-L", str(target)], limit=limit)
        return "Linked libraries: ldd/otool not found"

    def _collect_strings(self, target: Path, min_length: int, limit: int) -> str:
        if shutil.which("strings"):
            output = self._run_tool(
                f"strings -n {min_length}",
                ["strings", "-a", "-n", str(min_length), str(target)],
                limit=limit,
            )
            return output
        # Fallback to a simple Python-based extractor
        try:
            data = target.read_bytes()
        except OSError as exc:
            return f"Strings: unable to read file ({exc})"

        printable = set(range(32, 127)) | {9, 10, 13}
        current: List[str] = []
        results: List[str] = []
        for byte in data:
            if byte in printable:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    results.append("".join(current))
                current = []
        if len(current) >= min_length:
            results.append("".join(current))

        formatted = "\n".join(results) or "(no strings found)"
        trimmed = self._limit_lines(formatted, limit)
        return f"== strings (built-in) ==\n{trimmed}"

    def _run_tool(
        self,
        label: str,
        argv: List[str],
        limit: int,
        fallback: str | None = None,
    ) -> str:
        if not shutil.which(Path(argv[0]).name):
            return fallback or f"{label}: tool not found"
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        output = result.stdout or result.stderr or ""
        trimmed = self._limit_lines(output.strip(), limit)
        return f"== {label} ==\n{trimmed}"

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _safe_int(self, value: str, default: int, minimum: int, maximum: int) -> int:
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, number))

    def _limit_lines(self, text: str, limit: int) -> str:
        if limit <= 0:
            return text
        lines = text.splitlines()
        if len(lines) <= limit:
            return text
        truncated = lines[:limit]
        truncated.append(f"... (truncated, showing first {limit} lines)")
        return "\n".join(truncated)


__all__ = ["BinaryInspector"]
