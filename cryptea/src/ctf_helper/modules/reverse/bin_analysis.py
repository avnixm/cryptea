"""Offline binary triage helpers."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List

from ..base import ToolResult


class StringsExtractTool:
    name = "Extract Strings"
    description = "Run the local `strings` utility (if available) to inspect ASCII data."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        min_length: str = "4",
        unicode: str = "false",
        unique: str = "true",
        search: str = "",
        limit: str = "0",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        min_len = max(1, int(min_length or "1"))
        include_unicode = self._truthy(unicode)
        unique_only = self._truthy(unique)
        limit_count = max(0, int(limit or "0"))
        term = search.lower().strip()

        strings = self._extract_with_system(path, min_len, include_unicode)
        if strings is None:
            data = path.read_bytes()
            strings = list(self._extract_fallback(data, min_len, include_unicode))

        if unique_only:
            seen = set()
            deduped: List[str] = []
            for item in strings:
                lower = item.lower()
                if lower in seen:
                    continue
                seen.add(lower)
                deduped.append(item)
            strings = deduped

        if term:
            strings = [item for item in strings if term in item.lower()]

        strings.sort(key=str.lower)
        if limit_count > 0:
            strings = strings[:limit_count]

        body = "\n".join(strings)
        title = f"{len(strings)} strings from {path.name}"
        return ToolResult(title=title, body=body)

    def _extract_with_system(self, path: Path, min_len: int, include_unicode: bool) -> List[str] | None:
        binary = shutil.which("strings")
        if not binary:
            return None
        args = [binary, f"-n{min_len}", str(path)]
        result = subprocess.run(
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = result.stdout or result.stderr
        if not include_unicode:
            return output.splitlines()
        # include UTF-16LE strings via additional invocation if available
        unicode_args = [binary, "-el", f"-n{min_len}", str(path)]
        ures = subprocess.run(
            unicode_args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        combined = output.splitlines() + (ures.stdout or ures.stderr).splitlines()
        return combined

    def _extract_fallback(self, data: bytes, min_len: int, include_unicode: bool) -> Iterable[str]:
        ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        for match in ascii_pattern.finditer(data):
            yield match.group().decode("ascii", errors="ignore")

        if include_unicode:
            pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
            for match in pattern.finditer(data):
                yield match.group().decode("utf-16le", errors="ignore")

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
