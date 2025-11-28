"""Offline binary triage helpers."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List

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
        categorize: str = "false",
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
        
        # Categorize strings if requested
        categorized: Dict[str, List[str]] = {}
        if self._truthy(categorize):
            categorized = self._categorize_strings(strings)
        
        if limit_count > 0:
            strings = strings[:limit_count]

        body = "\n".join(strings)
        
        # Add categorization summary
        if categorized:
            body += "\n\n=== String Categories ===\n"
            for category, items in categorized.items():
                body += f"\n{category} ({len(items)}):\n"
                body += "\n".join(items[:20])  # Show first 20 per category
                if len(items) > 20:
                    body += f"\n... (showing first 20 of {len(items)})\n"
        
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

    def _categorize_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        """Categorize strings into useful groups."""
        categories: Dict[str, List[str]] = {
            "URLs": [],
            "File Paths": [],
            "API Keys/Tokens": [],
            "Emails": [],
            "IP Addresses": [],
            "UUIDs": [],
            "Base64-like": [],
            "Hex Strings": [],
            "Error Messages": [],
            "Function Names": [],
        }
        
        url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
        path_pattern = re.compile(r'(/[^\s<>"\'{}|\\^`\[\]]+|[C-Z]:\\[^\s<>"\'{}|\\^`\[\]]+)', re.IGNORECASE)
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
        hex_pattern = re.compile(r'^[0-9a-fA-F]{16,}$')
        error_pattern = re.compile(r'\b(error|fail|exception|warning|invalid|not found|access denied)\b', re.IGNORECASE)
        func_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*\(.*\)$')
        api_key_pattern = re.compile(r'\b(api[_-]?key|token|secret|password|auth[_-]?token)\s*[=:]\s*[a-zA-Z0-9+/=_-]{16,}', re.IGNORECASE)
        
        for string in strings:
            string_lower = string.lower()
            
            if url_pattern.search(string):
                categories["URLs"].append(string)
            elif path_pattern.search(string):
                categories["File Paths"].append(string)
            elif email_pattern.search(string):
                categories["Emails"].append(string)
            elif ip_pattern.search(string):
                categories["IP Addresses"].append(string)
            elif uuid_pattern.search(string):
                categories["UUIDs"].append(string)
            elif base64_pattern.match(string):
                categories["Base64-like"].append(string)
            elif hex_pattern.match(string):
                categories["Hex Strings"].append(string)
            elif error_pattern.search(string):
                categories["Error Messages"].append(string)
            elif func_pattern.match(string):
                categories["Function Names"].append(string)
            
            if api_key_pattern.search(string):
                categories["API Keys/Tokens"].append(string)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
