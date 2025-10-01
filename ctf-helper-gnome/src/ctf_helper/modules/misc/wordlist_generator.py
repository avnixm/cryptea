"""Generate simple offline wordlists for brute-force attempts."""

from __future__ import annotations

import itertools
from typing import Iterable

from ..base import ToolResult


class WordlistGenerator:
    name = "Wordlist Generator"
    description = "Generate permutations of supplied tokens (offline)."
    category = "Misc"

    def run(self, tokens: str, min_length: str = "1", max_length: str = "3") -> ToolResult:
        parts = [token.strip() for token in tokens.split(',') if token.strip()]
        if not parts:
            raise ValueError("At least one token required")
        min_len = int(min_length)
        max_len = int(max_length)
        if min_len > max_len:
            min_len, max_len = max_len, min_len
        lines = []
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(parts, repeat=length):
                lines.append(''.join(combo))
        body = '\n'.join(lines)
        return ToolResult(title="Generated wordlist", body=body)
