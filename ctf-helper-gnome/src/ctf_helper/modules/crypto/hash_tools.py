"""Offline hashing utilities."""

from __future__ import annotations

import hashlib
from typing import Iterable

from ..base import ToolResult


def available_algorithms() -> Iterable[str]:
    yield from sorted(hashlib.algorithms_guaranteed)


class HashDigestTool:
    name = "Hash Digest"
    description = "Compute message digests using Python's hashlib (offline)."
    category = "Crypto"

    def run(self, text: str, algorithm: str = "sha256") -> ToolResult:
        algo = algorithm.lower()
        if algo not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        digest = hashlib.new(algo)
        digest.update(text.encode("utf-8"))
        return ToolResult(
            title=f"{algorithm.upper()} digest",
            body=digest.hexdigest(),
        )
