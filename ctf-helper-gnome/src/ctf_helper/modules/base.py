"""Base classes for offline CTF helper modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class ToolResult:
    title: str
    body: str
    mime_type: str = "text/plain"


class OfflineTool(Protocol):
    """Common interface for offline helper tools."""

    @property
    def name(self) -> str:
        ...

    @property
    def description(self) -> str:
        ...

    @property
    def category(self) -> str:
        ...

    def run(self, *args, **kwargs) -> ToolResult:
        ...
