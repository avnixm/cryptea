"""Markdown rendering helpers for offline preview."""

from __future__ import annotations

import importlib
from functools import cached_property


class MarkdownRenderer:
    @cached_property
    def _converter(self):
        markdown2 = importlib.import_module("markdown2")
        return markdown2.Markdown(extras=["fenced-code-blocks", "tables", "strike", "task_list"])

    def render(self, text: str) -> str:
        return self._converter.convert(text)
