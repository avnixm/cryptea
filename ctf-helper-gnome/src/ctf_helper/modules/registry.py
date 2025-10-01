"""Module registry for offline tools."""

from __future__ import annotations

from typing import Dict, Iterable, List

from .base import OfflineTool
from .crypto.classic_ciphers import CaesarCipherTool, VigenereCipherTool
from .crypto.hash_tools import HashDigestTool
from .forensics.file_inspector import FileInspectorTool
from .misc.wordlist_generator import WordlistGenerator
from .reverse.bin_analysis import StringsExtractTool
from .web.offline_payloads import OfflinePayloadLibrary


class ModuleRegistry:
    """Simple in-memory registry of offline-capable tools."""

    def __init__(self) -> None:
        self._tools: List[OfflineTool] = [
            HashDigestTool(),
            CaesarCipherTool(),
            VigenereCipherTool(),
            FileInspectorTool(),
            StringsExtractTool(),
            OfflinePayloadLibrary(),
            WordlistGenerator(),
        ]

    def categories(self) -> List[str]:
        return sorted({tool.category for tool in self._tools})

    def tools(self) -> Iterable[OfflineTool]:
        return list(self._tools)

    def by_category(self) -> Dict[str, List[OfflineTool]]:
        grouped: Dict[str, List[OfflineTool]] = {}
        for tool in self._tools:
            grouped.setdefault(tool.category, []).append(tool)
        return grouped

    def find(self, name: str) -> OfflineTool:
        for tool in self._tools:
            if tool.name == name:
                return tool
        raise KeyError(name)
