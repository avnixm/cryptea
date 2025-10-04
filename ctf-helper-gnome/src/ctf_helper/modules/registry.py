"""Module registry for offline tools."""

from __future__ import annotations

from typing import Dict, Iterable, List

from .base import OfflineTool
from .crypto.classic_ciphers import CaesarCipherTool, VigenereCipherTool
from .crypto.decoder import DecoderWorkbenchTool
from .crypto.morse_decoder import MorseDecoderTool
from .crypto.hash_suite import HashSuite
from .crypto.rsa_toolkit import RSAToolkit
from .crypto.xor_analyzer import XORKeystreamAnalyzer
from .forensics.disk_image_tools import DiskImageToolkit
from .forensics.file_inspector import FileInspectorTool
from .forensics.memory_analyzer import MemoryAnalyzerTool
from .forensics.pcap_viewer import PcapViewerTool
from .forensics.timeline_builder import TimelineBuilderTool
from .media import (
    AudioAnalyzerTool,
    ExifMetadataTool,
    ImageStegoTool,
    QRScannerTool,
    VideoFrameExporterTool,
)
from .misc.wordlist_generator import WordlistGenerator
from .reverse.bin_analysis import StringsExtractTool
from .reverse.binary_diff import BinaryDiffTool
from .reverse.binary_inspector import BinaryInspector
from .reverse.disassembler import DisassemblerLauncher
from .reverse.exe_decompiler import ExeDecompiler
from .reverse.gdb_helper import GDBHelper
from .reverse.rizin_console import RizinConsole
from .reverse.rop_gadget import ROPGadgetTool
from .web.discovery import DirDiscoveryTool
from .web.file_upload import FileUploadTester
from .web.jwt_tool import JWTTool
from .web.sqli_tester import SQLInjectionTester
from .web.sqlmap import SqlmapTool
from .web.xss_tester import XSSTester
from .network.nmap import NmapTool, is_nmap_available, network_consent_enabled


class ModuleRegistry:
    """Simple in-memory registry of offline-capable tools."""

    def __init__(self) -> None:
        self._tools: List[OfflineTool] = [
            # Crypto & Encoding - Hash Suite (consolidated all hash tools)
            HashSuite(),                    # Unified: Identify, Verify, Crack, Format, Generate, Benchmark, Queue
            
            # Crypto & Encoding - Other tools
            DecoderWorkbenchTool(),
            MorseDecoderTool(),
            XORKeystreamAnalyzer(),
            RSAToolkit(),
            CaesarCipherTool(),
            VigenereCipherTool(),
            
            # Forensics
            FileInspectorTool(),
            PcapViewerTool(),
            MemoryAnalyzerTool(),
            DiskImageToolkit(),
            TimelineBuilderTool(),
            
            # Media
            ImageStegoTool(),
            ExifMetadataTool(),
            AudioAnalyzerTool(),
            VideoFrameExporterTool(),
            QRScannerTool(),
            
                        # Reverse Engineering
            StringsExtractTool(),
            BinaryDiffTool(),
            BinaryInspector(),
            DisassemblerLauncher(),
            ExeDecompiler(),
            GDBHelper(),
            RizinConsole(),
            ROPGadgetTool(),
            
            # Miscellaneous
            WordlistGenerator(),
            
            # Web
            DirDiscoveryTool(),
            SQLInjectionTester(),
            SqlmapTool(),
            XSSTester(),
            JWTTool(),
            FileUploadTester(),
        ]
        if network_consent_enabled() and is_nmap_available():
            self._tools.append(NmapTool())

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
