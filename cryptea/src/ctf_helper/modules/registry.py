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
from .crypto.rsactftool import RsaCtfToolTool
from .crypto.featherduster import FeatherDusterTool
from .crypto.cyberchef import CyberChefTool
from .forensics.disk_image_tools import DiskImageToolkit
from .forensics.file_inspector import FileInspectorTool
from .forensics.memory_analyzer import MemoryAnalyzerTool
from .forensics.pcap_viewer import PcapViewerTool
from .forensics.timeline_builder import TimelineBuilderTool
from .forensics.binwalk import BinwalkTool
from .forensics.foremost import ForemostTool
from .forensics.bulk_extractor import BulkExtractorTool
from .forensics.volatility import VolatilityTool
from .forensics.sleuthkit import SleuthkitTool
from .forensics.scalpel import ScalpelTool
from .media import (
    AudioAnalyzerTool,
    ExifMetadataTool,
    ImageStegoTool,
    QRScannerTool,
    VideoFrameExporterTool,
)
from .misc.wordlist_generator import WordlistGenerator
from .misc.hydra import HydraTool
from .misc.medusa import MedusaTool
from .misc.crackmapexec import CrackMapExecTool
from .reverse.bin_analysis import StringsExtractTool
from .reverse.binary_diff import BinaryDiffTool
from .reverse.binary_inspector import BinaryInspector
from .reverse.disassembler import DisassemblerLauncher
from .reverse.exe_decompiler import ExeDecompiler
from .reverse.gdb_helper import GDBHelper
from .reverse.rizin_console import RizinConsole
from .reverse.rop_gadget import ROPGadgetTool
from .reverse.pwntools_helper import PwntoolsHelperTool
from .reverse.angr_helper import AngrHelperTool
from .reverse.checksec import ChecksecTool
from .reverse.syscall_tracer import SyscallTracerTool
from .reverse.objdump_viewer import ObjdumpViewerTool
from .web.discovery import DirDiscoveryTool
from .web.file_upload import FileUploadTester
from .web.jwt_tool import JWTTool
from .web.sqli_tester import SQLInjectionTester
from .web.sqlmap import SqlmapTool
from .web.xss_tester import XSSTester
from .web.wfuzz import WfuzzTool
from .web.commix import CommixTool
from .web.arjun import ArjunTool
from .web.sublist3r import Sublist3rTool
from .network.nmap import NmapTool, is_nmap_available, network_consent_enabled
from .network.gobuster import GobusterTool
from .network.ffuf import FfufTool
from .network.nikto import NiktoTool
from .network.masscan import MasscanTool
from .network.enum4linux import Enum4linuxTool


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
            RsaCtfToolTool(),
            FeatherDusterTool(),
            CyberChefTool(),
            
            # Forensics
            FileInspectorTool(),
            PcapViewerTool(),
            MemoryAnalyzerTool(),
            DiskImageToolkit(),
            TimelineBuilderTool(),
            BinwalkTool(),
            ForemostTool(),
            BulkExtractorTool(),
            VolatilityTool(),
            SleuthkitTool(),
            ScalpelTool(),
            
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
            PwntoolsHelperTool(),
            AngrHelperTool(),
            ChecksecTool(),
            SyscallTracerTool(),
            ObjdumpViewerTool(),
            
            # Miscellaneous
            WordlistGenerator(),
            HydraTool(),
            MedusaTool(),
            CrackMapExecTool(),
            
            # Web
            DirDiscoveryTool(),
            SQLInjectionTester(),
            SqlmapTool(),
            XSSTester(),
            JWTTool(),
            FileUploadTester(),
            WfuzzTool(),
            CommixTool(),
            ArjunTool(),
            Sublist3rTool(),
        ]
        # Network tools (require consent)
        if network_consent_enabled():
            if is_nmap_available():
                self._tools.append(NmapTool())
            # Add other network tools
            from .network.gobuster import is_gobuster_available
            from .network.ffuf import is_ffuf_available
            from .network.nikto import is_nikto_available
            from .network.masscan import is_masscan_available
            from .network.enum4linux import is_enum4linux_available
            
            if is_gobuster_available():
                self._tools.append(GobusterTool())
            if is_ffuf_available():
                self._tools.append(FfufTool())
            if is_nikto_available():
                self._tools.append(NiktoTool())
            if is_masscan_available():
                self._tools.append(MasscanTool())
            if is_enum4linux_available():
                self._tools.append(Enum4linuxTool())

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
