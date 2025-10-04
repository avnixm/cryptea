from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ctf_helper.modules.forensics.disk_image_tools import DiskImageToolkit
from ctf_helper.modules.forensics.memory_analyzer import MemoryAnalyzerTool
from ctf_helper.modules.forensics.pcap_viewer import PcapViewerTool
from ctf_helper.modules.forensics.timeline_builder import TimelineBuilderTool


class ForensicsToolsTest(unittest.TestCase):
    def test_pcap_viewer_basic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            capture_path = tmp_path / "sample.pcap"
            ethernet_payload = self._build_tcp_packet()
            with capture_path.open("wb") as fh:
                fh.write(b"\xd4\xc3\xb2\xa1")
                fh.write(struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1))
                fh.write(struct.pack("<IIII", 0, 0, len(ethernet_payload), len(ethernet_payload)))
                fh.write(ethernet_payload)

            tool = PcapViewerTool()
            result = tool.run(str(capture_path), packet_limit="10", include_hex="false")
            payload = json.loads(result.body)
            self.assertEqual(payload["packets_analyzed"], 1)
            protocols = dict(payload["protocol_breakdown"])
            self.assertIn("TCP", protocols)
            self.assertTrue(payload["samples"])

    def test_memory_analyzer_detects_keywords(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            dump_path = tmp_path / "dump.bin"
            data = b"A" * 64 + b"flag{demo}" + b"\x00" * 16 + b"MZ" + os.urandom(32)
            dump_path.write_bytes(data)

            tool = MemoryAnalyzerTool()
            result = tool.run(str(dump_path), strings_limit="200", keywords="flag", include_hashes="false")
            payload = json.loads(result.body)
            analysis = payload["analysis"]
            self.assertGreaterEqual(analysis["strings_total"], 1)
            keyword_hits = analysis.get("keyword_hits", {})
            self.assertTrue(any("flag" in hit["value"].lower() for hit in keyword_hits.get("flag", [])))

    def test_disk_image_parses_mbr(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            image_path = tmp_path / "disk.img"
            sector = 512
            image = bytearray(sector * 4096)
            entry_offset = 446
            image[entry_offset] = 0x80
            image[entry_offset + 4] = 0x83
            image[entry_offset + 8 : entry_offset + 12] = (2048).to_bytes(4, "little")
            image[entry_offset + 12 : entry_offset + 16] = (4096).to_bytes(4, "little")
            image[510:512] = b"\x55\xaa"
            image_path.write_bytes(image)

            tool = DiskImageToolkit()
            result = tool.run(str(image_path), sector_size="512", max_partitions="4", include_hashes="false")
            payload = json.loads(result.body)
            self.assertEqual(payload["partition_scheme"], "MBR")
            partitions = payload["partitions"]
            self.assertEqual(partitions[0]["type_id"], "0x83")
            self.assertEqual(partitions[0]["first_lba"], 2048)

    def test_timeline_builder_outputs_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "sub").mkdir()
            (base / "root.txt").write_text("hello", encoding="utf-8")
            (base / "sub" / "nested.txt").write_text("world", encoding="utf-8")

            tool = TimelineBuilderTool()
            result = tool.run(
                str(base),
                max_entries="10",
                include_directories="false",
                output_format="csv",
                include_hashes="false",
            )
            self.assertEqual(result.mime_type, "text/csv")
            self.assertIn("root.txt", result.body)
            self.assertIn("nested.txt", result.body)

    def _build_tcp_packet(self) -> bytes:
        dst_mac = bytes.fromhex("aabbccddeeff")
        src_mac = bytes.fromhex("112233445566")
        eth_type = b"\x08\x00"
        ip_header = bytes.fromhex(
            "450000280000000040060000c0a80001c0a80002"
        )
        tcp_header = bytes.fromhex(
            "04d2005000000001000000005002200000000000"
        )
        return dst_mac + src_mac + eth_type + ip_header + tcp_header


if __name__ == "__main__":
    unittest.main()
