"""PCAP summarisation helpers for offline analysis."""

from __future__ import annotations

import json
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from ..base import ToolResult


class PcapViewerTool:
    """Lightweight PCAP analysis without external dependencies."""

    name = "PCAP Viewer"
    description = "Summarise packet captures (PCAP and PCAPNG), conversations, and top talkers."
    category = "Forensics"

    def run(self, file_path: str, packet_limit: str = "200", include_hex: str = "false") -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        limit = max(1, int(packet_limit or "200"))
        hex_preview = self._truthy(include_hex)
        summary = self._summarise_capture(path, limit=limit, include_hex=hex_preview)
        body = json.dumps(summary, indent=2)
        title = f"PCAP summary for {path.name}"
        return ToolResult(title=title, body=body, mime_type="application/json")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _summarise_capture(self, path: Path, *, limit: int, include_hex: bool) -> Dict[str, object]:
        with path.open("rb") as fh:
            global_header = fh.read(24)
            if len(global_header) < 24:
                raise ValueError("File is too small to be a PCAP capture")

            magic = global_header[:4]
            
            # Check if it's PCAPNG format
            if magic == b"\x0a\x0d\x0d\x0a":
                return self._summarise_pcapng(fh, path, limit=limit, include_hex=include_hex)
            
            # Classic PCAP format
            magic_map = {
                b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # little-endian, microsecond resolution
                b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # big-endian, microsecond resolution
                b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian, nanosecond resolution
                b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian, nanosecond resolution
            }
            if magic not in magic_map:
                raise ValueError("File does not appear to be a PCAP or PCAPNG capture")

            endian, ts_divisor = magic_map[magic]
            version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
                endian + "HHiIII", global_header[4:]
            )

            packets = 0
            truncated = False
            total_bytes = 0
            proto_counts: Counter[str] = Counter()
            talkers: Counter[str] = Counter()
            conversations: Dict[Tuple[str, str, str], Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
            samples: List[Dict[str, object]] = []
            start_ts: float | None = None
            end_ts: float | None = None

            while True:
                packet_header = fh.read(16)
                if len(packet_header) < 16:
                    break
                ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", packet_header)
                data = fh.read(incl_len)
                if len(data) < incl_len:
                    break

                packets += 1
                total_bytes += orig_len
                timestamp = ts_sec + (ts_frac / ts_divisor if ts_divisor else 0)
                start_ts = timestamp if start_ts is None else start_ts
                end_ts = timestamp

                frame = self._parse_frame(data, network)
                proto = str(frame.get("protocol", "Unknown"))
                proto_counts[proto] += 1

                src_ip = frame.get("src_ip")
                if isinstance(src_ip, str) and src_ip:
                    talkers[src_ip] += 1
                dst_ip = frame.get("dst_ip")
                if isinstance(dst_ip, str) and dst_ip:
                    talkers[dst_ip] += 1

                src_label = str(frame.get("src") or "unknown")
                dst_label = str(frame.get("dst") or "unknown")
                convo_key = (src_label, dst_label, proto)
                convo = conversations[convo_key]
                convo["packets"] += 1
                convo["bytes"] += orig_len

                if len(samples) < min(limit, 25):
                    samples.append(self._build_sample(packets, timestamp, frame, data, include_hex))

                if packets >= limit:
                    truncated = True
                    break

            linktype = self._linktype_name(network)
            period = self._format_period(start_ts, end_ts) if start_ts is not None and end_ts is not None else None

        convo_items = [
            {
                "src": src,
                "dst": dst,
                "protocol": proto,
                "packets": metrics["packets"],
                "bytes": metrics["bytes"],
            }
            for (src, dst, proto), metrics in conversations.items()
        ]
        convo_items.sort(key=lambda item: (item["packets"], item["bytes"]), reverse=True)

        summary: Dict[str, object] = {
            "file": str(path.resolve()),
            "packets_analyzed": packets,
            "bytes_observed": total_bytes,
            "packet_limit": limit,
            "truncated": truncated,
            "pcap_version": f"{version_major}.{version_minor}",
            "timezone_offset": thiszone,
            "sigfigs": sigfigs,
            "snaplen": snaplen,
            "linktype": linktype,
            "protocol_breakdown": proto_counts.most_common(),
            "top_talkers": talkers.most_common(10),
            "top_conversations": convo_items[:10],
            "samples": samples,
        }
        if period:
            summary["capture_period"] = period
        return summary

    def _summarise_pcapng(self, fh, path: Path, *, limit: int, include_hex: bool) -> Dict[str, object]:
        """Parse PCAPNG format files."""
        fh.seek(0)  # Reset to beginning
        
        packets = 0
        truncated = False
        total_bytes = 0
        proto_counts: Counter[str] = Counter()
        talkers: Counter[str] = Counter()
        conversations: Dict[Tuple[str, str, str], Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
        samples: List[Dict[str, object]] = []
        start_ts: float | None = None
        end_ts: float | None = None
        linktype = 1  # Default to Ethernet
        ts_resolution = 1_000_000  # Default microseconds
        endian = "<"  # Default little-endian
        
        # First, read the Section Header Block to determine byte order
        shb_header = fh.read(28)  # Minimum SHB size
        if len(shb_header) >= 12:
            byte_order_magic = struct.unpack("<I", shb_header[8:12])[0]
            if byte_order_magic == 0x1A2B3C4D:
                endian = "<"  # Little-endian
            elif byte_order_magic == 0x4D3C2B1A:
                endian = ">"  # Big-endian
            
            # Read rest of SHB if needed
            shb_length = struct.unpack(endian + "I", shb_header[4:8])[0]
            if shb_length > 28:
                fh.read(shb_length - 28)
        
        while True:
            # Read block header
            block_header = fh.read(8)
            if len(block_header) < 8:
                break
                
            block_type = struct.unpack(endian + "I", block_header[:4])[0]
            block_length = struct.unpack(endian + "I", block_header[4:8])[0]
            
            if block_length < 12:  # Minimum block size
                break
                
            # Read rest of block (excluding header and trailing length)
            block_body = fh.read(block_length - 12)
            trailing_length = fh.read(4)
            
            if len(block_body) < block_length - 12 or len(trailing_length) < 4:
                break
            
            # Enhanced Packet Block (EPB) - type 6
            if block_type == 0x00000006:
                if len(block_body) < 20:
                    continue
                    
                interface_id = struct.unpack(endian + "I", block_body[:4])[0]
                ts_high = struct.unpack(endian + "I", block_body[4:8])[0]
                ts_low = struct.unpack(endian + "I", block_body[8:12])[0]
                captured_len = struct.unpack(endian + "I", block_body[12:16])[0]
                orig_len = struct.unpack(endian + "I", block_body[16:20])[0]
                
                # Combine timestamp - PCAPNG stores 64-bit timestamp
                # The timestamp is typically in microseconds or nanoseconds since epoch
                ts_64bit = (ts_high << 32) | ts_low
                
                # Convert to Unix timestamp (seconds since epoch)
                timestamp = float(ts_64bit) / float(ts_resolution)
                
                # Extract packet data
                packet_data = block_body[20:20+captured_len]
                
                packets += 1
                total_bytes += orig_len
                start_ts = timestamp if start_ts is None else start_ts
                end_ts = timestamp
                
                frame = self._parse_frame(packet_data, linktype)
                proto = str(frame.get("protocol", "Unknown"))
                proto_counts[proto] += 1
                
                src_ip = frame.get("src_ip")
                if isinstance(src_ip, str) and src_ip:
                    talkers[src_ip] += 1
                dst_ip = frame.get("dst_ip")
                if isinstance(dst_ip, str) and dst_ip:
                    talkers[dst_ip] += 1
                
                src_label = str(frame.get("src") or "unknown")
                dst_label = str(frame.get("dst") or "unknown")
                convo_key = (src_label, dst_label, proto)
                convo = conversations[convo_key]
                convo["packets"] += 1
                convo["bytes"] += orig_len
                
                if len(samples) < min(limit, 25):
                    samples.append(self._build_sample(packets, timestamp, frame, packet_data, include_hex))
                
                if packets >= limit:
                    truncated = True
                    break
            
            # Interface Description Block (IDB) - type 1
            elif block_type == 0x00000001:
                if len(block_body) >= 8:
                    linktype = struct.unpack(endian + "H", block_body[:2])[0]
                    # Try to extract timestamp resolution from options (if present)
                    # This is simplified - full parsing would handle all options
                    if len(block_body) > 8:
                        # Check for if_tsresol option (code 9)
                        options_data = block_body[8:]
                        if len(options_data) >= 4:
                            opt_code = struct.unpack(endian + "H", options_data[:2])[0]
                            if opt_code == 9 and len(options_data) >= 5:
                                tsresol_byte = options_data[4]
                                if tsresol_byte & 0x80:
                                    # High bit set: power of 2
                                    ts_resolution = 2 ** (tsresol_byte & 0x7F)
                                else:
                                    # Power of 10
                                    ts_resolution = 10 ** tsresol_byte
        
        convo_items = [
            {
                "src": src,
                "dst": dst,
                "protocol": proto,
                "packets": metrics["packets"],
                "bytes": metrics["bytes"],
            }
            for (src, dst, proto), metrics in conversations.items()
        ]
        convo_items.sort(key=lambda item: (item["packets"], item["bytes"]), reverse=True)
        
        period = self._format_period(start_ts, end_ts) if start_ts is not None and end_ts is not None else None
        
        summary: Dict[str, object] = {
            "file": str(path.resolve()),
            "format": "PCAPNG",
            "packets_analyzed": packets,
            "bytes_observed": total_bytes,
            "packet_limit": limit,
            "truncated": truncated,
            "linktype": self._linktype_name(linktype),
            "protocol_breakdown": proto_counts.most_common(),
            "top_talkers": talkers.most_common(10),
            "top_conversations": convo_items[:10],
            "samples": samples,
        }
        if period:
            summary["capture_period"] = period
        return summary

    def _format_period(self, start_ts: float, end_ts: float) -> Dict[str, object]:
        try:
            start_dt = datetime.fromtimestamp(start_ts, tz=timezone.utc)
            end_dt = datetime.fromtimestamp(end_ts, tz=timezone.utc)
            duration = max(0.0, end_ts - start_ts)
            return {
                "start": start_dt.isoformat(),
                "end": end_dt.isoformat(),
                "duration_seconds": round(duration, 6),
            }
        except (ValueError, OSError, OverflowError):
            # If timestamps are invalid, return raw values
            return {
                "start": f"raw:{start_ts}",
                "end": f"raw:{end_ts}",
                "duration_seconds": max(0.0, end_ts - start_ts),
            }

    def _build_sample(
        self,
        index: int,
        timestamp: float,
        frame: Dict[str, object],
        data: bytes,
        include_hex: bool,
    ) -> Dict[str, object]:
        # Safely convert timestamp to datetime
        try:
            ts_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            # If timestamp is invalid, use a placeholder
            ts_iso = "invalid-timestamp"
        
        sample = {
            "index": index,
            "timestamp": ts_iso,
            "protocol": frame.get("protocol", "Unknown"),
            "src": frame.get("src"),
            "dst": frame.get("dst"),
            "length": len(data),
        }
        info = frame.get("info")
        if info:
            sample["info"] = info
        if include_hex and data:
            sample["hex_preview"] = data[:64].hex()
        return sample

    def _parse_frame(self, data: bytes, linktype: int) -> Dict[str, object]:
        if linktype != 1:  # currently we only parse Ethernet frames
            return {"protocol": self._linktype_name(linktype)}
        if len(data) < 14:
            return {"protocol": "Ethernet"}
        src_mac = self._format_mac(data[6:12])
        dst_mac = self._format_mac(data[0:6])
        eth_type = int.from_bytes(data[12:14], "big")
        payload = data[14:]

        if eth_type == 0x0800:
            return self._parse_ipv4(src_mac, dst_mac, payload)
        if eth_type == 0x0806:
            return self._parse_arp(src_mac, dst_mac, payload)
        if eth_type == 0x86DD:
            return {"protocol": "IPv6", "src": src_mac, "dst": dst_mac}
        return {"protocol": f"Ethertype 0x{eth_type:04x}", "src": src_mac, "dst": dst_mac}

    def _parse_ipv4(self, src_mac: str, dst_mac: str, payload: bytes) -> Dict[str, object]:
        if len(payload) < 20:
            return {"protocol": "IPv4", "src": src_mac, "dst": dst_mac}
        version_ihl = payload[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or len(payload) < ihl:
            return {"protocol": "IPv4", "src": src_mac, "dst": dst_mac}

        proto_num = payload[9]
        src_ip = self._format_ipv4(payload[12:16])
        dst_ip = self._format_ipv4(payload[16:20])
        total_length = int.from_bytes(payload[2:4], "big")

        protocol = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }.get(proto_num, f"IP proto {proto_num}")

        detail = {
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "length": total_length,
        }

        info_parts: List[str] = []
        data_offset = ihl
        if protocol in {"TCP", "UDP"} and len(payload) >= data_offset + 4:
            src_port = int.from_bytes(payload[data_offset : data_offset + 2], "big")
            dst_port = int.from_bytes(payload[data_offset + 2 : data_offset + 4], "big")
            detail["src_port"] = src_port
            detail["dst_port"] = dst_port
            detail["src"] = f"{src_ip}:{src_port}"
            detail["dst"] = f"{dst_ip}:{dst_port}"
            info_parts.append(f"{src_port} → {dst_port}")

            if protocol == "TCP" and len(payload) >= data_offset + 14:
                flags = payload[data_offset + 13]
                flag_labels = self._tcp_flags(flags)
                if flag_labels:
                    info_parts.append(",".join(flag_labels))
        else:
            detail["src"] = src_ip
            detail["dst"] = dst_ip

        if protocol == "ICMP" and len(payload) >= data_offset + 2:
            icmp_type = payload[data_offset]
            icmp_code = payload[data_offset + 1]
            info_parts.append(f"ICMP type {icmp_type}, code {icmp_code}")

        if info_parts:
            detail["info"] = " | ".join(info_parts)
        return detail

    def _parse_arp(self, src_mac: str, dst_mac: str, payload: bytes) -> Dict[str, object]:
        if len(payload) < 28:
            return {"protocol": "ARP", "src": src_mac, "dst": dst_mac}
        op = int.from_bytes(payload[6:8], "big")
        sender_ip = self._format_ipv4(payload[14:18])
        target_ip = self._format_ipv4(payload[24:28])
        operation = "request" if op == 1 else "reply" if op == 2 else f"op {op}"
        info = f"{operation}: {sender_ip} → {target_ip}"
        return {
            "protocol": "ARP",
            "src": src_mac,
            "dst": dst_mac,
            "info": info,
        }

    def _tcp_flags(self, flags: int) -> List[str]:
        labels = []
        mapping = [
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        ]
        for mask, label in mapping:
            if flags & mask:
                labels.append(label)
        return labels

    def _linktype_name(self, code: int) -> str:
        mapping = {
            0: "Null/loopback",
            1: "Ethernet",
            6: "IEEE 802.5",
            7: "Arcnet",
            101: "Raw IP",
            105: "IEEE 802.11",
            113: "Linux cooked capture",
            147: "User0",
        }
        return mapping.get(code, f"DLT {code}")

    def _format_mac(self, raw: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in raw)

    def _format_ipv4(self, raw: bytes) -> str:
        return ".".join(str(byte) for byte in raw)

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
