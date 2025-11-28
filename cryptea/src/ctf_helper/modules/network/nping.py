"""nping wrapper (opt-in) for local packet crafting/testing."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Dict, List

from ..base import ToolResult
from .nmap import network_consent_enabled


def is_nping_available() -> bool:
    return shutil.which("nping") is not None


class NpingTool:
    name = "nping"
    description = "Send crafted packets locally (consent required)."
    category = "Network"

    def run(
        self,
        target: str,
        proto: str = "tcp",
        dport: str = "80",
        payload: str = "",
        rate: str = "1",
        tcp_flags: str = "",
        count: str = "1",
        delay: str = "",
        analyze_latency: str = "true",
        firewall_test: str = "false",
        icmp_type: str = "",
        icmp_code: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_nping_available():
            raise RuntimeError("nping not found in PATH")
        if not target.strip():
            raise ValueError("Target is required")
        
        args: List[str] = ["nping", "--rate", rate]
        
        # Count
        if count.strip():
            args.extend(["-c", count.strip()])
        else:
            args.extend(["-c", "1"])
        
        # Delay
        if delay.strip():
            args.extend(["--delay", delay.strip()])
        
        # Protocol selection
        proto_lower = proto.lower().strip()
        if proto_lower == "tcp":
            args.extend(["--tcp", "-p", dport])
            
            # TCP flags
            if tcp_flags.strip():
                flags = tcp_flags.strip().upper()
                if flags in ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]:
                    args.extend(["--flags", flags])
                elif "," in flags:
                    # Multiple flags
                    args.extend(["--flags", flags.replace(" ", "")])
        elif proto_lower == "udp":
            args.extend(["--udp", "-p", dport])
        elif proto_lower == "icmp":
            args.append("--icmp")
            if icmp_type.strip():
                args.extend(["--icmp-type", icmp_type.strip()])
            if icmp_code.strip():
                args.extend(["--icmp-code", icmp_code.strip()])
        elif proto_lower == "arp":
            args.append("--arp")
        else:
            args.append("--icmp")
        
        # Firewall testing - use SYN probe
        if self._is_truthy(firewall_test) and proto_lower == "tcp":
            if not tcp_flags.strip():
                args.extend(["--flags", "SYN"])
        
        # Payload
        if payload.strip():
            payload_hex = payload.encode().hex()
            args.extend(["--data", payload_hex])
        
        args.append(target)
        
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        
        output = proc.stdout or proc.stderr
        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        
        # Latency analysis
        if self._is_truthy(analyze_latency) and output:
            latency_analysis = self._analyze_latency(output)
            if latency_analysis:
                body_lines.append("Latency Analysis:")
                body_lines.append(json.dumps(latency_analysis, indent=2))
                body_lines.append("")
        
        # Protocol behavior analysis
        if output:
            behavior = self._analyze_protocol_behavior(output, proto_lower)
            if behavior:
                body_lines.append("Protocol Behavior:")
                body_lines.append(json.dumps(behavior, indent=2))
                body_lines.append("")
        
        body_lines.append("Output:")
        body_lines.append(output)
        
        return ToolResult(title="nping", body="\n".join(body_lines))
    
    def _analyze_latency(self, output: str) -> Dict[str, object]:
        """Parse and analyze latency measurements from nping output."""
        analysis: Dict[str, object] = {
            "latencies": [],
            "statistics": {
                "min_rtt": None,
                "max_rtt": None,
                "avg_rtt": None,
                "packet_loss": None,
            },
        }
        
        # Parse RTT from output
        # Format: "Max rtt: 123.456ms | Min rtt: 12.345ms | Avg rtt: 67.890ms"
        rtt_pattern = r"(?:Max|Min|Avg)\s+rtt:\s+(\d+\.?\d*)\s*ms"
        rtts = re.findall(rtt_pattern, output, re.IGNORECASE)
        
        if rtts:
            rtt_values = [float(rtt) for rtt in rtts]
            analysis["statistics"]["min_rtt"] = min(rtt_values) if rtt_values else None
            analysis["statistics"]["max_rtt"] = max(rtt_values) if rtt_values else None
            analysis["statistics"]["avg_rtt"] = sum(rtt_values) / len(rtt_values) if rtt_values else None
        
        # Parse packet loss
        loss_pattern = r"(\d+(?:\.\d+)?)%\s+packet\s+loss"
        loss_match = re.search(loss_pattern, output, re.IGNORECASE)
        if loss_match:
            analysis["statistics"]["packet_loss"] = float(loss_match.group(1))
        
        # Parse sent/received
        sent_pattern = r"(\d+)\s+packets\s+sent"
        recv_pattern = r"(\d+)\s+packets\s+received"
        sent_match = re.search(sent_pattern, output, re.IGNORECASE)
        recv_match = re.search(recv_pattern, output, re.IGNORECASE)
        
        if sent_match and recv_match:
            sent = int(sent_match.group(1))
            recv = int(recv_match.group(1))
            analysis["statistics"]["packets_sent"] = sent
            analysis["statistics"]["packets_received"] = recv
            if sent > 0:
                loss_pct = ((sent - recv) / sent) * 100
                analysis["statistics"]["packet_loss"] = loss_pct
        
        return analysis
    
    def _analyze_protocol_behavior(self, output: str, proto: str) -> Dict[str, object]:
        """Analyze protocol behavior and port state detection."""
        behavior: Dict[str, object] = {
            "port_state": "unknown",
            "responses": [],
        }
        
        # Detect port states based on responses
        if "open" in output.lower():
            behavior["port_state"] = "open"
        elif "filtered" in output.lower() or "no response" in output.lower():
            behavior["port_state"] = "filtered"
        elif "closed" in output.lower():
            behavior["port_state"] = "closed"
        
        # Parse response patterns
        if proto == "tcp":
            if "SYN-ACK" in output or "syn-ack" in output.lower():
                behavior["responses"].append("SYN-ACK received - port likely open")
            elif "RST" in output or "rst" in output.lower():
                behavior["responses"].append("RST received - port likely closed")
            elif "no response" in output.lower():
                behavior["responses"].append("No response - port may be filtered")
        elif proto == "udp":
            if "ICMP" in output:
                behavior["responses"].append("ICMP response received")
            elif "no response" in output.lower():
                behavior["responses"].append("No response - port may be open/filtered")
        
        return behavior
    
    def _is_truthy(self, value: str) -> bool:
        return value.lower() in {"1", "true", "yes", "y", "on"}



