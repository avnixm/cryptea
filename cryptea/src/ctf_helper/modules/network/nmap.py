"""Local nmap wrapper (opt-in) for offline scanning.

This module only runs the locally installed `nmap` binary. It respects an
opt-in consent flag stored in the user's config directory.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, NamedTuple, Sequence

from ..base import ToolResult
from ...data_paths import user_config_dir


CONSENT_FILE = user_config_dir() / "network_consent.json"


def network_consent_enabled() -> bool:
    try:
        if not CONSENT_FILE.exists():
            return False
        data = json.loads(CONSENT_FILE.read_text())
        return bool(data.get("enabled", False))
    except Exception:
        return False


def set_network_consent(enabled: bool) -> None:
    payload = {"enabled": bool(enabled)}
    CONSENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONSENT_FILE.write_text(json.dumps(payload))


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


class NmapProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[NmapProfile] = (
    NmapProfile(
        "quick",
        "Quick",
        "Fast scan of top 100 TCP ports with aggressive timing",
        ("-T4", "-F"),
    ),
    NmapProfile(
        "default",
        "Default",
        "Balanced scan using nmap defaults",
        (),
    ),
    NmapProfile(
        "full",
        "Full TCP",
        "Scan all 65535 TCP ports with faster timing",
        ("-T4", "-p-"),
    ),
    NmapProfile(
        "aggressive",
        "Aggressive",
        "Includes OS detection, scripts, and traceroute (-A)",
        ("-T4", "-A"),
    ),
)

PROFILE_ARGS: Dict[str, Sequence[str]] = {profile.profile_id: profile.args for profile in PROFILE_CHOICES}


@dataclass
class NmapRow:
    host: str
    port: str
    proto: str
    service: str
    banner: str
    script: str


def _parse_nmap_xml(xml_text: str) -> List[NmapRow]:
    rows: List[NmapRow] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return rows
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "?"
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            portid = p.get("portid", "?")
            proto = p.get("protocol", "?")
            state = p.find("state")
            if state is not None and state.get("state") != "open":
                continue
            service_el = p.find("service")
            service = service_el.get("name") if service_el is not None else "?"
            banner_parts: List[str] = []
            for k in ("product", "version", "extrainfo"):
                v = service_el.get(k) if service_el is not None else None
                if v:
                    banner_parts.append(v)
            banner = " ".join(banner_parts)
            script_out: List[str] = []
            for sc in p.findall("script"):
                out = sc.get("output")
                if out:
                    script_out.append(out)
            # Ensure addr and service are str, not None
            rows.append(NmapRow(
                addr if addr is not None else "?",
                portid if portid is not None else "?",
                proto if proto is not None else "?",
                service if service is not None else "?",
                banner,
                " | ".join(script_out)
            ))
    return rows


class NmapTool:
    name = "Nmap"
    description = "Run local nmap scans (opt-in)."
    category = "Network"

    def run(
        self,
        target: str,
        profile: str = "default",
        extra: str = "",
        os_detect: str = "0",
        version_detect: str = "1",
        default_scripts: str = "0",
        skip_ping: str = "0",
        ports: str = "",
        scan_type: str = "default",
        nse_scripts: str = "",
        output_format: str = "text",
        analyze_results: str = "true",
        traceroute: str = "false",
        port_range: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_nmap_available():
            raise RuntimeError("nmap not found in PATH. Install nmap locally.")
        if not target.strip():
            raise ValueError("Target is required")
        
        # Determine output format
        output_format_lower = output_format.lower().strip()
        if output_format_lower == "json":
            args: List[str] = ["nmap", "-oJ", "-"]
        elif output_format_lower == "grepable":
            args = ["nmap", "-oG", "-"]
        else:
            args = ["nmap", "-oX", "-"]  # XML for parsing
        
        args.extend(PROFILE_ARGS.get(profile, ()))
        
        # Scan type selection
        scan_type_lower = scan_type.lower().strip()
        if scan_type_lower == "syn":
            args.append("-sS")
        elif scan_type_lower == "udp":
            args.append("-sU")
        elif scan_type_lower == "ack":
            args.append("-sA")
        elif scan_type_lower == "fin":
            args.append("-sF")
        elif scan_type_lower == "null":
            args.append("-sN")
        elif scan_type_lower == "xmas":
            args.append("-sX")
        
        if _is_truthy(version_detect):
            args.append("-sV")
        if _is_truthy(os_detect):
            args.append("-O")
        if _is_truthy(default_scripts):
            args.append("-sC")
        
        # NSE script selection
        if nse_scripts.strip():
            scripts = nse_scripts.strip()
            if scripts.startswith("default") or scripts == "default":
                args.append("-sC")
            else:
                args.extend(["--script", scripts])
        
        if _is_truthy(skip_ping):
            args.append("-Pn")
        
        # Traceroute
        if _is_truthy(traceroute):
            args.append("--traceroute")
        
        # Port range utilities
        if port_range.strip():
            port_ranges = {
                "top-100": "--top-ports 100",
                "top-1000": "--top-ports 1000",
                "web": "80,443,8080,8443,8000,8888",
                "database": "3306,5432,1433,27017,6379",
            }
            if port_range.strip() in port_ranges:
                range_value = port_ranges[port_range.strip()]
                if range_value.startswith("--"):
                    args.extend(range_value.split())
                else:
                    args.extend(["-p", range_value])
            else:
                args.extend(["-p", port_range.strip()])
        elif ports.strip():
            args.extend(["-p", ports.strip()])
        if extra.strip():
            try:
                args.extend(shlex.split(extra, comments=False, posix=True))
            except ValueError as exc:
                raise ValueError(f"Invalid extra arguments: {exc}") from exc
        args.append(target)

        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(proc.stderr.strip() or "nmap failed")
        
        # Parse results based on format
        if output_format_lower == "json":
            body = proc.stdout
            mime_type = "application/json"
        elif output_format_lower == "grepable":
            body = proc.stdout
            mime_type = "text/plain"
        else:
            # XML format - parse and analyze
            rows = _parse_nmap_xml(proc.stdout)
            body_lines: List[str] = []
            body_lines.append(f"Command: {' '.join(args)}")
            body_lines.append("")
            
            # Result analysis
            if _is_truthy(analyze_results):
                analysis = self._analyze_results(proc.stdout, rows)
                if analysis:
                    body_lines.append("Scan Analysis:")
                    body_lines.append(json.dumps(analysis, indent=2))
                    body_lines.append("")
            
            body_lines.append(_format_rows(rows))
            if proc.stderr.strip():
                body_lines.append("")
                body_lines.append("Warnings/Notes:")
                body_lines.append(proc.stderr.strip())
            body = "\n".join(body_lines).strip()
            mime_type = "application/json" if _is_truthy(analyze_results) else "text/plain"
        
        return ToolResult(
            title=f"nmap results for {target}",
            body=body,
            mime_type=mime_type,
        )
    
    def _analyze_results(self, xml_output: str, rows: List[NmapRow]) -> Dict[str, object]:
        """Analyze nmap scan results and provide summary."""
        # Count by protocol
        protocols: Dict[str, int] = {}
        services_count: Dict[str, int] = {}
        
        services_list: List[Dict[str, str]] = []
        vulnerabilities_list: List[Dict[str, str]] = []
        common_ports_list: List[str] = []
        
        for row in rows:
            proto = row.proto.lower()
            protocols[proto] = protocols.get(proto, 0) + 1
            if row.service and row.service != "?":
                services_count[row.service.lower()] = services_count.get(row.service.lower(), 0) + 1
        
        # Extract services
        seen_services: set[str] = set()
        for row in rows:
            if row.service and row.service != "?":
                service_key = f"{row.service}:{row.port}"
                if service_key not in seen_services:
                    seen_services.add(service_key)
                    services_list.append({
                        "port": row.port,
                        "protocol": row.proto,
                        "service": row.service,
                        "banner": row.banner,
                    })
        
        # Parse XML for vulnerabilities and OS info
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                # OS detection
                os_matches = host.find("os")
                if os_matches is not None:
                    for osmatch in os_matches.findall("osmatch"):
                        name = osmatch.get("name", "")
                        if name:
                            common_ports_list.append(f"OS: {name}")
                
                # Vulnerability scripts
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        for script in port.findall("script"):
                            script_id = script.get("id", "")
                            if any(keyword in script_id.lower() for keyword in ["vuln", "exploit", "cve"]):
                                output = script.get("output", "")
                                if output:
                                    vulnerabilities_list.append({
                                        "port": port.get("portid", "?"),
                                        "script": script_id,
                                        "output": output[:200],  # Limit length
                                    })
        except ET.ParseError:
            pass
        
        # Parse host count from XML
        total_hosts = 1
        try:
            root = ET.fromstring(xml_output)
            hosts = root.findall("host")
            total_hosts = len(hosts)
        except ET.ParseError:
            pass
        
        analysis: Dict[str, object] = {
            "summary": {
                "total_hosts": total_hosts,
                "total_ports": len(rows),
                "ports_by_protocol": protocols,
                "ports_by_service": services_count,
            },
            "services": services_list,
            "vulnerabilities": vulnerabilities_list,
            "common_ports": common_ports_list,
        }
        
        return analysis


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}


def _format_rows(rows: Sequence[NmapRow]) -> str:
    if not rows:
        return "No open ports reported."
    headers = ("Host", "Port", "Proto", "Service", "Banner", "Scripts")
    table: List[Sequence[str]] = [
        (r.host, r.port, r.proto, r.service, _clip(r.banner), _clip(r.script))
        for r in rows
    ]
    widths = [len(h) for h in headers]
    for row in table:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))
    divider = "  ".join("-" * w for w in widths)
    header_line = "  ".join(_pad(headers[idx], widths[idx]) for idx in range(len(headers)))
    lines = [header_line, divider]
    for row in table:
        lines.append("  ".join(_pad(cell, widths[idx]) for idx, cell in enumerate(row)))
    return "\n".join(lines)


def _pad(text: str, width: int) -> str:
    return text.ljust(width)


def _clip(text: str, max_len: int = 48) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"
