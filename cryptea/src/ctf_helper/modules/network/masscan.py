"""Masscan wrapper for ultra-fast port scanning (opt-in)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Dict, List, NamedTuple, Sequence

from ..base import ToolResult
from ...data_paths import user_config_dir, user_data_dir


CONSENT_FILE = user_config_dir() / "network_consent.json"


def network_consent_enabled() -> bool:
    try:
        if not CONSENT_FILE.exists():
            return False
        data = json.loads(CONSENT_FILE.read_text())
        return bool(data.get("enabled", False))
    except Exception:
        return False


def is_masscan_available() -> bool:
    return shutil.which("masscan") is not None


class MasscanProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[MasscanProfile] = (
    MasscanProfile(
        "quick",
        "Quick",
        "Fast scan of top 100 ports",
        ("--top-ports", "100", "--rate", "1000"),
    ),
    MasscanProfile(
        "default",
        "Default",
        "Balanced scan of common ports",
        ("-p", "1-1000,3000,3306,5432,8000,8080,8443", "--rate", "500"),
    ),
    MasscanProfile(
        "full",
        "Full",
        "Scan all TCP ports",
        ("-p", "0-65535", "--rate", "1000"),
    ),
    MasscanProfile(
        "stealth",
        "Stealth",
        "Slow scan to avoid detection",
        ("-p", "1-1000", "--rate", "100"),
    ),
)


class MasscanTool:
    name = "Masscan"
    description = "Ultra-fast TCP port scanner (opt-in, requires root)."
    category = "Network"

    def run(
        self,
        target: str,
        profile: str = "default",
        ports: str = "",
        rate: str = "500",
        output_format: str = "text",
        banner_grab: str = "false",
        analyze_results: str = "true",
        port_range: str = "",
        exclude: str = "",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_masscan_available():
            raise RuntimeError("masscan not found in PATH. Install masscan locally.")
        if not target.strip():
            raise ValueError("Target is required")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[1]  # default

        args: List[str] = ["masscan", target]

        # Add profile args
        args.extend(selected_profile.args)

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
            args = [a for i, a in enumerate(args) if not (a == "-p" or (i > 0 and args[i-1] == "-p"))]
            args = [a for i, a in enumerate(args) if not (a == "--top-ports" or (i > 0 and args[i-1] == "--top-ports"))]
            args.extend(["-p", ports.strip()])

        # Override rate if specified
        if rate.strip():
            args = [a for i, a in enumerate(args) if not (a == "--rate" or (i > 0 and args[i-1] == "--rate"))]
            args.extend(["--rate", rate.strip()])
        
        # Banner grabbing
        if self._is_truthy(banner_grab):
            args.append("--banners")
        
        # Output format
        output_format_lower = output_format.lower().strip()
        if output_format_lower == "json":
            output_file = user_data_dir() / "masscan_reports" / f"masscan_{target.replace('/', '_').replace(' ', '_')}.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            args.extend(["-oJ", str(output_file)])
        elif output_format_lower == "xml":
            output_file = user_data_dir() / "masscan_reports" / f"masscan_{target.replace('/', '_').replace(' ', '_')}.xml"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            args.extend(["-oX", str(output_file)])
        elif output_format_lower == "binary":
            output_file = user_data_dir() / "masscan_reports" / f"masscan_{target.replace('/', '_').replace(' ', '_')}.bin"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            args.extend(["-oB", str(output_file)])
        
        # Exclude hosts
        if exclude.strip():
            args.extend(["--exclude", exclude.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,  # 10 minute timeout
        )

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        
        stdout_text = proc.stdout.strip()
        
        # Result analysis
        if stdout_text and self._is_truthy(analyze_results):
            analysis = self._analyze_results(stdout_text)
            if analysis:
                body_lines.append("Scan Analysis:")
                body_lines.append(json.dumps(analysis, indent=2))
                body_lines.append("")
        
        if stdout_text:
            body_lines.append("Results:")
            body_lines.append(stdout_text)
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not stdout_text:
            error_msg = proc.stderr.strip()
            if "permission denied" in error_msg.lower() or "operation not permitted" in error_msg.lower():
                raise RuntimeError("Masscan requires root privileges. Run with sudo or as root.")
            raise RuntimeError(f"Masscan failed: {error_msg}")

        mime_type = "application/json" if self._is_truthy(analyze_results) and stdout_text else "text/plain"
        
        return ToolResult(
            title=f"Masscan: {target}",
            body="\n".join(body_lines).strip(),
            mime_type=mime_type,
        )
    
    def _analyze_results(self, output: str) -> Dict[str, object]:
        """Analyze Masscan scan results."""
        analysis: Dict[str, object] = {
            "summary": {
                "total_ports": 0,
                "ports_by_host": {},
                "unique_ports": set(),
            },
            "ports": [],
        }
        
        # Parse Masscan output format
        # Format: "Discovered open port 80/tcp on 192.168.1.1"
        port_pattern = r"Discovered open port (\d+)/(\w+)\s+on\s+([\d.]+)"
        matches = re.findall(port_pattern, output, re.IGNORECASE)
        
        ports_list: List[Dict[str, str]] = []
        ports_by_host: Dict[str, List[str]] = {}
        unique_ports: set[str] = set()
        
        for match in matches:
            port, proto, host = match
            port_key = f"{port}/{proto}"
            unique_ports.add(port_key)
            
            ports_list.append({
                "host": host,
                "port": port,
                "protocol": proto,
            })
            
            if host not in ports_by_host:
                ports_by_host[host] = []
            ports_by_host[host].append(port_key)
        
        summary = {
            "total_ports": len(ports_list),
            "ports_by_host": {host: ports for host, ports in ports_by_host.items()},
            "unique_ports": list(unique_ports),
        }
        
        return {
            "summary": summary,
            "ports": ports_list,
        }
    
    def _is_truthy(self, value: str) -> bool:
        return value.lower() in {"1", "true", "yes", "y", "on"}

