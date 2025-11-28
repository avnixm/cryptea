"""Volatility wrapper for memory forensics analysis."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence

from ..base import ToolResult


def is_volatility_available() -> bool:
    # Check for both volatility2 and volatility3
    return shutil.which("vol.py") is not None or shutil.which("vol") is not None or shutil.which("volatility") is not None


class VolatilityProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    plugins: Sequence[str]


PROFILE_CHOICES: Sequence[VolatilityProfile] = (
    VolatilityProfile(
        "info",
        "Image Info",
        "Get basic information about the memory image",
        ("windows.info", "linux.banner"),
    ),
    VolatilityProfile(
        "processes",
        "Processes",
        "List running processes",
        ("windows.pslist", "windows.pstree", "windows.psscan"),
    ),
    VolatilityProfile(
        "network",
        "Network",
        "Network connections and sockets",
        ("windows.netscan", "windows.netstat", "linux.netstat"),
    ),
    VolatilityProfile(
        "malware",
        "Malware Analysis",
        "Common malware detection plugins",
        ("windows.malfind", "windows.dlllist", "windows.handles"),
    ),
    VolatilityProfile(
        "registry",
        "Registry",
        "Registry analysis",
        ("windows.registry.hivelist", "windows.registry.printkey"),
    ),
    VolatilityProfile(
        "files",
        "Files",
        "File system and file analysis",
        ("windows.filescan", "windows.dumpfiles"),
    ),
)


class VolatilityTool:
    name = "Volatility"
    description = "Memory forensics framework for analyzing RAM dumps."
    category = "Forensics"

    def run(
        self,
        memory_dump: str,
        profile: str = "processes",
        plugin: str = "",
        os_profile: str = "",
        extra: str = "",
        chain_plugins: str = "false",
        parse_output: str = "false",
    ) -> ToolResult:
        if not is_volatility_available():
            raise RuntimeError("volatility not found in PATH. Install volatility locally.")
        
        dump_path = Path(memory_dump).expanduser()
        if not dump_path.exists():
            raise FileNotFoundError(f"Memory dump not found: {memory_dump}")

        # Determine which version of volatility is available
        if shutil.which("vol"):
            vol_cmd = "vol"
            is_vol3 = True
        elif shutil.which("vol.py"):
            vol_cmd = "vol.py"
            is_vol3 = True
        else:
            vol_cmd = "volatility"
            is_vol3 = False

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[1]  # processes

        should_chain = self._truthy(chain_plugins)
        should_parse = self._truthy(parse_output)
        
        results: List[str] = []
        parsed_results: Dict[str, object] = {}
        results.append(f"Memory dump: {dump_path}")
        results.append(f"Volatility version: {'3' if is_vol3 else '2'}")
        results.append("")

        # Run each plugin in the profile
        plugins_to_run = [plugin.strip()] if plugin.strip() else list(selected_profile.plugins)

        for plug in plugins_to_run:
            if is_vol3:
                args: List[str] = [vol_cmd, "-f", str(dump_path)]
                if os_profile.strip():
                    # Vol3 doesn't use profiles the same way, but we can pass it
                    pass
                args.append(plug)
            else:
                # Volatility 2
                args = [vol_cmd, "-f", str(dump_path)]
                if os_profile.strip():
                    args.extend(["--profile", os_profile.strip()])
                # Convert vol3 plugin names to vol2 if needed
                vol2_plug = plug.replace("windows.", "").replace("linux.", "")
                args.append(vol2_plug)

            # Extra arguments
            if extra.strip():
                args.extend(extra.split())

            results.append(f"Running plugin: {plug}")
            results.append(f"Command: {' '.join(args)}")
            results.append("-" * 80)

            # Execute
            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600,  # 10 minute timeout per plugin
            )

            if proc.stdout.strip():
                output = proc.stdout.strip()
                results.append(output)
                
                # Parse output if requested
                if should_parse:
                    parsed = self._parse_plugin_output(plug, output)
                    if parsed:
                        parsed_results[plug] = parsed
            
            if proc.stderr.strip():
                results.append("Errors/Warnings:")
                results.append(proc.stderr.strip())

            results.append("")
            results.append("")
        
        # Add parsed results summary if parsing was enabled
        if should_parse and parsed_results:
            results.append("=" * 80)
            results.append("Parsed Results Summary:")
            results.append(json.dumps(parsed_results, indent=2))

        return ToolResult(
            title=f"Volatility: {dump_path.name}",
            body="\n".join(results).strip(),
            mime_type="text/plain",
        )

    def _parse_plugin_output(self, plugin: str, output: str) -> Optional[Dict[str, object]]:
        """Parse common Volatility plugin outputs into structured data."""
        parsed: Dict[str, object] = {}
        
        # Parse pslist/pscan output
        if "pslist" in plugin.lower() or "pscan" in plugin.lower():
            processes = self._parse_process_list(output)
            if processes:
                parsed["processes"] = processes
                parsed["process_count"] = len(processes)
        
        # Parse netscan/netstat output
        elif "netscan" in plugin.lower() or "netstat" in plugin.lower():
            connections = self._parse_network_connections(output)
            if connections:
                parsed["connections"] = connections
                parsed["connection_count"] = len(connections)
        
        # Parse malfind output
        elif "malfind" in plugin.lower():
            findings = self._parse_malfind(output)
            if findings:
                parsed["findings"] = findings
                parsed["finding_count"] = len(findings)
        
        # Parse info/banner output
        elif "info" in plugin.lower() or "banner" in plugin.lower():
            info = self._parse_info_output(output)
            if info:
                parsed["info"] = info
        
        # Parse registry output
        elif "registry" in plugin.lower() or "hivelist" in plugin.lower():
            hives = self._parse_registry_hives(output)
            if hives:
                parsed["hives"] = hives
                parsed["hive_count"] = len(hives)
        
        # Parse filescan output
        elif "filescan" in plugin.lower():
            files = self._parse_filescan(output)
            if files:
                parsed["files"] = files
                parsed["file_count"] = len(files)
        
        return parsed if parsed else None

    def _parse_process_list(self, output: str) -> List[Dict[str, object]]:
        """Parse process list output."""
        processes: List[Dict[str, object]] = []
        lines = output.splitlines()
        
        # Skip header lines
        data_started = False
        for line in lines:
            if "PID" in line and "PPID" in line and "Name" in line:
                data_started = True
                continue
            
            if not data_started:
                continue
            
            # Parse process line
            parts = line.split()
            if len(parts) >= 4:
                try:
                    processes.append({
                        "pid": parts[0],
                        "ppid": parts[1] if len(parts) > 1 else "",
                        "name": parts[-1] if parts else "",
                        "full_line": line.strip(),
                    })
                except Exception:
                    pass
        
        return processes

    def _parse_network_connections(self, output: str) -> List[Dict[str, object]]:
        """Parse network connections output."""
        connections: List[Dict[str, object]] = []
        lines = output.splitlines()
        
        data_started = False
        for line in lines:
            if "Local" in line and "Remote" in line:
                data_started = True
                continue
            
            if not data_started:
                continue
            
            # Parse connection line
            parts = line.split()
            if len(parts) >= 4:
                try:
                    connections.append({
                        "local": parts[0] if parts else "",
                        "remote": parts[1] if len(parts) > 1 else "",
                        "state": parts[2] if len(parts) > 2 else "",
                        "full_line": line.strip(),
                    })
                except Exception:
                    pass
        
        return connections

    def _parse_malfind(self, output: str) -> List[Dict[str, object]]:
        """Parse malfind output."""
        findings: List[Dict[str, object]] = []
        
        # Look for process names and suspicious indicators
        lines = output.splitlines()
        current_finding: Dict[str, object] = {}
        
        for line in lines:
            if "Process:" in line:
                if current_finding:
                    findings.append(current_finding)
                current_finding = {"process": line.split("Process:")[-1].strip(), "indicators": []}
            elif "Vad" in line or "Protection" in line:
                if current_finding:
                    current_finding["indicators"] = current_finding.get("indicators", [])
                    if isinstance(current_finding["indicators"], list):
                        current_finding["indicators"].append(line.strip())
        
        if current_finding:
            findings.append(current_finding)
        
        return findings

    def _parse_info_output(self, output: str) -> Dict[str, object]:
        """Parse info/banner output."""
        info: Dict[str, object] = {}
        lines = output.splitlines()
        
        for line in lines:
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower().replace(" ", "_")
                    value = parts[1].strip()
                    info[key] = value
        
        return info

    def _parse_registry_hives(self, output: str) -> List[Dict[str, object]]:
        """Parse registry hivelist output."""
        hives: List[Dict[str, object]] = []
        lines = output.splitlines()
        
        data_started = False
        for line in lines:
            if "Virtual" in line and "Physical" in line:
                data_started = True
                continue
            
            if not data_started:
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                hives.append({
                    "virtual": parts[0] if parts else "",
                    "physical": parts[1] if len(parts) > 1 else "",
                    "full_line": line.strip(),
                })
        
        return hives

    def _parse_filescan(self, output: str) -> List[Dict[str, object]]:
        """Parse filescan output."""
        files: List[Dict[str, object]] = []
        lines = output.splitlines()
        
        for line in lines:
            # Filescan typically shows offset, path
            if "0x" in line and ("\\" in line or "/" in line):
                parts = line.split()
                if len(parts) >= 2:
                    files.append({
                        "offset": parts[0],
                        "path": parts[-1] if parts else "",
                        "full_line": line.strip(),
                    })
        
        return files[:100]  # Limit to 100 files

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

 