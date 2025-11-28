"""Volatility wrapper for memory forensics analysis."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

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
        ("windows.info",),
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
        ("windows.netscan", "windows.netstat"),
    ),
    VolatilityProfile(
        "malware",
        "Malware Analysis",
        "Common malware detection plugins",
        ("windows.malfind", "windows.dlllist", "windows.handles"),
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

        results: List[str] = []
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
                results.append(proc.stdout.strip())
            
            if proc.stderr.strip():
                results.append("Errors/Warnings:")
                results.append(proc.stderr.strip())

            results.append("")
            results.append("")

        return ToolResult(
            title=f"Volatility: {dump_path.name}",
            body="\n".join(results).strip(),
            mime_type="text/plain",
        )

