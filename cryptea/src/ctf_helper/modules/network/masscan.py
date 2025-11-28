"""Masscan wrapper for ultra-fast port scanning (opt-in)."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import List, NamedTuple, Sequence

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

        # Override ports if specified
        if ports.strip():
            args = [a for i, a in enumerate(args) if not (a == "-p" or (i > 0 and args[i-1] == "-p"))]
            args = [a for i, a in enumerate(args) if not (a == "--top-ports" or (i > 0 and args[i-1] == "--top-ports"))]
            args.extend(["-p", ports.strip()])

        # Override rate if specified
        if rate.strip():
            args = [a for i, a in enumerate(args) if not (a == "--rate" or (i > 0 and args[i-1] == "--rate"))]
            args.extend(["--rate", rate.strip()])

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
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not proc.stdout.strip():
            error_msg = proc.stderr.strip()
            if "permission denied" in error_msg.lower() or "operation not permitted" in error_msg.lower():
                raise RuntimeError("Masscan requires root privileges. Run with sudo or as root.")
            raise RuntimeError(f"Masscan failed: {error_msg}")

        return ToolResult(
            title=f"Masscan: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

