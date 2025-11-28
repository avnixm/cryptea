"""Nikto wrapper for web server vulnerability scanning (opt-in)."""

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


def is_nikto_available() -> bool:
    return shutil.which("nikto") is not None


class NiktoProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[NiktoProfile] = (
    NiktoProfile(
        "quick",
        "Quick",
        "Fast scan with basic tests",
        ("-Tuning", "1,2,3", "-maxtime", "5m"),
    ),
    NiktoProfile(
        "default",
        "Default",
        "Standard vulnerability scan",
        ("-Tuning", "x", "-maxtime", "10m"),
    ),
    NiktoProfile(
        "full",
        "Full",
        "Comprehensive scan with all tests",
        ("-Tuning", "0", "-maxtime", "30m"),
    ),
    NiktoProfile(
        "stealth",
        "Stealth",
        "Slow, evasive scan",
        ("-Tuning", "x", "-maxtime", "20m", "-Pause", "2"),
    ),
)


class NiktoTool:
    name = "Nikto"
    description = "Web server vulnerability scanner (opt-in)."
    category = "Network"

    def run(
        self,
        target: str,
        profile: str = "default",
        port: str = "80",
        ssl: str = "0",
        tuning: str = "",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_nikto_available():
            raise RuntimeError("nikto not found in PATH. Install nikto locally.")
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

        args: List[str] = ["nikto", "-h", target]

        # Add profile args
        args.extend(selected_profile.args)

        # Port
        if port.strip():
            args.extend(["-p", port.strip()])

        # SSL
        if _is_truthy(ssl):
            args.append("-ssl")

        # Tuning override
        if tuning.strip():
            args = [a for i, a in enumerate(args) if not (a == "-Tuning" or (i > 0 and args[i-1] == "-Tuning"))]
            args.extend(["-Tuning", tuning.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1800,  # 30 minute timeout
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
            raise RuntimeError(f"Nikto failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Nikto scan: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

