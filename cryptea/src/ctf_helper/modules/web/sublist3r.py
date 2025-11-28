"""Sublist3r wrapper for subdomain enumeration (opt-in)."""

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


def is_sublist3r_available() -> bool:
    return shutil.which("sublist3r") is not None


class Sublist3rProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[Sublist3rProfile] = (
    Sublist3rProfile(
        "quick",
        "Quick",
        "Fast subdomain enumeration",
        ("-t", "10"),
    ),
    Sublist3rProfile(
        "default",
        "Default",
        "Standard subdomain enumeration",
        ("-t", "20"),
    ),
    Sublist3rProfile(
        "full",
        "Full",
        "Comprehensive enumeration with brute-force",
        ("-t", "30", "-b"),
    ),
)


class Sublist3rTool:
    name = "Sublist3r"
    description = "Subdomain enumeration tool (opt-in)."
    category = "Web"

    def run(
        self,
        domain: str,
        profile: str = "default",
        brute_force: str = "0",
        ports: str = "",
        engines: str = "",
        threads: str = "",
        data_sources: str = "all",
        analyze_results: str = "true",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_sublist3r_available():
            raise RuntimeError("sublist3r not found in PATH. Install sublist3r locally.")
        if not domain.strip():
            raise ValueError("Domain is required")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[1]  # default

        args: List[str] = ["sublist3r", "-d", domain.strip()]

        # Add profile args
        args.extend(selected_profile.args)

        # Brute force
        if _is_truthy(brute_force):
            if "-b" not in args:
                args.append("-b")

        # Ports
        if ports.strip():
            args.extend(["-p", ports.strip()])

        # Engines
        if engines.strip():
            args.extend(["-e", engines.strip()])

        # Threads override
        if threads.strip():
            args = [a for i, a in enumerate(args) if not (a == "-t" or (i > 0 and args[i-1] == "-t"))]
            args.extend(["-t", threads.strip()])

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
            raise RuntimeError(f"Sublist3r failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Sublist3r: {domain}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

