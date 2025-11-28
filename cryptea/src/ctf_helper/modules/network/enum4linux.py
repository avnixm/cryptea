"""Enum4linux wrapper for SMB enumeration (opt-in)."""

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


def is_enum4linux_available() -> bool:
    return shutil.which("enum4linux") is not None or shutil.which("enum4linux-ng") is not None


class Enum4linuxProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[Enum4linuxProfile] = (
    Enum4linuxProfile(
        "quick",
        "Quick",
        "Basic enumeration",
        ("-U", "-S", "-P"),
    ),
    Enum4linuxProfile(
        "default",
        "Default",
        "Standard enumeration with shares and users",
        ("-a",),
    ),
    Enum4linuxProfile(
        "full",
        "Full",
        "Comprehensive enumeration with all checks",
        ("-a", "-v"),
    ),
)


class Enum4linuxTool:
    name = "Enum4linux"
    description = "SMB/Windows enumeration tool (opt-in)."
    category = "Network"

    def run(
        self,
        target: str,
        profile: str = "default",
        username: str = "",
        password: str = "",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        
        # Check for enum4linux-ng first (newer version), then fall back to enum4linux
        tool_name = "enum4linux-ng" if shutil.which("enum4linux-ng") else "enum4linux"
        if not is_enum4linux_available():
            raise RuntimeError("enum4linux/enum4linux-ng not found in PATH. Install enum4linux locally.")
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

        args: List[str] = [tool_name]

        # Add profile args
        args.extend(selected_profile.args)

        # Credentials
        if username.strip():
            args.extend(["-u", username.strip()])
        if password.strip():
            args.extend(["-p", password.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Target at the end
        args.append(target.strip())

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,  # 5 minute timeout
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
            raise RuntimeError(f"Enum4linux failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Enum4linux: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

