"""CrackMapExec wrapper for network service exploitation (opt-in)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
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


def is_crackmapexec_available() -> bool:
    # Check for both cme and crackmapexec
    return shutil.which("cme") is not None or shutil.which("crackmapexec") is not None


class CrackMapExecProfile(NamedTuple):
    """Declarative description for a preset protocol profile."""

    profile_id: str
    label: str
    description: str
    protocol: str


PROFILE_CHOICES: Sequence[CrackMapExecProfile] = (
    CrackMapExecProfile(
        "smb",
        "SMB",
        "SMB enumeration and exploitation",
        "smb",
    ),
    CrackMapExecProfile(
        "winrm",
        "WinRM",
        "Windows Remote Management",
        "winrm",
    ),
    CrackMapExecProfile(
        "ssh",
        "SSH",
        "SSH enumeration",
        "ssh",
    ),
    CrackMapExecProfile(
        "ldap",
        "LDAP",
        "LDAP enumeration",
        "ldap",
    ),
)


class CrackMapExecTool:
    name = "CrackMapExec"
    description = "Network service exploitation framework (opt-in, use responsibly)."
    category = "Misc"

    def run(
        self,
        target: str,
        profile: str = "smb",
        username: str = "",
        password: str = "",
        domain: str = "",
        command: str = "",
        shares: str = "0",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        
        # Check for both possible command names
        tool_name = "cme" if shutil.which("cme") else "crackmapexec"
        if not is_crackmapexec_available():
            raise RuntimeError("crackmapexec/cme not found in PATH. Install crackmapexec locally.")
        if not target.strip():
            raise ValueError("Target is required")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[0]  # smb

        protocol = selected_profile.protocol

        args: List[str] = [tool_name, protocol, target.strip()]

        # Credentials
        if username.strip():
            args.extend(["-u", username.strip()])
        if password.strip():
            args.extend(["-p", password.strip()])
        if domain.strip():
            args.extend(["-d", domain.strip()])

        # Enumerate shares (SMB)
        if _is_truthy(shares) and protocol == "smb":
            args.append("--shares")

        # Execute command
        if command.strip():
            args.extend(["-x", command.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

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
        body_lines.append("WARNING: Use only on systems you own or have permission to test!")
        body_lines.append("")
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"CrackMapExec failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"CrackMapExec {protocol}: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

