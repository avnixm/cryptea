"""Hydra wrapper for network login brute-forcing (opt-in)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

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


def is_hydra_available() -> bool:
    return shutil.which("hydra") is not None


class HydraProfile(NamedTuple):
    """Declarative description for a preset protocol profile."""

    profile_id: str
    label: str
    description: str
    protocol: str


PROFILE_CHOICES: Sequence[HydraProfile] = (
    HydraProfile(
        "ssh",
        "SSH",
        "SSH login brute-force",
        "ssh",
    ),
    HydraProfile(
        "ftp",
        "FTP",
        "FTP login brute-force",
        "ftp",
    ),
    HydraProfile(
        "http-get",
        "HTTP GET",
        "HTTP GET authentication brute-force",
        "http-get",
    ),
    HydraProfile(
        "http-post",
        "HTTP POST",
        "HTTP POST form brute-force",
        "http-post-form",
    ),
    HydraProfile(
        "smb",
        "SMB",
        "SMB/Windows share brute-force",
        "smb",
    ),
    HydraProfile(
        "rdp",
        "RDP",
        "RDP login brute-force",
        "rdp",
    ),
)


class HydraTool:
    name = "Hydra"
    description = "Network login brute-forcer (opt-in, use responsibly)."
    category = "Misc"

    def run(
        self,
        target: str,
        profile: str = "ssh",
        username: str = "",
        password: str = "",
        user_list: str = "",
        pass_list: str = "",
        port: str = "",
        threads: str = "4",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_hydra_available():
            raise RuntimeError("hydra not found in PATH. Install hydra locally.")
        if not target.strip():
            raise ValueError("Target is required")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[0]  # ssh

        protocol = selected_profile.protocol

        args: List[str] = ["hydra"]

        # Username/password or lists
        if username.strip():
            args.extend(["-l", username.strip()])
        elif user_list.strip():
            user_path = Path(user_list.strip()).expanduser()
            if not user_path.exists():
                raise FileNotFoundError(f"User list not found: {user_list}")
            args.extend(["-L", str(user_path)])
        else:
            # Use default username list if available
            default_users = Path(user_data_dir()) / "SecLists" / "common.txt"
            if default_users.exists():
                args.extend(["-L", str(default_users)])
            else:
                raise ValueError("Either username or user_list must be provided")

        if password.strip():
            args.extend(["-p", password.strip()])
        elif pass_list.strip():
            pass_path = Path(pass_list.strip()).expanduser()
            if not pass_path.exists():
                raise FileNotFoundError(f"Password list not found: {pass_list}")
            args.extend(["-P", str(pass_path)])
        else:
            # Use default password list if available
            default_passes = Path(user_data_dir()) / "SecLists" / "common.txt"
            if default_passes.exists():
                args.extend(["-P", str(default_passes)])
            else:
                raise ValueError("Either password or pass_list must be provided")

        # Port
        if port.strip():
            args.extend(["-s", port.strip()])

        # Threads
        if threads.strip():
            args.extend(["-t", threads.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Target and protocol
        args.append(target.strip())
        args.append(protocol)

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
            raise RuntimeError(f"Hydra failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Hydra {protocol}: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

