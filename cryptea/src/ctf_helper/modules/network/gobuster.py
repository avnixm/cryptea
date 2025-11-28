"""Gobuster wrapper for directory/DNS/vhost brute-forcing (opt-in)."""

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


def is_gobuster_available() -> bool:
    return shutil.which("gobuster") is not None


class GobusterProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    mode: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[GobusterProfile] = (
    GobusterProfile(
        "dir-quick",
        "Directory Quick",
        "Fast directory brute-force with common wordlist",
        "dir",
        ("-t", "50", "--no-error"),
    ),
    GobusterProfile(
        "dir-default",
        "Directory Default",
        "Balanced directory enumeration",
        "dir",
        ("-t", "30", "--no-error"),
    ),
    GobusterProfile(
        "dir-full",
        "Directory Full",
        "Comprehensive directory scan with extensions",
        "dir",
        ("-t", "50", "-x", "php,html,txt,js,zip,bak", "--no-error"),
    ),
    GobusterProfile(
        "dns-quick",
        "DNS Quick",
        "Fast subdomain enumeration",
        "dns",
        ("-t", "50",),
    ),
    GobusterProfile(
        "vhost-default",
        "VHost Default",
        "Virtual host discovery",
        "vhost",
        ("-t", "30",),
    ),
)


class GobusterTool:
    name = "Gobuster"
    description = "Directory/DNS/VHost brute-forcing tool (opt-in)."
    category = "Network"

    def run(
        self,
        target: str,
        profile: str = "dir-default",
        wordlist: str = "",
        extensions: str = "",
        threads: str = "30",
        timeout: str = "10s",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_gobuster_available():
            raise RuntimeError("gobuster not found in PATH. Install gobuster locally.")
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

        mode = selected_profile.mode
        args: List[str] = ["gobuster", mode, "-u", target]

        # Add profile args
        args.extend(selected_profile.args)

        # Wordlist handling
        if wordlist.strip():
            wordlist_path = Path(wordlist.strip()).expanduser()
            if not wordlist_path.exists():
                raise FileNotFoundError(f"Wordlist not found: {wordlist}")
            args.extend(["-w", str(wordlist_path)])
        else:
            # Use default wordlist from SecLists
            default_wordlist = Path(user_data_dir()) / "SecLists" / "common.txt"
            if default_wordlist.exists():
                args.extend(["-w", str(default_wordlist)])
            else:
                raise RuntimeError("No wordlist specified and default not found")

        # Additional options
        if extensions.strip() and mode == "dir":
            args.extend(["-x", extensions.strip()])
        
        if threads.strip():
            args.extend(["-t", threads.strip()])
        
        if timeout.strip():
            args.extend(["--timeout", timeout.strip()])

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
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"Gobuster failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Gobuster {mode} scan: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

