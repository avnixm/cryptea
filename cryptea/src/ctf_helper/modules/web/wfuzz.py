"""Wfuzz wrapper for web application fuzzing (opt-in)."""

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


def is_wfuzz_available() -> bool:
    return shutil.which("wfuzz") is not None


class WfuzzProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[WfuzzProfile] = (
    WfuzzProfile(
        "quick",
        "Quick",
        "Fast fuzzing with basic filters",
        ("-t", "50", "--hc", "404"),
    ),
    WfuzzProfile(
        "default",
        "Default",
        "Balanced fuzzing",
        ("-t", "100", "--hc", "404,403"),
    ),
    WfuzzProfile(
        "full",
        "Full",
        "Comprehensive fuzzing with all responses",
        ("-t", "200", "--sc", "200,301,302,401,403,500"),
    ),
    WfuzzProfile(
        "stealth",
        "Stealth",
        "Slow, evasive fuzzing",
        ("-t", "10", "-s", "2", "--hc", "404"),
    ),
)


class WfuzzTool:
    name = "Wfuzz"
    description = "Web application fuzzer (opt-in)."
    category = "Web"

    def run(
        self,
        target: str,
        profile: str = "default",
        wordlist: str = "",
        fuzz_keyword: str = "FUZZ",
        hide_codes: str = "",
        show_codes: str = "",
        hide_lines: str = "",
        threads: str = "100",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_wfuzz_available():
            raise RuntimeError("wfuzz not found in PATH. Install wfuzz locally.")
        if not target.strip():
            raise ValueError("Target URL is required")
        if fuzz_keyword.upper() not in target.upper():
            raise ValueError(f"Target must contain {fuzz_keyword} keyword for fuzzing position")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[1]  # default

        args: List[str] = ["wfuzz"]

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

        # Override hide/show codes if specified
        if hide_codes.strip():
            args = [a for i, a in enumerate(args) if not (a == "--hc" or (i > 0 and args[i-1] == "--hc"))]
            args.extend(["--hc", hide_codes.strip()])
        
        if show_codes.strip():
            args = [a for i, a in enumerate(args) if not (a == "--sc" or (i > 0 and args[i-1] == "--sc"))]
            args.extend(["--sc", show_codes.strip()])
        
        if hide_lines.strip():
            args.extend(["--hl", hide_lines.strip()])

        # Threads
        if threads.strip():
            args = [a for i, a in enumerate(args) if not (a == "-t" or (i > 0 and args[i-1] == "-t"))]
            args.extend(["-t", threads.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Target URL at the end
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
            raise RuntimeError(f"Wfuzz failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Wfuzz: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

