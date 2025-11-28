"""ffuf wrapper for fast web fuzzing (opt-in)."""

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


def is_ffuf_available() -> bool:
    return shutil.which("ffuf") is not None


class FfufProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[FfufProfile] = (
    FfufProfile(
        "quick",
        "Quick",
        "Fast fuzzing with minimal threads",
        ("-t", "50", "-mc", "200,204,301,302,307,401,403"),
    ),
    FfufProfile(
        "default",
        "Default",
        "Balanced fuzzing",
        ("-t", "100", "-mc", "all", "-fc", "404"),
    ),
    FfufProfile(
        "full",
        "Full",
        "Comprehensive fuzzing with recursion",
        ("-t", "200", "-mc", "all", "-fc", "404", "-recursion", "-recursion-depth", "2"),
    ),
    FfufProfile(
        "stealth",
        "Stealth",
        "Slow, stealthy fuzzing",
        ("-t", "10", "-p", "1.0", "-mc", "all", "-fc", "404"),
    ),
)


class FfufTool:
    name = "ffuf"
    description = "Fast web fuzzer for directory/parameter discovery (opt-in)."
    category = "Network"

    def run(
        self,
        target: str,
        profile: str = "default",
        wordlist: str = "",
        fuzz_keyword: str = "FUZZ",
        match_codes: str = "",
        filter_codes: str = "",
        filter_size: str = "",
        threads: str = "100",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_ffuf_available():
            raise RuntimeError("ffuf not found in PATH. Install ffuf locally.")
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

        args: List[str] = ["ffuf", "-u", target]

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

        # Override match/filter codes if specified
        if match_codes.strip():
            # Remove any existing -mc from profile
            args = [a for i, a in enumerate(args) if not (a == "-mc" or (i > 0 and args[i-1] == "-mc"))]
            args.extend(["-mc", match_codes.strip()])
        
        if filter_codes.strip():
            args = [a for i, a in enumerate(args) if not (a == "-fc" or (i > 0 and args[i-1] == "-fc"))]
            args.extend(["-fc", filter_codes.strip()])
        
        if filter_size.strip():
            args.extend(["-fs", filter_size.strip()])

        # Threads
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
            raise RuntimeError(f"ffuf failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"ffuf scan: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

