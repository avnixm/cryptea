"""Wfuzz wrapper for web application fuzzing (opt-in)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, NamedTuple, Sequence

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
        hide_words: str = "",
        hide_chars: str = "",
        threads: str = "100",
        cookie: str = "",
        header: str = "",
        post_data: str = "",
        parse_results: str = "true",
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
        
        if hide_words.strip():
            args.extend(["--hw", hide_words.strip()])
        
        if hide_chars.strip():
            args.extend(["--hh", hide_chars.strip()])
        
        # Cookie fuzzing
        if cookie.strip():
            cookie_fuzz = cookie.replace("FUZZ", fuzz_keyword) if "FUZZ" not in cookie else cookie.replace("FUZZ", fuzz_keyword)
            args.extend(["-H", f"Cookie: {cookie_fuzz}"])

        # Header fuzzing
        if header.strip():
            header_fuzz = header.replace("FUZZ", fuzz_keyword) if "FUZZ" not in header else header.replace("FUZZ", fuzz_keyword)
            args.extend(["-H", header_fuzz])

        # POST data fuzzing
        if post_data.strip():
            post_fuzz = post_data.replace("FUZZ", fuzz_keyword)
            args.extend(["-d", post_fuzz, "-X", "POST"])

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
        
        stdout_text = proc.stdout.strip()
        
        if stdout_text:
            if self._is_truthy(parse_results):
                parsed = self._parse_wfuzz_output(stdout_text)
                if parsed:
                    body_lines.append("Parsed Results:")
                    body_lines.append(json.dumps(parsed, indent=2))
                    body_lines.append("")
                    body_lines.append("Raw Output:")
            
            body_lines.append("Results:")
            body_lines.append(stdout_text)
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not stdout_text:
            raise RuntimeError(f"Wfuzz failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Wfuzz: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="application/json" if self._is_truthy(parse_results) and stdout_text else "text/plain",
        )
    
    def _parse_wfuzz_output(self, output: str) -> Dict[str, object]:
        """Parse wfuzz output into structured format."""
        results: List[Dict[str, object]] = []
        lines = output.splitlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith("Total"):
                continue
            
            # Parse wfuzz table format
            # Format: Code    Lines    Word    Chars    Payload
            parts = line.split()
            if len(parts) >= 5:
                try:
                    code = int(parts[0])
                    lines_count = int(parts[1])
                    words_count = int(parts[2])
                    chars_count = int(parts[3])
                    payload = " ".join(parts[4:])
                    
                    results.append({
                        "code": code,
                        "lines": lines_count,
                        "words": words_count,
                        "chars": chars_count,
                        "payload": payload,
                    })
                except (ValueError, IndexError):
                    continue
        
        summary = {
            "total_requests": len(results),
            "by_status_code": {},
        }
        
        for result in results:
            code = str(result.get("code", 0))
            summary["by_status_code"][code] = summary["by_status_code"].get(code, 0) + 1
        
        return {
            "summary": summary,
            "results": results,
        }

    def _is_truthy(self, value: str) -> bool:
        return value.lower() in {"1", "true", "yes", "y", "on"}

