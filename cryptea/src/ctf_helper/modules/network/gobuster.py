"""Gobuster wrapper for directory/DNS/vhost brute-forcing (opt-in)."""

from __future__ import annotations

import json
import re
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
        filter_status: str = "",
        filter_size: str = "",
        categorize_results: str = "true",
        detect_wildcard: str = "true",
        follow_redirects: str = "false",
        output_format: str = "text",
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
        
        # Status code filtering
        if filter_status.strip():
            args.extend(["-b", filter_status.strip()])
        
        # Response size filtering
        if filter_size.strip():
            args.extend(["-s", filter_size.strip()])
        
        # Follow redirects
        if self._is_truthy(follow_redirects):
            args.append("-k")
        
        # Output format
        if output_format.lower() == "json":
            args.extend(["-o", "-", "--format", "json"])

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
        
        stdout_text = proc.stdout.strip()
        
        # Wildcard detection (for DNS mode)
        if mode == "dns" and self._is_truthy(detect_wildcard) and stdout_text:
            wildcard_detected = self._detect_wildcard(target, stdout_text)
            if wildcard_detected:
                body_lines.append("⚠ Wildcard subdomain detected - results may be unreliable")
                body_lines.append("")
        
        # Result categorization
        if self._is_truthy(categorize_results) and stdout_text:
            if output_format.lower() == "json":
                try:
                    parsed = json.loads(stdout_text)
                    categorized = self._categorize_results_json(parsed, mode)
                    if categorized:
                        body_lines.append("Categorized Results:")
                        body_lines.append(json.dumps(categorized, indent=2))
                        body_lines.append("")
                        body_lines.append("Raw Output:")
                except json.JSONDecodeError:
                    pass
            else:
                categorized = self._categorize_results_text(stdout_text, mode)
                if categorized:
                    body_lines.append("Categorized Results:")
                    body_lines.append(json.dumps(categorized, indent=2))
                    body_lines.append("")
        
        if stdout_text:
            body_lines.append("Results:")
            body_lines.append(stdout_text)
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not stdout_text:
            raise RuntimeError(f"Gobuster failed: {proc.stderr.strip()}")

        mime_type = "application/json" if output_format.lower() == "json" or self._is_truthy(categorize_results) else "text/plain"
        
        return ToolResult(
            title=f"Gobuster {mode} scan: {target}",
            body="\n".join(body_lines).strip(),
            mime_type=mime_type,
        )
    
    def _detect_wildcard(self, target: str, output: str) -> bool:
        """Detect wildcard subdomains in DNS enumeration."""
        # Check for patterns that indicate wildcard
        wildcard_patterns = [
            r"wildcard",
            r"all.*resolved",
            r"too many results",
        ]
        output_lower = output.lower()
        return any(re.search(pattern, output_lower, re.IGNORECASE) for pattern in wildcard_patterns)
    
    def _categorize_results_text(self, output: str, mode: str) -> Dict[str, List[Dict[str, str]]]:
        """Categorize results from text output."""
        categorized: Dict[str, List[Dict[str, str]]] = {
            "admin_panels": [],
            "api_endpoints": [],
            "backup_files": [],
            "sensitive_files": [],
            "directories": [],
            "other": [],
        }
        
        admin_keywords = ["admin", "administrator", "login", "dashboard", "panel", "wp-admin"]
        api_keywords = ["api", "/api/", "v1", "v2", "rest", "graphql", "json", "xml"]
        backup_keywords = [".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp"]
        sensitive_keywords = [".env", ".git", "config", "password", "secret", "key", ".htaccess"]
        
        lines = output.splitlines()
        for line in lines:
            line_lower = line.lower()
            result_dict: Dict[str, str] = {"path": line.strip()}
            
            # Extract status code if present
            status_match = re.search(r"\(Status:\s*(\d+)\)", line)
            if status_match:
                result_dict["status"] = status_match.group(1)
            
            # Categorize
            categorized_flag = False
            if any(kw in line_lower for kw in admin_keywords):
                categorized["admin_panels"].append(result_dict)
                categorized_flag = True
            elif any(kw in line_lower for kw in api_keywords):
                categorized["api_endpoints"].append(result_dict)
                categorized_flag = True
            elif any(kw in line_lower for kw in backup_keywords):
                categorized["backup_files"].append(result_dict)
                categorized_flag = True
            elif any(kw in line_lower for kw in sensitive_keywords):
                categorized["sensitive_files"].append(result_dict)
                categorized_flag = True
            
            if not categorized_flag:
                categorized["other"].append(result_dict)
        
        return categorized
    
    def _categorize_results_json(self, parsed: object, mode: str) -> Dict[str, List[Dict[str, str]]]:
        """Categorize results from JSON output."""
        # Similar logic but for JSON structure
        return self._categorize_results_text(str(parsed), mode)
    
    def _is_truthy(self, value: str) -> bool:
        return value.lower() in {"1", "true", "yes", "y", "on"}

