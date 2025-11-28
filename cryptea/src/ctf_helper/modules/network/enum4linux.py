"""Enum4linux wrapper for SMB enumeration (opt-in)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
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
        parse_results: str = "true",
        output_format: str = "text",
        enumerate_shares: str = "true",
        enumerate_users: str = "true",
        enumerate_groups: str = "true",
        enumerate_policies: str = "true",
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
        
        # Enhanced enumeration flags
        enum_flags = []
        if self._is_truthy(enumerate_shares):
            enum_flags.append("-S")  # Share enumeration
        if self._is_truthy(enumerate_users):
            enum_flags.append("-U")  # User enumeration
        if self._is_truthy(enumerate_groups):
            enum_flags.append("-G")  # Group enumeration
        if self._is_truthy(enumerate_policies):
            enum_flags.append("-P")  # Password policy
        
        # Add enum flags if specific flags requested
        if enum_flags and profile == "default":
            args.extend(enum_flags)
        
        # Output format
        output_format_lower = output_format.lower().strip()
        if output_format_lower == "json":
            output_file = user_data_dir() / "enum4linux_reports" / f"enum4linux_{target.replace('/', '_')}.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            # enum4linux-ng supports JSON output
            if "enum4linux-ng" in args[0]:
                args.extend(["-oJ", str(output_file)])

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
        
        stdout_text = proc.stdout.strip()
        
        # Parse and structure results
        if stdout_text and self._is_truthy(parse_results):
            structured = self._parse_results(stdout_text)
            if structured:
                body_lines.append("Structured Results:")
                body_lines.append(json.dumps(structured, indent=2))
                body_lines.append("")
                body_lines.append("Raw Output:")
        
        if stdout_text:
            body_lines.append("Results:")
            body_lines.append(stdout_text)
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not stdout_text:
            raise RuntimeError(f"Enum4linux failed: {proc.stderr.strip()}")

        mime_type = "application/json" if self._is_truthy(parse_results) and stdout_text else "text/plain"
        
        return ToolResult(
            title=f"Enum4linux: {target}",
            body="\n".join(body_lines).strip(),
            mime_type=mime_type,
        )
    
    def _parse_results(self, output: str) -> Dict[str, object]:
        """Parse Enum4linux output into structured format."""
        users: List[Dict[str, str]] = []
        groups: List[Dict[str, str]] = []
        shares: List[Dict[str, str]] = []
        policies: Dict[str, object] = {}
        domains: List[str] = []
        
        lines = output.splitlines()
        current_section = None
        
        for line in lines:
            line_stripped = line.strip()
            
            # Detect sections
            if "user:" in line_stripped.lower() or "account:" in line_stripped.lower():
                current_section = "users"
            elif "group:" in line_stripped.lower() or "group name:" in line_stripped.lower():
                current_section = "groups"
            elif "share:" in line_stripped.lower() or "share name:" in line_stripped.lower():
                current_section = "shares"
            elif "domain:" in line_stripped.lower():
                current_section = "domains"
            
            # Parse users
            user_match = re.search(r"user:\[([^\]]+)\].*rid:\[(\d+)\]", line_stripped, re.IGNORECASE)
            if user_match:
                username, rid = user_match.groups()
                users.append({"username": username, "rid": rid})
            
            # Parse groups
            group_match = re.search(r"group:\[([^\]]+)\].*rid:\[(\d+)\]", line_stripped, re.IGNORECASE)
            if group_match:
                groupname, rid = group_match.groups()
                groups.append({"groupname": groupname, "rid": rid})
            
            # Parse shares
            share_match = re.search(r"Share\s+name\s+Type\s+Comment", line_stripped, re.IGNORECASE)
            if share_match:
                current_section = "shares"
                continue
            
            if current_section == "shares" and ("Disk" in line_stripped or "IPC$" in line_stripped):
                parts = line_stripped.split()
                if len(parts) >= 3:
                    shares.append({
                        "name": parts[0],
                        "type": parts[1] if len(parts) > 1 else "Unknown",
                        "comment": " ".join(parts[2:]) if len(parts) > 2 else "",
                    })
            
            # Parse password policies
            if "password" in line_stripped.lower() and "policy" in line_stripped.lower():
                if "minimum length" in line_stripped.lower():
                    min_len_match = re.search(r"(\d+)", line_stripped)
                    if min_len_match:
                        policies["min_password_length"] = int(min_len_match.group(1))
                elif "complexity" in line_stripped.lower():
                    policies["complexity_required"] = "yes" in line_stripped.lower()
            
            # Parse domains
            domain_match = re.search(r"domain:\[([^\]]+)\]", line_stripped, re.IGNORECASE)
            if domain_match:
                domain = domain_match.group(1)
                if domain not in domains:
                    domains.append(domain)
        
        return {
            "users": users,
            "groups": groups,
            "shares": shares,
            "policies": policies,
            "domains": domains,
        }
    
    def _is_truthy(self, value: str) -> bool:
        return value.lower() in {"1", "true", "yes", "y", "on"}

