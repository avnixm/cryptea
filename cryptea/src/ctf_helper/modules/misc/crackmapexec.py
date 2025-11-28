"""CrackMapExec wrapper for network service exploitation (opt-in)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Sequence

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
    CrackMapExecProfile("smb", "SMB", "SMB enumeration and exploitation", "smb"),
    CrackMapExecProfile("winrm", "WinRM", "Windows Remote Management", "winrm"),
    CrackMapExecProfile("ssh", "SSH", "SSH enumeration", "ssh"),
    CrackMapExecProfile("ldap", "LDAP", "LDAP enumeration", "ldap"),
    CrackMapExecProfile("mssql", "MSSQL", "Microsoft SQL Server enumeration", "mssql"),
    CrackMapExecProfile("vnc", "VNC", "VNC enumeration", "vnc"),
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
        enumerate_users: str = "false",
        enumerate_groups: str = "false",
        enumerate_shares: str = "false",
        enumerate_sessions: str = "false",
        enumerate_policies: str = "false",
        ldap_users: str = "false",
        ldap_groups: str = "false",
        ldap_ous: str = "false",
        ldap_computers: str = "false",
        mssql_databases: str = "false",
        mssql_tables: str = "false",
        execute_command: str = "",
        upload_file: str = "",
        download_file: str = "",
        output_format: str = "text",
        parse_results: str = "true",
        export_results: str = "false",
        output_file: str = "",
        credential_spray: str = "false",
        password_policy: str = "false",
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

        # Enhanced enumeration options
        if protocol == "smb":
            if self._is_truthy(enumerate_shares) or self._is_truthy(shares):
                args.append("--shares")
            if self._is_truthy(enumerate_users):
                args.append("--users")
            if self._is_truthy(enumerate_groups):
                args.append("--groups")
            if self._is_truthy(enumerate_sessions):
                args.append("--sessions")
            if self._is_truthy(enumerate_policies):
                args.append("--local-auth")
        
        elif protocol == "ldap":
            if self._is_truthy(ldap_users):
                args.append("--users")
            if self._is_truthy(ldap_groups):
                args.append("--groups")
            if self._is_truthy(ldap_ous):
                args.append("--ous")
            if self._is_truthy(ldap_computers):
                args.append("--computers")
        
        elif protocol == "mssql":
            if self._is_truthy(mssql_databases):
                args.append("--databases")
            if self._is_truthy(mssql_tables):
                args.append("--tables")

        # Output format
        if output_format == "json":
            args.append("--json")

        # Execute command
        if execute_command.strip():
            args.extend(["-x", execute_command.strip()])
        elif command.strip():
            args.extend(["-x", command.strip()])

        # File upload/download
        if upload_file.strip():
            args.extend(["--put", upload_file.strip()])
        if download_file.strip():
            args.extend(["--get", download_file.strip()])

        # Credential spraying
        if self._is_truthy(credential_spray):
            args.append("--spray")

        # Password policy testing
        if self._is_truthy(password_policy):
            args.append("--pass-pol")

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

        # Parse results
        parsed_results: Dict[str, Any] = {}
        if self._is_truthy(parse_results):
            parsed_results = self._parse_cme_output(proc.stdout, proc.stderr, protocol, output_format)

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        body_lines.append("WARNING: Use only on systems you own or have permission to test!")
        body_lines.append("")
        
        # Summary
        if parsed_results:
            body_lines.append("=== Summary ===")
            if parsed_results.get("users"):
                body_lines.append(f"Users found: {len(parsed_results['users'])}")
            if parsed_results.get("groups"):
                body_lines.append(f"Groups found: {len(parsed_results['groups'])}")
            if parsed_results.get("shares"):
                body_lines.append(f"Shares found: {len(parsed_results['shares'])}")
            if parsed_results.get("sessions"):
                body_lines.append(f"Active sessions: {len(parsed_results['sessions'])}")
            if parsed_results.get("interesting_findings"):
                body_lines.append(f"Interesting findings: {len(parsed_results['interesting_findings'])}")
            body_lines.append("")
        
        if proc.stdout.strip():
            body_lines.append("=== Raw Output ===")
            body_lines.append(proc.stdout.strip())
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("=== Errors/Warnings ===")
            body_lines.append(proc.stderr.strip())

        # Export results if requested
        if self._is_truthy(export_results) or output_file.strip():
            export_path = self._export_results(parsed_results, output_file, target, protocol, output_format)
            body_lines.append("")
            body_lines.append(f"Results exported to: {export_path}")

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"CrackMapExec failed: {proc.stderr.strip()}")

        # Include parsed results in JSON if available
        result_body = "\n".join(body_lines).strip()
        if parsed_results:
            result_body += "\n\n=== Parsed Results (JSON) ===\n"
            result_body += json.dumps(parsed_results, indent=2)

        return ToolResult(
            title=f"CrackMapExec {protocol}: {target}",
            body=result_body,
            mime_type="text/plain",
        )
    
    def _parse_cme_output(self, stdout: str, stderr: str, protocol: str, output_format: str) -> Dict[str, Any]:
        """Parse CrackMapExec output to extract structured data."""
        result: Dict[str, Any] = {
            "protocol": protocol,
            "users": [],
            "groups": [],
            "shares": [],
            "sessions": [],
            "policies": [],
            "interesting_findings": []
        }
        
        if output_format == "json":
            # Try to parse JSON output
            try:
                lines = stdout.splitlines()
                for line in lines:
                    if line.strip().startswith("{"):
                        data = json.loads(line)
                        if "username" in data or "user" in data:
                            result["users"].append(data)
                        if "group" in data:
                            result["groups"].append(data)
                        if "share" in data:
                            result["shares"].append(data)
            except json.JSONDecodeError:
                pass
        
        # Parse text output
        for line in stdout.splitlines():
            line_lower = line.lower()
            
            # Users
            if "user:" in line_lower or "username:" in line_lower:
                user_match = re.search(r'[Uu]ser(?:name)?:\s*([^\s]+)', line)
                if user_match:
                    result["users"].append({"username": user_match.group(1), "source": line.strip()})
            
            # Groups
            if "group:" in line_lower:
                group_match = re.search(r'[Gg]roup:\s*([^\s]+)', line)
                if group_match:
                    result["groups"].append({"group": group_match.group(1), "source": line.strip()})
            
            # Shares (SMB)
            if protocol == "smb" and ("share" in line_lower or "\\\\" in line):
                share_match = re.search(r'([A-Z]\$?|\w+)\s+.*?READ|WRITE|READ/WRITE', line, re.IGNORECASE)
                if share_match:
                    result["shares"].append({"share": share_match.group(1), "source": line.strip()})
                    # Check for writable shares
                    if "WRITE" in line.upper():
                        result["interesting_findings"].append({
                            "type": "writable_share",
                            "share": share_match.group(1),
                            "description": "Writable SMB share found"
                        })
            
            # Admin users
            if "admin" in line_lower or "administrator" in line_lower:
                result["interesting_findings"].append({
                    "type": "admin_user",
                    "description": "Administrative user detected",
                    "source": line.strip()
                })
            
            # Domain admins
            if "domain admin" in line_lower or "domain admins" in line_lower:
                result["interesting_findings"].append({
                    "type": "domain_admin",
                    "description": "Domain administrator detected",
                    "source": line.strip()
                })
        
        return result
    
    def _export_results(self, results: Dict[str, Any], output_file: str, target: str, protocol: str, output_format: str) -> Path:
        """Export results to file."""
        if output_file.strip():
            output_path = Path(output_file.strip()).expanduser()
        else:
            output_dir = user_data_dir() / "crackmapexec_results"
            output_dir.mkdir(parents=True, exist_ok=True)
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = "json" if output_format == "json" else "txt"
            output_path = output_dir / f"cme_{protocol}_{target.replace('.', '_')}_{timestamp}.{ext}"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if output_format == "json":
            output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        else:
            output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        
        return output_path
    
    def _is_truthy(self, value: str) -> bool:
        """Check if string value is truthy."""
        return value.lower() in {"1", "true", "yes", "y", "on"}



