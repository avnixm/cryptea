"""Hydra wrapper for network login brute-forcing (opt-in)."""

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


def is_hydra_available() -> bool:
    return shutil.which("hydra") is not None


class HydraProfile(NamedTuple):
    """Declarative description for a preset protocol profile."""

    profile_id: str
    label: str
    description: str
    protocol: str


PROFILE_CHOICES: Sequence[HydraProfile] = (
    HydraProfile("ssh", "SSH", "SSH login brute-force", "ssh"),
    HydraProfile("ftp", "FTP", "FTP login brute-force", "ftp"),
    HydraProfile("http-get", "HTTP GET", "HTTP GET authentication brute-force", "http-get"),
    HydraProfile("http-post", "HTTP POST", "HTTP POST form brute-force", "http-post-form"),
    HydraProfile("smb", "SMB", "SMB/Windows share brute-force", "smb"),
    HydraProfile("rdp", "RDP", "RDP login brute-force", "rdp"),
    HydraProfile("mysql", "MySQL", "MySQL database login", "mysql"),
    HydraProfile("postgresql", "PostgreSQL", "PostgreSQL database login", "postgres"),
    HydraProfile("mssql", "MSSQL", "Microsoft SQL Server login", "mssql"),
    HydraProfile("pop3", "POP3", "POP3 email login", "pop3"),
    HydraProfile("imap", "IMAP", "IMAP email login", "imap"),
    HydraProfile("smtp", "SMTP", "SMTP authentication", "smtp"),
    HydraProfile("telnet", "Telnet", "Telnet login", "telnet"),
    HydraProfile("vnc", "VNC", "VNC remote desktop", "vnc"),
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
        stop_on_success: str = "false",
        delay: str = "0",
        retry: str = "3",
        timeout: str = "30",
        ssh_key: str = "",
        ssh_cipher: str = "",
        http_form: str = "",
        http_cookie: str = "",
        smb_domain: str = "",
        rdp_domain: str = "",
        parse_results: str = "true",
        export_results: str = "false",
        output_file: str = "",
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

        # Stop on first success
        if self._is_truthy(stop_on_success):
            args.append("-f")

        # Delay between attempts
        if delay.strip() and int(delay) > 0:
            args.extend(["-w", delay.strip()])

        # Timeout
        if timeout.strip():
            args.extend(["-W", timeout.strip()])

        # Protocol-specific options
        if profile == "ssh":
            if ssh_key.strip():
                args.extend(["-I", ssh_key.strip()])  # Key file
            if ssh_cipher.strip():
                args.extend(["-C", ssh_cipher.strip()])  # Cipher
        
        elif profile in ["http-post", "http-get"]:
            if http_form.strip():
                args.append(http_form.strip())  # Form fields
            if http_cookie.strip():
                args.extend(["-C", http_cookie.strip()])  # Cookie
        
        elif profile == "smb":
            if smb_domain.strip():
                args.extend(["-m", smb_domain.strip()])  # Domain
        
        elif profile == "rdp":
            if rdp_domain.strip():
                args.extend(["-d", rdp_domain.strip()])  # Domain/workgroup

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

        # Parse results
        parsed_results: Dict[str, Any] = {}
        if self._is_truthy(parse_results):
            parsed_results = self._parse_hydra_output(proc.stdout, proc.stderr)

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        body_lines.append("WARNING: Use only on systems you own or have permission to test!")
        body_lines.append("")
        
        # Summary
        if parsed_results:
            body_lines.append("=== Summary ===")
            body_lines.append(f"Successful logins: {len(parsed_results.get('credentials', []))}")
            body_lines.append(f"Total attempts: {parsed_results.get('total_attempts', 'unknown')}")
            body_lines.append(f"Success rate: {parsed_results.get('success_rate', '0')}%")
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
            export_path = self._export_results(parsed_results, output_file, target, protocol)
            body_lines.append("")
            body_lines.append(f"Results exported to: {export_path}")

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"Hydra failed: {proc.stderr.strip()}")

        # Include parsed results in JSON if available
        result_body = "\n".join(body_lines).strip()
        if parsed_results:
            result_body += "\n\n=== Parsed Results (JSON) ===\n"
            result_body += json.dumps(parsed_results, indent=2)

        return ToolResult(
            title=f"Hydra {protocol}: {target}",
            body=result_body,
            mime_type="text/plain",
        )
    
    def _parse_hydra_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Hydra output to extract credentials and statistics."""
        credentials: List[Dict[str, str]] = []
        total_attempts = 0
        
        # Pattern for successful login: [protocol] host:port login: password
        # Example: [22][ssh] host: 192.168.1.1   login: admin   password: password123
        success_pattern = re.compile(
            r'\[(\d+)\]\[(\w+)\]\s+host:\s+([^\s]+)\s+login:\s+([^\s]+)\s+password:\s+(.+)',
            re.IGNORECASE
        )
        
        for line in stdout.splitlines():
            match = success_pattern.search(line)
            if match:
                credentials.append({
                    "port": match.group(1),
                    "protocol": match.group(2),
                    "host": match.group(3),
                    "username": match.group(4),
                    "password": match.group(5).strip()
                })
            
            # Count attempts (lines with "attempts" or "tries")
            if "attempt" in line.lower() or "tries" in line.lower():
                numbers = re.findall(r'\d+', line)
                if numbers:
                    total_attempts = max(total_attempts, int(numbers[-1]))
        
        success_rate = 0.0
        if total_attempts > 0:
            success_rate = round((len(credentials) / total_attempts) * 100, 2)
        
        return {
            "credentials": credentials,
            "total_attempts": total_attempts if total_attempts > 0 else len(credentials),
            "successful_logins": len(credentials),
            "success_rate": success_rate,
            "failed": len(credentials) == 0
        }
    
    def _export_results(self, results: Dict[str, Any], output_file: str, target: str, protocol: str) -> Path:
        """Export results to file."""
        if output_file.strip():
            output_path = Path(output_file.strip()).expanduser()
        else:
            output_dir = user_data_dir() / "hydra_results"
            output_dir.mkdir(parents=True, exist_ok=True)
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = output_dir / f"hydra_{protocol}_{target.replace('.', '_')}_{timestamp}.json"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        return output_path
    
    def _is_truthy(self, value: str) -> bool:
        """Check if string value is truthy."""
        return value.lower() in {"1", "true", "yes", "y", "on"}

