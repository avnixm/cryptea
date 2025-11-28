"""Medusa wrapper for parallel network brute-forcing (opt-in)."""

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


def is_medusa_available() -> bool:
    return shutil.which("medusa") is not None


class MedusaProfile(NamedTuple):
    """Declarative description for a preset protocol profile."""

    profile_id: str
    label: str
    description: str
    module: str


PROFILE_CHOICES: Sequence[MedusaProfile] = (
    MedusaProfile("ssh", "SSH", "SSH login brute-force", "ssh"),
    MedusaProfile("ftp", "FTP", "FTP login brute-force", "ftp"),
    MedusaProfile("http", "HTTP", "HTTP authentication brute-force", "http"),
    MedusaProfile("smb", "SMB", "SMB/Windows share brute-force", "smbnt"),
    MedusaProfile("telnet", "Telnet", "Telnet login brute-force", "telnet"),
    MedusaProfile("mssql", "MSSQL", "Microsoft SQL Server", "mssql"),
    MedusaProfile("postgresql", "PostgreSQL", "PostgreSQL database", "postgres"),
    MedusaProfile("mysql", "MySQL", "MySQL database", "mysql"),
    MedusaProfile("pop3", "POP3", "POP3 email", "pop3"),
    MedusaProfile("imap", "IMAP", "IMAP email", "imap"),
    MedusaProfile("smtp", "SMTP", "SMTP authentication", "smtp"),
)


class MedusaTool:
    name = "Medusa"
    description = "Parallel network brute-forcer (opt-in, use responsibly)."
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
        resume: str = "false",
        output_format: str = "text",
        parse_results: str = "true",
        export_results: str = "false",
        output_file: str = "",
        module_options: str = "",
        batch_size: str = "100",
        delay: str = "0",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_medusa_available():
            raise RuntimeError("medusa not found in PATH. Install medusa locally.")
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

        module = selected_profile.module

        args: List[str] = ["medusa", "-h", target.strip(), "-M", module]

        # Username/password or lists
        if username.strip():
            args.extend(["-u", username.strip()])
        elif user_list.strip():
            user_path = Path(user_list.strip()).expanduser()
            if not user_path.exists():
                raise FileNotFoundError(f"User list not found: {user_list}")
            args.extend(["-U", str(user_path)])
        else:
            # Use default username list if available
            default_users = Path(user_data_dir()) / "SecLists" / "common.txt"
            if default_users.exists():
                args.extend(["-U", str(default_users)])
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
            args.extend(["-n", port.strip()])

        # Threads
        if threads.strip():
            args.extend(["-t", threads.strip()])

        # Stop on first success
        if self._is_truthy(stop_on_success):
            args.append("-f")

        # Resume capability
        if self._is_truthy(resume):
            args.append("-R")

        # Output format
        if output_format == "json":
            args.append("-j")
        elif output_format == "csv":
            args.append("-c")

        # Module-specific options
        if module_options.strip():
            args.extend(["-M", module_options.strip()])

        # Batch size for optimization
        if batch_size.strip():
            args.extend(["-b", batch_size.strip()])

        # Delay between attempts
        if delay.strip() and int(delay) > 0:
            args.extend(["-d", delay.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

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
            parsed_results = self._parse_medusa_output(proc.stdout, proc.stderr, output_format)

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
            body_lines.append(f"Failed attempts: {parsed_results.get('failed_attempts', 0)}")
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
            export_path = self._export_results(parsed_results, output_file, target, module, output_format)
            body_lines.append("")
            body_lines.append(f"Results exported to: {export_path}")

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"Medusa failed: {proc.stderr.strip()}")

        # Include parsed results in JSON if available
        result_body = "\n".join(body_lines).strip()
        if parsed_results:
            result_body += "\n\n=== Parsed Results (JSON) ===\n"
            result_body += json.dumps(parsed_results, indent=2)

        return ToolResult(
            title=f"Medusa {module}: {target}",
            body=result_body,
            mime_type="text/plain",
        )
    
    def _parse_medusa_output(self, stdout: str, stderr: str, output_format: str) -> Dict[str, Any]:
        """Parse Medusa output to extract credentials and statistics."""
        credentials: List[Dict[str, str]] = []
        total_attempts = 0
        failed_attempts = 0
        
        if output_format == "json":
            # Try to parse JSON output
            try:
                lines = stdout.splitlines()
                for line in lines:
                    if line.strip().startswith("{"):
                        data = json.loads(line)
                        if "SUCCESS" in str(data).upper() or "ACCOUNT FOUND" in str(data).upper():
                            credentials.append({
                                "host": data.get("host", ""),
                                "username": data.get("user", ""),
                                "password": data.get("pass", ""),
                                "status": "SUCCESS"
                            })
            except json.JSONDecodeError:
                pass
        
        # Pattern for successful login in text output
        # Example: ACCOUNT FOUND: [ssh] Host: 192.168.1.1 User: admin Password: password123
        success_pattern = re.compile(
            r'ACCOUNT\s+FOUND:\s+\[(\w+)\]\s+Host:\s+([^\s]+)\s+User:\s+([^\s]+)\s+Password:\s+(.+)',
            re.IGNORECASE
        )
        
        for line in stdout.splitlines():
            match = success_pattern.search(line)
            if match:
                credentials.append({
                    "protocol": match.group(1),
                    "host": match.group(2),
                    "username": match.group(3),
                    "password": match.group(4).strip()
                })
            
            # Count attempts
            if "attempt" in line.lower() or "tries" in line.lower():
                numbers = re.findall(r'\d+', line)
                if numbers:
                    total_attempts = max(total_attempts, int(numbers[-1]))
            
            # Count failures
            if "FAILED" in line.upper() or "ERROR" in line.upper():
                failed_attempts += 1
        
        success_rate = 0.0
        if total_attempts > 0:
            success_rate = round((len(credentials) / total_attempts) * 100, 2)
        
        return {
            "credentials": credentials,
            "total_attempts": total_attempts if total_attempts > 0 else len(credentials),
            "successful_logins": len(credentials),
            "failed_attempts": failed_attempts,
            "success_rate": success_rate,
            "failed": len(credentials) == 0
        }
    
    def _export_results(self, results: Dict[str, Any], output_file: str, target: str, module: str, output_format: str) -> Path:
        """Export results to file."""
        if output_file.strip():
            output_path = Path(output_file.strip()).expanduser()
        else:
            output_dir = user_data_dir() / "medusa_results"
            output_dir.mkdir(parents=True, exist_ok=True)
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = "json" if output_format == "json" else "csv" if output_format == "csv" else "txt"
            output_path = output_dir / f"medusa_{module}_{target.replace('.', '_')}_{timestamp}.{ext}"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if output_format == "json":
            output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        elif output_format == "csv":
            # Simple CSV export
            lines = ["host,username,password,protocol"]
            for cred in results.get("credentials", []):
                lines.append(f"{cred.get('host', '')},{cred.get('username', '')},{cred.get('password', '')},{cred.get('protocol', '')}")
            output_path.write_text("\n".join(lines), encoding="utf-8")
        else:
            output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        
        return output_path
    
    def _is_truthy(self, value: str) -> bool:
        """Check if string value is truthy."""
        return value.lower() in {"1", "true", "yes", "y", "on"}

