"""Nikto wrapper for web server vulnerability scanning (opt-in)."""

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


def is_nikto_available() -> bool:
    return shutil.which("nikto") is not None


class NiktoProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[NiktoProfile] = (
    NiktoProfile(
        "quick",
        "Quick",
        "Fast scan with basic tests",
        ("-Tuning", "1,2,3", "-maxtime", "5m"),
    ),
    NiktoProfile(
        "default",
        "Default",
        "Standard vulnerability scan",
        ("-Tuning", "x", "-maxtime", "10m"),
    ),
    NiktoProfile(
        "full",
        "Full",
        "Comprehensive scan with all tests",
        ("-Tuning", "0", "-maxtime", "30m"),
    ),
    NiktoProfile(
        "stealth",
        "Stealth",
        "Slow, evasive scan",
        ("-Tuning", "x", "-maxtime", "20m", "-Pause", "2"),
    ),
)


class NiktoTool:
    name = "Nikto"
    description = "Web server vulnerability scanner (opt-in)."
    category = "Network"

    def run(
        self,
        target: str,
        profile: str = "default",
        port: str = "80",
        ssl: str = "0",
        tuning: str = "",
        output_format: str = "text",
        categorize_findings: str = "true",
        risk_assessment: str = "true",
        analyze_headers: str = "true",
        http_methods: str = "",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_nikto_available():
            raise RuntimeError("nikto not found in PATH. Install nikto locally.")
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

        args: List[str] = ["nikto", "-h", target]

        # Add profile args
        args.extend(selected_profile.args)

        # Port
        if port.strip():
            args.extend(["-p", port.strip()])

        # SSL
        if _is_truthy(ssl):
            args.append("-ssl")
        
        # Output format
        output_format_lower = output_format.lower().strip()
        if output_format_lower == "xml":
            output_file = user_data_dir() / "nikto_reports" / f"nikto_{target.replace('/', '_')}.xml"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            args.extend(["-Format", "xml", "-output", str(output_file)])
        elif output_format_lower == "csv":
            output_file = user_data_dir() / "nikto_reports" / f"nikto_{target.replace('/', '_')}.csv"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            args.extend(["-Format", "csv", "-output", str(output_file)])
        elif output_format_lower == "json":
            output_file = user_data_dir() / "nikto_reports" / f"nikto_{target.replace('/', '_')}.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            args.extend(["-Format", "json", "-output", str(output_file)])

        # Tuning override
        if tuning.strip():
            args = [a for i, a in enumerate(args) if not (a == "-Tuning" or (i > 0 and args[i-1] == "-Tuning"))]
            args.extend(["-Tuning", tuning.strip()])
        
        # HTTP methods
        if http_methods.strip():
            methods = http_methods.strip().upper()
            args.extend(["-maxtime", "10m", "-C", "all"])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1800,  # 30 minute timeout
        )

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        
        stdout_text = proc.stdout.strip()
        
        # Parse and categorize findings
        if stdout_text and self._is_truthy(categorize_findings):
            categorized = self._categorize_findings(stdout_text)
            if categorized:
                body_lines.append("Categorized Findings:")
                body_lines.append(json.dumps(categorized, indent=2))
                body_lines.append("")
        
        # Risk assessment
        if stdout_text and self._is_truthy(risk_assessment):
            risk = self._assess_risk(stdout_text)
            if risk:
                body_lines.append("Risk Assessment:")
                body_lines.append(json.dumps(risk, indent=2))
                body_lines.append("")
        
        # Header analysis
        if stdout_text and self._is_truthy(analyze_headers):
            headers = self._analyze_headers(stdout_text)
            if headers:
                body_lines.append("Security Headers Analysis:")
                body_lines.append(json.dumps(headers, indent=2))
                body_lines.append("")
        
        if stdout_text:
            body_lines.append("Results:")
            body_lines.append(stdout_text)
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not stdout_text:
            raise RuntimeError(f"Nikto failed: {proc.stderr.strip()}")

        mime_type = "application/json" if self._is_truthy(categorize_findings) else "text/plain"
        
        return ToolResult(
            title=f"Nikto scan: {target}",
            body="\n".join(body_lines).strip(),
            mime_type=mime_type,
        )
    
    def _categorize_findings(self, output: str) -> Dict[str, List[str]]:
        """Categorize Nikto findings."""
        outdated: List[str] = []
        misconfigs: List[str] = []
        defaults: List[str] = []
        disclosure: List[str] = []
        other: List[str] = []
        
        lines = output.splitlines()
        for line in lines:
            line_lower = line.lower()
            
            # Outdated software patterns
            if any(keyword in line_lower for keyword in ["outdated", "version", "old version", "deprecated"]):
                outdated.append(line.strip())
            # Misconfigurations
            elif any(keyword in line_lower for keyword in ["misconfiguration", "unnecessary", "exposed", "enabled"]):
                misconfigs.append(line.strip())
            # Default files
            elif any(keyword in line_lower for keyword in ["default", "test", "sample", "example"]):
                defaults.append(line.strip())
            # Information disclosure
            elif any(keyword in line_lower for keyword in ["disclosure", "information", "leak", "reveal"]):
                disclosure.append(line.strip())
            else:
                if line.strip() and not line.startswith("-"):
                    other.append(line.strip())
        
        return {
            "outdated_software": outdated,
            "misconfigurations": misconfigs,
            "default_files": defaults,
            "information_disclosure": disclosure,
            "other": other,
        }
    
    def _assess_risk(self, output: str) -> Dict[str, object]:
        """Assess risk levels of findings."""
        high: List[str] = []
        medium: List[str] = []
        low: List[str] = []
        
        high_keywords = ["exploit", "vulnerability", "cve-", "xss", "sql injection", "rce", "remote code"]
        medium_keywords = ["misconfiguration", "outdated", "information disclosure", "weak"]
        low_keywords = ["info", "header", "default"]
        
        lines = output.splitlines()
        for line in lines:
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in high_keywords):
                high.append(line.strip())
            elif any(keyword in line_lower for keyword in medium_keywords):
                medium.append(line.strip())
            elif any(keyword in line_lower for keyword in low_keywords):
                low.append(line.strip())
        
        return {
            "high": high,
            "medium": medium,
            "low": low,
            "summary": {
                "high_count": len(high),
                "medium_count": len(medium),
                "low_count": len(low),
            },
        }
    
    def _analyze_headers(self, output: str) -> Dict[str, object]:
        """Analyze security headers from Nikto output."""
        missing: List[str] = []
        present: List[str] = []
        recommendations: List[str] = []
        
        security_headers = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "X-XSS-Protection",
        ]
        
        output_upper = output.upper()
        for header in security_headers:
            if header.upper() in output_upper:
                present.append(header)
            else:
                missing.append(header)
        
        if missing:
            recommendations.append("Consider implementing missing security headers")
        
        return {
            "missing_headers": missing,
            "present_headers": present,
            "recommendations": recommendations,
        }
    
    def _is_truthy(self, value: str) -> bool:
        return value.lower() in {"1", "true", "yes", "y", "on"}


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

