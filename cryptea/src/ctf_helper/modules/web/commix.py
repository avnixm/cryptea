"""Commix wrapper for command injection exploitation (opt-in)."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import List, NamedTuple, Sequence

from ..base import ToolResult
from ...data_paths import user_config_dir


CONSENT_FILE = user_config_dir() / "network_consent.json"


def network_consent_enabled() -> bool:
    try:
        if not CONSENT_FILE.exists():
            return False
        data = json.loads(CONSENT_FILE.read_text())
        return bool(data.get("enabled", False))
    except Exception:
        return False


def is_commix_available() -> bool:
    return shutil.which("commix") is not None


class CommixProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[CommixProfile] = (
    CommixProfile(
        "quick",
        "Quick",
        "Fast detection scan",
        ("--level=1", "--batch"),
    ),
    CommixProfile(
        "default",
        "Default",
        "Standard detection and exploitation",
        ("--level=2", "--batch"),
    ),
    CommixProfile(
        "full",
        "Full",
        "Comprehensive scan with all techniques",
        ("--level=3", "--batch", "--all"),
    ),
)


class CommixTool:
    name = "Commix"
    description = "Command injection exploitation tool (opt-in)."
    category = "Web"

    def run(
        self,
        target: str,
        profile: str = "default",
        method: str = "GET",
        data: str = "",
        cookie: str = "",
        headers: str = "",
        level: str = "",
        os_detection: str = "true",
        shell: str = "",
        injection_points: str = "parameter",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_commix_available():
            raise RuntimeError("commix not found in PATH. Install commix locally.")
        if not target.strip():
            raise ValueError("Target URL is required")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[1]  # default

        args: List[str] = ["commix", "--url", target.strip()]

        # Add profile args
        args.extend(selected_profile.args)

        # HTTP method
        if method.strip().upper() in ["POST", "PUT", "DELETE"]:
            args.extend(["--method", method.strip().upper()])

        # POST data
        if data.strip():
            args.extend(["--data", data.strip()])

        # Cookie
        if cookie.strip():
            args.extend(["--cookie", cookie.strip()])

        # Headers
        if headers.strip():
            for header in headers.split(";"):
                if header.strip():
                    args.extend(["--headers", header.strip()])

        # OS detection
        if _is_truthy(os_detection):
            args.append("--os-cmd")

        # Shell selection
        if shell.strip() in ["bash", "sh", "cmd", "powershell"]:
            args.extend(["--shellshock", "--os-cmd", shell.strip()])

        # Injection points
        if injection_points.strip():
            if "header" in injection_points.lower():
                args.append("--header")
            if "cookie" in injection_points.lower():
                args.append("--cookie")

        # Level override
        if level.strip():
            args = [a for a in args if not a.startswith("--level=")]
            args.append(f"--level={level.strip()}")

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
            raise RuntimeError(f"Commix failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Commix: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

