"""Arjun wrapper for HTTP parameter discovery (opt-in)."""

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


def is_arjun_available() -> bool:
    return shutil.which("arjun") is not None


class ArjunProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[ArjunProfile] = (
    ArjunProfile(
        "quick",
        "Quick",
        "Fast parameter discovery",
        ("--stable",),
    ),
    ArjunProfile(
        "default",
        "Default",
        "Standard parameter discovery",
        ("--stable", "-t", "10"),
    ),
    ArjunProfile(
        "full",
        "Full",
        "Comprehensive parameter discovery",
        ("-t", "20", "--passive"),
    ),
)


class ArjunTool:
    name = "Arjun"
    description = "HTTP parameter discovery tool (opt-in)."
    category = "Web"

    def run(
        self,
        target: str,
        profile: str = "default",
        method: str = "GET",
        headers: str = "",
        delay: str = "",
        threads: str = "",
        json_data: str = "",
        xml_data: str = "",
        analyze_structure: str = "true",
        extra: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_arjun_available():
            raise RuntimeError("arjun not found in PATH. Install arjun locally.")
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

        args: List[str] = ["arjun", "-u", target.strip()]

        # Add profile args
        args.extend(selected_profile.args)

        # HTTP method
        method_upper = method.strip().upper()
        if method_upper in ["GET", "POST", "JSON", "XML"]:
            args.extend(["-m", method_upper])

        # JSON data
        if json_data.strip():
            args.extend(["-j", json_data.strip()])
            if method_upper != "JSON":
                args = [a for a in args if not (a == "-m")]
                args.extend(["-m", "JSON"])

        # XML data
        if xml_data.strip():
            args.extend(["-x", xml_data.strip()])
            if method_upper != "XML":
                args = [a for a in args if not (a == "-m")]
                args.extend(["-m", "XML"])

        # Structure analysis hint (Arjun handles this internally, but we document it)
        if _is_truthy(analyze_structure) and (json_data.strip() or xml_data.strip()):
            # Arjun automatically analyzes JSON/XML structures when -j or -x is used
            pass

        # Headers
        if headers.strip():
            for header in headers.split(";"):
                if header.strip():
                    args.extend(["--headers", header.strip()])

        # Delay
        if delay.strip():
            args.extend(["-d", delay.strip()])

        # Threads override
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
            raise RuntimeError(f"Arjun failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Arjun: {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

