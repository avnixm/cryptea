"""Scalpel wrapper for file carving with configuration presets."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

from ..base import ToolResult


def is_scalpel_available() -> bool:
    return shutil.which("scalpel") is not None


class ScalpelProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    comment: str


PROFILE_CHOICES: Sequence[ScalpelProfile] = (
    ScalpelProfile(
        "images",
        "Images",
        "Carve image files",
        "jpg,png,gif,bmp",
    ),
    ScalpelProfile(
        "documents",
        "Documents",
        "Carve document files",
        "pdf,doc,xls,ppt",
    ),
    ScalpelProfile(
        "archives",
        "Archives",
        "Carve archive files",
        "zip,rar,gz,tar",
    ),
    ScalpelProfile(
        "all",
        "All Types",
        "Carve all configured file types",
        "all",
    ),
)


class ScalpelTool:
    name = "Scalpel"
    description = "Fast file carving tool with configuration support."
    category = "Forensics"

    def run(
        self,
        input_file: str,
        profile: str = "all",
        output_dir: str = "",
        config_file: str = "",
        extra: str = "",
    ) -> ToolResult:
        if not is_scalpel_available():
            raise RuntimeError("scalpel not found in PATH. Install scalpel locally.")
        
        input_path = Path(input_file).expanduser()
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[3]  # all

        # Output directory
        if output_dir.strip():
            out_path = Path(output_dir.strip()).expanduser()
        else:
            out_path = input_path.parent / f"scalpel_output_{input_path.stem}"
        
        out_path.mkdir(parents=True, exist_ok=True)

        args: List[str] = ["scalpel"]

        # Config file
        if config_file.strip():
            conf_path = Path(config_file.strip()).expanduser()
            if conf_path.exists():
                args.extend(["-c", str(conf_path)])
        else:
            # Use default config (usually /etc/scalpel/scalpel.conf)
            default_conf = Path("/etc/scalpel/scalpel.conf")
            if default_conf.exists():
                args.extend(["-c", str(default_conf)])

        # Output directory
        args.extend(["-o", str(out_path)])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Input file
        args.append(str(input_path))

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
        body_lines.append(f"Output directory: {out_path}")
        body_lines.append(f"Profile: {selected_profile.label} ({selected_profile.comment})")
        body_lines.append("")
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        # Check audit.txt for summary
        audit_file = out_path / "audit.txt"
        if audit_file.exists():
            body_lines.append("")
            body_lines.append("Audit Summary:")
            body_lines.append(audit_file.read_text())
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0:
            raise RuntimeError(f"Scalpel failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Scalpel: {input_path.name}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

