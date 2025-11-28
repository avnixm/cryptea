"""Foremost wrapper for file carving from disk images."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

from ..base import ToolResult


def is_foremost_available() -> bool:
    return shutil.which("foremost") is not None


class ForemostProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[ForemostProfile] = (
    ForemostProfile(
        "all",
        "All Types",
        "Carve all supported file types",
        ("-t", "all"),
    ),
    ForemostProfile(
        "images",
        "Images",
        "Carve image files (jpg, png, gif, bmp)",
        ("-t", "jpg,png,gif,bmp"),
    ),
    ForemostProfile(
        "documents",
        "Documents",
        "Carve document files (pdf, doc, xls, ppt)",
        ("-t", "pdf,doc,xls,ppt"),
    ),
    ForemostProfile(
        "archives",
        "Archives",
        "Carve archive files (zip, rar, gz)",
        ("-t", "zip,rar,gz"),
    ),
    ForemostProfile(
        "executables",
        "Executables",
        "Carve executable files (exe, elf)",
        ("-t", "exe,elf"),
    ),
)


class ForemostTool:
    name = "Foremost"
    description = "File carving tool for recovering files from disk images."
    category = "Forensics"

    def run(
        self,
        input_file: str,
        profile: str = "all",
        output_dir: str = "",
        file_types: str = "",
        extra: str = "",
    ) -> ToolResult:
        if not is_foremost_available():
            raise RuntimeError("foremost not found in PATH. Install foremost locally.")
        
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
            selected_profile = PROFILE_CHOICES[0]  # all

        # Output directory
        if output_dir.strip():
            out_path = Path(output_dir.strip()).expanduser()
        else:
            out_path = input_path.parent / f"foremost_output_{input_path.stem}"
        
        out_path.mkdir(parents=True, exist_ok=True)

        args: List[str] = ["foremost", "-i", str(input_path), "-o", str(out_path)]

        # Add profile args
        args.extend(selected_profile.args)

        # Override file types if specified
        if file_types.strip():
            args = [a for i, a in enumerate(args) if not (a == "-t" or (i > 0 and args[i-1] == "-t"))]
            args.extend(["-t", file_types.strip()])

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
        body_lines.append(f"Output directory: {out_path}")
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
            raise RuntimeError(f"Foremost failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Foremost: {input_path.name}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

