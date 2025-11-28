"""Bulk Extractor wrapper for digital forensics extraction."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

from ..base import ToolResult


def is_bulk_extractor_available() -> bool:
    return shutil.which("bulk_extractor") is not None


class BulkExtractorProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[BulkExtractorProfile] = (
    BulkExtractorProfile(
        "quick",
        "Quick",
        "Fast extraction of common artifacts",
        ("-q", "1"),
    ),
    BulkExtractorProfile(
        "default",
        "Default",
        "Standard extraction",
        (),
    ),
    BulkExtractorProfile(
        "full",
        "Full",
        "Comprehensive extraction with all scanners",
        ("-E", "all"),
    ),
)


class BulkExtractorTool:
    name = "Bulk Extractor"
    description = "Digital forensics tool for extracting features from disk images."
    category = "Forensics"

    def run(
        self,
        input_file: str,
        profile: str = "default",
        output_dir: str = "",
        scanners: str = "",
        extra: str = "",
    ) -> ToolResult:
        if not is_bulk_extractor_available():
            raise RuntimeError("bulk_extractor not found in PATH. Install bulk_extractor locally.")
        
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
            selected_profile = PROFILE_CHOICES[1]  # default

        # Output directory
        if output_dir.strip():
            out_path = Path(output_dir.strip()).expanduser()
        else:
            out_path = input_path.parent / f"bulk_extractor_output_{input_path.stem}"
        
        out_path.mkdir(parents=True, exist_ok=True)

        args: List[str] = ["bulk_extractor", "-o", str(out_path)]

        # Add profile args
        args.extend(selected_profile.args)

        # Override scanners if specified
        if scanners.strip():
            args = [a for i, a in enumerate(args) if not (a == "-E" or (i > 0 and args[i-1] == "-E"))]
            args.extend(["-E", scanners.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Input file at the end
        args.append(str(input_path))

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
        body_lines.append(f"Output directory: {out_path}")
        body_lines.append("")
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        # List output files
        if out_path.exists():
            output_files = list(out_path.glob("*.txt"))
            if output_files:
                body_lines.append("")
                body_lines.append("Output files:")
                for f in sorted(output_files):
                    body_lines.append(f"  - {f.name}")
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0:
            raise RuntimeError(f"Bulk Extractor failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Bulk Extractor: {input_path.name}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

