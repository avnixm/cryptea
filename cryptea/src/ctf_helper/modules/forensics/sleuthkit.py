"""Sleuthkit/Autopsy wrapper for disk analysis."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

from ..base import ToolResult


def is_sleuthkit_available() -> bool:
    return shutil.which("fls") is not None and shutil.which("icat") is not None


def is_autopsy_available() -> bool:
    return shutil.which("autopsy") is not None


class SleuthkitProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    command: str


PROFILE_CHOICES: Sequence[SleuthkitProfile] = (
    SleuthkitProfile(
        "mmls",
        "Partition Layout",
        "Display partition table",
        "mmls",
    ),
    SleuthkitProfile(
        "fsstat",
        "Filesystem Info",
        "Display filesystem statistics",
        "fsstat",
    ),
    SleuthkitProfile(
        "fls",
        "File Listing",
        "List files and directories",
        "fls",
    ),
    SleuthkitProfile(
        "ils",
        "Inode Listing",
        "List inode information",
        "ils",
    ),
)


class SleuthkitTool:
    name = "Sleuthkit"
    description = "Disk analysis and file system forensics tools."
    category = "Forensics"

    def run(
        self,
        image_file: str,
        profile: str = "fls",
        offset: str = "",
        inode: str = "",
        recursive: str = "0",
        deleted: str = "0",
        extra: str = "",
    ) -> ToolResult:
        if not is_sleuthkit_available():
            raise RuntimeError("sleuthkit tools not found in PATH. Install sleuthkit locally.")
        
        image_path = Path(image_file).expanduser()
        if not image_path.exists():
            raise FileNotFoundError(f"Image file not found: {image_file}")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[2]  # fls

        args: List[str] = [selected_profile.command]

        # Offset for partition
        if offset.strip():
            args.extend(["-o", offset.strip()])

        # Command-specific options
        if selected_profile.command == "fls":
            if _is_truthy(recursive):
                args.append("-r")
            if _is_truthy(deleted):
                args.append("-d")
        elif selected_profile.command == "ils":
            if _is_truthy(deleted):
                args.append("-e")

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Image file
        args.append(str(image_path))

        # Inode for fls
        if inode.strip() and selected_profile.command == "fls":
            args.append(inode.strip())

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
            raise RuntimeError(f"Sleuthkit failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Sleuthkit {selected_profile.command}: {image_path.name}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

