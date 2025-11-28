"""System call tracer using strace/ltrace."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

from ..base import ToolResult


def is_strace_available() -> bool:
    return shutil.which("strace") is not None


def is_ltrace_available() -> bool:
    return shutil.which("ltrace") is not None


class SyscallTracerProfile(NamedTuple):
    """Declarative description for a preset trace profile."""

    profile_id: str
    label: str
    description: str
    tool: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[SyscallTracerProfile] = (
    SyscallTracerProfile(
        "strace_basic",
        "Strace Basic",
        "Basic system call trace",
        "strace",
        (),
    ),
    SyscallTracerProfile(
        "strace_full",
        "Strace Full",
        "Detailed system call trace with timestamps",
        "strace",
        ("-tt", "-T", "-v"),
    ),
    SyscallTracerProfile(
        "strace_file",
        "Strace File Operations",
        "Trace file operations only",
        "strace",
        ("-e", "trace=file"),
    ),
    SyscallTracerProfile(
        "strace_network",
        "Strace Network",
        "Trace network operations only",
        "strace",
        ("-e", "trace=network"),
    ),
    SyscallTracerProfile(
        "ltrace_basic",
        "Ltrace Basic",
        "Basic library call trace",
        "ltrace",
        (),
    ),
    SyscallTracerProfile(
        "ltrace_full",
        "Ltrace Full",
        "Detailed library call trace with timestamps",
        "ltrace",
        ("-tt", "-T"),
    ),
)


class SyscallTracerTool:
    name = "Syscall Tracer"
    description = "Trace system calls and library calls (strace/ltrace)."
    category = "Reverse"

    def run(
        self,
        binary_file: str,
        profile: str = "strace_basic",
        arguments: str = "",
        follow_forks: str = "0",
        extra: str = "",
    ) -> ToolResult:
        binary_path = Path(binary_file).expanduser()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_file}")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[0]  # strace_basic

        tool = selected_profile.tool

        # Check if tool is available
        if tool == "strace" and not is_strace_available():
            raise RuntimeError("strace not found in PATH. Install strace locally.")
        elif tool == "ltrace" and not is_ltrace_available():
            raise RuntimeError("ltrace not found in PATH. Install ltrace locally.")

        args: List[str] = [tool]

        # Add profile args
        args.extend(selected_profile.args)

        # Follow forks
        if _is_truthy(follow_forks):
            args.append("-f")

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Binary and its arguments
        args.append(str(binary_path))
        if arguments.strip():
            args.extend(arguments.split())

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,  # 1 minute timeout
        )

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        
        # strace/ltrace output goes to stderr by default
        if proc.stderr.strip():
            body_lines.append("Trace Output:")
            body_lines.append(proc.stderr.strip())
        
        if proc.stdout.strip():
            body_lines.append("")
            body_lines.append("Program Output:")
            body_lines.append(proc.stdout.strip())

        return ToolResult(
            title=f"{tool}: {binary_path.name}",
            body="\n".join(body_lines),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

