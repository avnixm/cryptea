"""Pwntools helper for CTF exploit development."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

from ..base import ToolResult


def is_pwntools_available() -> bool:
    """Check if pwntools is available via Python."""
    try:
        import pwn  # type: ignore
        return True
    except ImportError:
        return False


class PwntoolsProfile(NamedTuple):
    """Declarative description for a preset operation."""

    profile_id: str
    label: str
    description: str
    operation: str


PROFILE_CHOICES: Sequence[PwntoolsProfile] = (
    PwntoolsProfile(
        "cyclic",
        "Cyclic Pattern",
        "Generate cyclic pattern for buffer overflow",
        "cyclic",
    ),
    PwntoolsProfile(
        "cyclic_find",
        "Find Cyclic Offset",
        "Find offset in cyclic pattern",
        "cyclic_find",
    ),
    PwntoolsProfile(
        "asm",
        "Assemble",
        "Assemble shellcode",
        "asm",
    ),
    PwntoolsProfile(
        "disasm",
        "Disassemble",
        "Disassemble shellcode",
        "disasm",
    ),
)


class PwntoolsHelperTool:
    name = "Pwntools Helper"
    description = "CTF exploit development utilities from pwntools."
    category = "Reverse"

    def run(
        self,
        profile: str = "cyclic",
        length: str = "100",
        value: str = "",
        arch: str = "i386",
        extra: str = "",
    ) -> ToolResult:
        if not is_pwntools_available():
            raise RuntimeError("pwntools not installed. Install with: pip install pwntools")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[0]  # cyclic

        operation = selected_profile.operation
        result_lines: List[str] = []
        result_lines.append(f"Operation: {selected_profile.label}")
        result_lines.append("")

        try:
            if operation == "cyclic":
                # Generate cyclic pattern
                from pwn import cyclic  # type: ignore
                pattern_len = int(length) if length.strip() else 100
                pattern = cyclic(pattern_len)
                result_lines.append(f"Cyclic pattern ({pattern_len} bytes):")
                result_lines.append(pattern.decode("latin-1"))
                result_lines.append("")
                result_lines.append("Hex:")
                result_lines.append(pattern.hex())

            elif operation == "cyclic_find":
                # Find offset in cyclic pattern
                from pwn import cyclic_find  # type: ignore
                if not value.strip():
                    raise ValueError("Value is required for cyclic_find")
                
                # Try to parse value as hex or int
                if value.strip().startswith("0x"):
                    search_val = int(value.strip(), 16)
                else:
                    try:
                        search_val = int(value.strip())
                    except ValueError:
                        # Treat as string
                        search_val = value.strip().encode()
                
                offset = cyclic_find(search_val)
                result_lines.append(f"Search value: {value}")
                result_lines.append(f"Offset: {offset}")

            elif operation == "asm":
                # Assemble shellcode
                from pwn import asm, context  # type: ignore
                if not value.strip():
                    raise ValueError("Assembly code is required")
                
                context.arch = arch.strip() or "i386"
                shellcode = asm(value.strip())
                result_lines.append(f"Architecture: {context.arch}")
                result_lines.append(f"Assembly: {value.strip()}")
                result_lines.append("")
                result_lines.append("Shellcode (hex):")
                result_lines.append(shellcode.hex())
                result_lines.append("")
                result_lines.append("Shellcode (bytes):")
                result_lines.append(repr(shellcode))

            elif operation == "disasm":
                # Disassemble shellcode
                from pwn import disasm, context  # type: ignore
                if not value.strip():
                    raise ValueError("Hex shellcode is required")
                
                context.arch = arch.strip() or "i386"
                shellcode_bytes = bytes.fromhex(value.strip().replace("\\x", ""))
                disassembly = disasm(shellcode_bytes)
                result_lines.append(f"Architecture: {context.arch}")
                result_lines.append(f"Shellcode: {value.strip()}")
                result_lines.append("")
                result_lines.append("Disassembly:")
                result_lines.append(disassembly)

        except Exception as e:
            result_lines.append(f"Error: {str(e)}")

        return ToolResult(
            title=f"Pwntools: {selected_profile.label}",
            body="\n".join(result_lines),
            mime_type="text/plain",
        )

