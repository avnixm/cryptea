"""Checksec wrapper for binary security property checking."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List

from ..base import ToolResult


def is_checksec_available() -> bool:
    return shutil.which("checksec") is not None


def is_pwntools_available() -> bool:
    """Check if pwntools is available (has checksec functionality)."""
    try:
        import pwn  # type: ignore
        return True
    except ImportError:
        return False


class ChecksecTool:
    name = "Checksec"
    description = "Check binary security properties (NX, PIE, RELRO, etc.)."
    category = "Reverse"

    def run(
        self,
        binary_file: str,
        output_format: str = "text",
        extra: str = "",
    ) -> ToolResult:
        binary_path = Path(binary_file).expanduser()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_file}")

        result_lines: List[str] = []
        result_lines.append(f"Binary: {binary_path.name}")
        result_lines.append("")

        # Try checksec command first
        if is_checksec_available():
            args: List[str] = ["checksec", "--file", str(binary_path)]
            
            if output_format == "json":
                args.append("--output=json")
            
            if extra.strip():
                args.extend(extra.split())

            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )

            result_lines.append(f"Command: {' '.join(args)}")
            result_lines.append("")
            
            if proc.stdout.strip():
                result_lines.append("Security Properties:")
                result_lines.append(proc.stdout.strip())
            
            if proc.stderr.strip():
                result_lines.append("")
                result_lines.append("Errors/Warnings:")
                result_lines.append(proc.stderr.strip())

        # Fallback to pwntools if checksec not available
        elif is_pwntools_available():
            try:
                from pwn import ELF  # type: ignore
                
                result_lines.append("Using pwntools for checksec analysis:")
                result_lines.append("")
                
                elf = ELF(str(binary_path), checksec=False)
                
                result_lines.append("Security Properties:")
                result_lines.append(f"  Architecture: {elf.arch}")
                result_lines.append(f"  Bits: {elf.bits}")
                result_lines.append(f"  Endianness: {elf.endian}")
                result_lines.append(f"  NX (No Execute): {elf.nx}")
                result_lines.append(f"  PIE (Position Independent): {elf.pie}")
                result_lines.append(f"  Canary: {elf.canary}")
                result_lines.append(f"  RELRO: {elf.relro}")
                result_lines.append(f"  RPATH: {elf.rpath}")
                result_lines.append(f"  RUNPATH: {elf.runpath}")
                
            except Exception as e:
                result_lines.append(f"Error using pwntools: {str(e)}")
        
        else:
            raise RuntimeError("Neither checksec nor pwntools is available. Install one of them.")

        return ToolResult(
            title=f"Checksec: {binary_path.name}",
            body="\n".join(result_lines),
            mime_type="text/plain",
        )

