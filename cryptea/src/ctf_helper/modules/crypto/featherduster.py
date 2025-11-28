"""Featherduster wrapper for automated cryptanalysis."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List

from ..base import ToolResult


def is_featherduster_available() -> bool:
    return shutil.which("featherduster") is not None


class FeatherDusterTool:
    name = "FeatherDuster"
    description = "Automated cryptanalysis tool for breaking weak encryption."
    category = "Crypto"

    def run(
        self,
        ciphertext: str,
        input_file: str = "",
        analysis_only: str = "0",
        extra: str = "",
    ) -> ToolResult:
        if not is_featherduster_available():
            raise RuntimeError("featherduster not found in PATH. Install featherduster locally.")

        args: List[str] = ["featherduster"]

        # Input from file or direct ciphertext
        if input_file.strip():
            file_path = Path(input_file.strip()).expanduser()
            if not file_path.exists():
                raise FileNotFoundError(f"Input file not found: {input_file}")
            args.extend(["-f", str(file_path)])
        elif ciphertext.strip():
            # Create temporary file for ciphertext
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
                tmp.write(ciphertext.strip())
                tmp_path = tmp.name
            args.extend(["-f", tmp_path])
        else:
            raise ValueError("Either ciphertext or input_file must be provided")

        # Analysis only mode
        if _is_truthy(analysis_only):
            args.append("--analysis-only")

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
            raise RuntimeError(f"FeatherDuster failed: {proc.stderr.strip()}")

        return ToolResult(
            title="FeatherDuster Cryptanalysis",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

