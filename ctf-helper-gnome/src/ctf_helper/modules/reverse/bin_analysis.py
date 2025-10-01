"""Offline binary triage helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List

from ..base import ToolResult


class StringsExtractTool:
    name = "Extract Strings"
    description = "Run the local `strings` utility (if available) to inspect ASCII data."
    category = "Reverse"

    def run(self, file_path: str, min_length: str = "4") -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        binary = shutil.which("strings")
        if binary:
            result = subprocess.run(
                [binary, f"-n{min_length}", str(path)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            output = result.stdout or result.stderr
        else:
            output = path.read_bytes().decode("latin-1", errors="ignore")
        return ToolResult(title=f"Strings from {path.name}", body=output)
