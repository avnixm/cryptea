"""Lightweight wrapper around rizin/radare2."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from ..base import ToolResult

_DEFAULT_COMMANDS = ["aaa", "s main", "pdf @ main"]


class RizinConsole:
    name = "Radare/Rizin Console"
    description = "Run scripted rizin (or radare2) commands against a binary."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        commands: str = "",
        tool: str = "auto",
        quiet: str = "true",
    ) -> ToolResult:
        target = Path(file_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        binary = self._select_tool(tool)
        if not binary:
            raise RuntimeError("rizin or radare2 not found in PATH")

        cmd_list = self._normalize_commands(commands)
        flag = "-q" if self._truthy(quiet) else "-Q"
        joined = ";".join(cmd_list)
        argv = [binary, flag, "-c", joined, str(target)]
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        output = result.stdout or result.stderr
        title = f"{Path(binary).name} output ({len(cmd_list)} commands)"
        return ToolResult(title=title, body=output or "(no output)")

    def _normalize_commands(self, commands: str) -> Sequence[str]:
        items = [line.strip() for line in commands.splitlines() if line.strip()]
        if not items:
            return _DEFAULT_COMMANDS
        return items

    def _select_tool(self, requested: str) -> str | None:
        requested = requested.strip().lower()
        order: Sequence[str]
        if requested in {"rizin", "rz"}:
            order = ["rizin"]
        elif requested in {"radare2", "r2"}:
            order = ["radare2"]
        else:
            order = ["rizin", "radare2"]
        for binary in order:
            path = shutil.which(binary)
            if path:
                return path
        return None

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}


__all__ = ["RizinConsole"]
