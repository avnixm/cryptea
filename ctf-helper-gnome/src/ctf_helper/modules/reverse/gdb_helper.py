"""Batch-mode helpers for gdb execution."""

from __future__ import annotations

import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, List

from ..base import ToolResult

_DEFAULT_COMMANDS = ["info registers", "backtrace", "info shared"]


class GDBHelper:
    name = "GDB Runner"
    description = "Execute scripted gdb sessions with optional breakpoints and memory dumps."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        breakpoints: str = "",
        run_args: str = "",
        commands: str = "",
        stop_on_entry: str = "false",
        attach_pid: str = "",
        additional_files: str = "",
    ) -> ToolResult:
        binary = shutil.which("gdb")
        if not binary:
            raise RuntimeError("gdb is not available in PATH")

        target = Path(file_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        script_lines = self._build_script(
            breakpoints=breakpoints,
            commands=commands,
            run_args=run_args,
            stop_on_entry=stop_on_entry,
            attach_pid=attach_pid,
            additional_files=additional_files,
        )

        with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as script:
            script.write("\n".join(script_lines))
            script_path = script.name

        argv = [binary, "-q", str(target)]
        if attach_pid.strip():
            argv += ["-p", attach_pid.strip()]
        argv += ["-x", script_path]

        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        title = f"gdb session for {target.name}"
        return ToolResult(title=title, body=output.strip() or "(no output)")

    def _build_script(
        self,
        breakpoints: str,
        commands: str,
        run_args: str,
        stop_on_entry: str,
        attach_pid: str,
        additional_files: str,
    ) -> List[str]:
        lines: List[str] = ["set pagination off"]
        if self._truthy(stop_on_entry):
            lines.append("set stop-on-solib-events 1")
        for bp in self._split_lines(breakpoints):
            lines.append(f"break {bp}")
        if additional_files.strip():
            for path in self._split_lines(additional_files):
                lines.append(f"add-symbol-file {path}")
        if attach_pid.strip():
            lines.append(f"attach {attach_pid.strip()}")
        if run_args.strip():
            quoted = " ".join(shlex.quote(arg) for arg in shlex.split(run_args))
            lines.append(f"set args {quoted}")
        default_cmds = _DEFAULT_COMMANDS if not commands.strip() else self._split_lines(commands)
        for cmd in default_cmds:
            lines.append(cmd)
        lines.append("quit")
        return lines

    def _split_lines(self, blob: str) -> List[str]:
        return [line.strip() for line in blob.splitlines() if line.strip()]

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}


__all__ = ["GDBHelper"]
