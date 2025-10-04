"""Launch external disassemblers/decompilers."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from ..base import ToolResult


@dataclass(frozen=True)
class CandidateTool:
    slug: str
    label: str
    binaries: Sequence[str]
    category: str = "gui"  # gui, cli, headless
    default_args: Sequence[str] = ()
    supports_scripts: bool = False
    requires_project: bool = False


TOOLS: Sequence[CandidateTool] = (
    CandidateTool("ghidra", "Ghidra", ("ghidraRun", "ghidra"), "gui"),
    CandidateTool(
        "ghidra-headless",
        "Ghidra Headless",
        ("analyzeHeadless",),
        "headless",
        supports_scripts=True,
        requires_project=True,
    ),
    CandidateTool("ida", "IDA Pro", ("ida64", "idat64", "ida", "idat"), "gui"),
    CandidateTool("binaryninja", "Binary Ninja", ("binaryninja", "BinaryNinja"), "gui"),
    CandidateTool("hopper", "Hopper", ("hopper", "hopperv4"), "gui"),
    CandidateTool("cutter", "Cutter", ("cutter",), "gui"),
    CandidateTool(
        "rizin",
        "rizin",
        ("rizin",),
        "cli",
        ("-q", "-e", "bin.cache=true", "-e", "bin.relocs.apply=true"),
    ),
    CandidateTool(
        "radare2",
        "radare2",
        ("radare2",),
        "cli",
        ("-q", "-e", "bin.cache=true", "-e", "bin.relocs.apply=true"),
    ),
)


class DisassemblerLauncher:
    name = "Disassembler Launcher"
    description = "Kick off Ghidra, IDA, Cutter, or rizin with the selected binary."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        preferred: str = "auto",
        extra: str = "",
        workdir: str = "",
        mode: str = "auto",
        script: str = "",
        project_dir: str = "",
        list_available: str = "false",
    ) -> ToolResult:
        available = self._available_tools()
        if self._truthy(list_available):
            body = self._format_available(available)
            return ToolResult(title="Detected disassemblers", body=body)

        if not file_path.strip():
            raise ValueError("Provide a binary to launch")

        target = Path(file_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        record = self._pick_tool(preferred, mode, available)
        if record is None:
            suggestions = self._format_available(available)
            hint = self._pick_failure_hint(preferred, mode, available)
            message = "No supported disassembler was found in PATH."
            if hint:
                message += f"\n{hint}"
            message += "\n" + suggestions
            raise RuntimeError(message)

        tool, binary_path = record
        argv, raw_command, context_note, execution_mode = self._build_command(
            tool,
            binary_path,
            target,
            extra,
            script,
            project_dir,
        )

        cwd = Path(workdir).expanduser() if workdir.strip() else target.parent
        if not cwd.exists():
            cwd = target.parent

        if execution_mode == "spawn":
            try:
                subprocess.Popen(argv, cwd=str(cwd))
            except FileNotFoundError as exc:
                raise RuntimeError(f"Unable to launch {tool.label}: {exc}") from exc

            header = f"Launched {tool.label} ({Path(binary_path).name})"
            body_parts = [header]
            if context_note:
                body_parts.append(context_note)
            body_parts.append("Tool command:")
            body_parts.append(self._format_command(raw_command))
            if argv != raw_command:
                body_parts.append("Invocation:")
                body_parts.append(self._format_command(argv))
            body_parts.extend(["", self._format_available(available)])
            return ToolResult(title=header, body="\n".join(body_parts))

        # Capture output mode (CLI tools)
        result = subprocess.run(
            argv,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        output = (result.stdout or "").strip()
        errors = (result.stderr or "").strip()
        combined = output
        if errors:
            combined = f"{combined}\n\n[stderr]\n{errors}" if combined else errors
        combined = combined or "(no output)"
        header = f"Executed {tool.label} ({Path(binary_path).name})"
        body_parts = [header]
        if context_note:
            body_parts.append(context_note)
        body_parts.append("Command:")
        body_parts.append(self._format_command(raw_command))
        body_parts.append(f"Exit status: {result.returncode}")
        body_parts.append("")
        body_parts.append(combined)
        body_parts.extend(["", self._format_available(available)])
        return ToolResult(title=header, body="\n".join(body_parts))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _available_tools(self) -> List[Tuple[CandidateTool, str]]:
        discovered: List[Tuple[CandidateTool, str]] = []
        for tool in TOOLS:
            for binary in tool.binaries:
                path = shutil.which(binary)
                if path:
                    discovered.append((tool, path))
                    break
        return discovered

    def _pick_tool(
        self,
        preferred: str,
        mode: str,
        available: Sequence[Tuple[CandidateTool, str]],
    ) -> Tuple[CandidateTool, str] | None:
        normalized_preferred = preferred.strip().lower()
        normalized_mode = mode.strip().lower() or "auto"

        def _mode_filter(candidate: CandidateTool) -> bool:
            if normalized_mode in {"", "auto"}:
                return True
            if normalized_mode == "gui":
                return candidate.category == "gui"
            if normalized_mode in {"cli", "terminal"}:
                return candidate.category in {"cli", "headless"}
            if normalized_mode == "headless":
                return candidate.category == "headless"
            return True

        ordered: Iterable[Tuple[CandidateTool, str]]
        if normalized_preferred and normalized_preferred != "auto":
            ordered = [entry for entry in available if entry[0].slug == normalized_preferred]
        else:
            ordered = [entry for entry in available if _mode_filter(entry[0])]

        for entry in ordered:
            return entry
        return None

    def _pick_failure_hint(
        self,
        preferred: str,
        mode: str,
        available: Sequence[Tuple[CandidateTool, str]],
    ) -> str:
        normalized_preferred = preferred.strip().lower()
        normalized_mode = mode.strip().lower()

        lines: List[str] = []
        if normalized_preferred and normalized_preferred not in {"auto", ""}:
            slugs = {tool.slug for tool, _ in available}
            if normalized_preferred not in slugs:
                lines.append(f"Preferred tool '{preferred}' was not detected.")

        if normalized_mode in {"gui", "cli", "terminal", "headless"}:
            def _mode_filter(candidate: CandidateTool) -> bool:
                if normalized_mode == "gui":
                    return candidate.category == "gui"
                if normalized_mode in {"cli", "terminal"}:
                    return candidate.category in {"cli", "headless"}
                return candidate.category == "headless"

            matching = [tool for tool, _ in available if _mode_filter(tool)]
            if not matching:
                lines.append(f"No tools matching launch mode '{mode}' were detected; try a different mode or Auto.")

        return " ".join(lines)

    def _build_command(
        self,
        tool: CandidateTool,
        binary_path: str,
        target: Path,
        extra: str,
        script: str,
        project_dir: str,
    ) -> Tuple[List[str], List[str], str | None, str]:
        argv: List[str] = [binary_path]

        if tool.slug == "ghidra-headless":
            project_root = Path(project_dir).expanduser() if project_dir.strip() else target.parent
            project_root.mkdir(parents=True, exist_ok=True)
            project_name = target.stem
            argv = [binary_path, str(project_root), project_name, "-import", str(target)]
            if script.strip():
                script_path = Path(script).expanduser()
                if not script_path.exists():
                    raise FileNotFoundError(script_path)
                argv.extend(["-scriptPath", str(script_path.parent), "-postScript", script_path.name])
            if extra.strip():
                argv.extend(shlex.split(extra, posix=True))
            return argv, argv, None, "spawn"

        if tool.slug in {"rizin", "radare2"}:
            argv = [binary_path, *tool.default_args]
            script_note: str | None = None
            if script.strip():
                script_content = Path(script).expanduser()
                if script_content.exists():
                    argv.extend(["-i", str(script_content)])
                else:
                    argv.extend(["-c", script.strip()])
            else:
                default_commands = "aaa; s entry0; pd 128"
                argv.extend(["-c", default_commands])
                script_note = "No script provided; executed default commands: 'aaa; s entry0; pd 128'."
            argv.append(str(target))
            if extra.strip():
                argv.extend(shlex.split(extra, posix=True))
            return argv, argv, script_note, "capture"

        argv.extend(tool.default_args)
        argv.append(str(target))
        if extra.strip():
            argv.extend(shlex.split(extra, posix=True))
        return argv, argv, None, "spawn"

    def _format_available(self, available: Sequence[Tuple[CandidateTool, str]]) -> str:
        if not available:
            return "Detected tools: none"
        lines = ["Detected tools:"]
        for tool, path in sorted(available, key=lambda item: item[0].label.lower()):
            lines.append(f"• {tool.label} ({tool.slug}) -> {path}")
        return "\n".join(lines)

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _format_command(self, argv: Sequence[str]) -> str:
        return " ".join(shlex.quote(part) for part in argv)


__all__ = ["DisassemblerLauncher"]
