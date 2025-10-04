"""Generate inline disassembly previews using local tooling."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Sequence, Tuple

from ..base import ToolResult


@dataclass(frozen=True)
class PreviewBackend:
    slug: str
    label: str
    binaries: Sequence[str]
    runner: Callable[[str, Path, int, str], str]


class QuickDisassembler:
    name = "Quick Disassembly"
    description = "Render disassembly inside Cryptea using objdump, radare2, or rizin."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        preferred: str = "auto",
        max_instructions: str = "400",
        syntax: str = "auto",
    ) -> ToolResult:
        target = Path(file_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        count = self._safe_int(max_instructions, default=400, minimum=32, maximum=4096)
        syntax_choice = syntax.strip().lower()

        available = self._available_backends()
        record = self._pick_backend(preferred, available)
        if record is None:
            message = "No disassembly backend was found in PATH.\n" + self._format_available(available)
            raise RuntimeError(message)

        backend, binary_path = record
        output = backend.runner(binary_path, target, count, syntax_choice)
        trimmed = self._limit_lines(output, count * 8)
        header = f"== {backend.label} via {binary_path} =="
        body = f"{header}\n\n{trimmed.strip() or '(no disassembly output)'}"
        return ToolResult(title=f"Quick disassembly with {backend.label}", body=body)

    # ------------------------------------------------------------------
    # Backend discovery
    # ------------------------------------------------------------------
    def _available_backends(self) -> List[Tuple[PreviewBackend, str]]:
        backends = self._all_backends()
        discovered: List[Tuple[PreviewBackend, str]] = []
        for backend in backends:
            for candidate in backend.binaries:
                path = shutil.which(candidate)
                if path:
                    discovered.append((backend, path))
                    break
        return discovered

    def _all_backends(self) -> Sequence[PreviewBackend]:
        return (
            PreviewBackend("objdump", "objdump", ("objdump",), self._run_objdump),
            PreviewBackend("radare2", "radare2", ("radare2",), self._run_radare2),
            PreviewBackend("rizin", "rizin", ("rizin",), self._run_rizin),
        )

    def _pick_backend(
        self,
        preferred: str,
        available: Sequence[Tuple[PreviewBackend, str]],
    ) -> Tuple[PreviewBackend, str] | None:
        preferred_slug = preferred.strip().lower()
        ordered: Sequence[Tuple[PreviewBackend, str]]
        if preferred_slug and preferred_slug not in {"auto", ""}:
            ordered = [entry for entry in available if entry[0].slug == preferred_slug]
            if ordered:
                return ordered[0]
        if not available:
            return None
        # Auto preference order: objdump -> radare2 -> rizin
        priority = {backend.slug: idx for idx, backend in enumerate(self._all_backends())}
        return sorted(available, key=lambda entry: priority.get(entry[0].slug, 99))[0]

    # ------------------------------------------------------------------
    # Backend runners
    # ------------------------------------------------------------------
    def _run_objdump(self, binary: str, target: Path, count: int, syntax: str) -> str:
        args = [binary, "-d", str(target)]
        if syntax in {"intel", "att"}:
            args = [binary, "-M", syntax, "-d", str(target)]
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return result.stdout or result.stderr or ""

    def _run_radare2(self, binary: str, target: Path, count: int, syntax: str) -> str:
        commands = ["e bin.cache=true", "e bin.relocs.apply=true", "aaa", "s entry0", f"pd {count}"]
        if syntax == "intel":
            commands.insert(0, "e asm.syntax=intel")
        elif syntax == "att":
            commands.insert(0, "e asm.syntax=att")
        joined = "; ".join(commands)
        result = subprocess.run(
            [binary, "-q", "-c", joined, str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.stdout or result.stderr or ""

    def _run_rizin(self, binary: str, target: Path, count: int, syntax: str) -> str:
        commands = ["e bin.cache=true", "e bin.relocs.apply=true", "aaa", "s entry0", f"pd {count}"]
        if syntax == "intel":
            commands.insert(0, "e asm.syntax=intel")
        elif syntax == "att":
            commands.insert(0, "e asm.syntax=att")
        joined = "; ".join(commands)
        result = subprocess.run(
            [binary, "-q", "-c", joined, str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.stdout or result.stderr or ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _safe_int(self, value: str, default: int, minimum: int, maximum: int) -> int:
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, number))

    def _limit_lines(self, text: str, limit: int) -> str:
        if limit <= 0:
            return text
        lines = text.splitlines()
        if len(lines) <= limit:
            return "\n".join(lines)
        truncated = lines[:limit]
        truncated.append(f"... (truncated, showing first {limit} lines)")
        return "\n".join(truncated)

    def _format_available(self, available: Sequence[Tuple[PreviewBackend, str]]) -> str:
        if not available:
            return "Detected backends: none"
        lines = ["Detected backends:"]
        for backend, path in sorted(available, key=lambda entry: entry[0].label.lower()):
            lines.append(f"• {backend.label} → {path}")
        return "\n".join(lines)


__all__ = ["QuickDisassembler"]
