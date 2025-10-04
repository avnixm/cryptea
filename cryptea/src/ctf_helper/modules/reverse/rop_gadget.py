"""ROP gadget helper leveraging local tooling."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple

from ..base import ToolResult


class ROPGadgetTool:
    name = "ROP Gadget Finder"
    description = "Enumerate ROP gadgets using ROPgadget/ropper/rizin if present."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        search: str = "",
        max_depth: str = "6",
        tool: str = "auto",
        architecture: str = "auto",
        limit: str = "0",
    ) -> ToolResult:
        target = Path(file_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        tools = self._resolve_tools(tool)
        if not tools:
            raise RuntimeError("Neither ROPgadget, ropper, nor rizin were found in PATH")

        depth_value = self._safe_int(max_depth, default=6, minimum=1, maximum=40)
        limit_value = self._safe_int(limit, default=0, minimum=0, maximum=1000)
        arch_key, arch_meta = self._normalise_architecture(architecture)

        sections: List[str] = []
        for slug, executor in tools:
            try:
                output = executor(target, search, depth_value, arch_key, arch_meta, limit_value)
            except FileNotFoundError:
                continue
            label = self._tool_label(slug)
            trimmed = self._limit_output(output, limit_value)
            sections.append(f"== {label} ==\n{trimmed.strip() or '(no output)'}")

        body = "\n\n".join(sections) if sections else "No output produced by the selected tools."
        title = f"ROP results for {target.name}"
        return ToolResult(title=title, body=body)

    def _resolve_tools(self, tool_request: str) -> List[Tuple[str, Callable[..., str]]]:
        request = tool_request.strip().lower()
        available = {
            "ropgadget": self._ropgadget,
            "ropper": self._ropper,
            "rizin": self._rizin,
        }

        discovered = {
            slug: func
            for slug, func in available.items()
            if self._is_tool_available(slug)
        }

        if not discovered:
            return []

        if not request or request == "auto":
            # Prefer GUI friendly -> CLI ordering
            for preferred in ("ropgadget", "ropper", "rizin"):
                if preferred in discovered:
                    return [(preferred, discovered[preferred])]
            return []

        selections: List[str] = []
        if "all" in request:
            selections = list(discovered.keys())
        else:
            for part in (segment.strip() for segment in request.split(",")):
                if not part:
                    continue
                if part in {"rop", "ropg"}:
                    part = "ropgadget"
                if part in {"rz", "radare2"}:
                    part = "rizin"
                if part in discovered and part not in selections:
                    selections.append(part)

        if not selections:
            return []
        return [(slug, discovered[slug]) for slug in selections]

    def _is_tool_available(self, slug: str) -> bool:
        if slug == "ropgadget":
            return shutil.which("ROPgadget") is not None
        if slug == "ropper":
            return shutil.which("ropper") is not None
        if slug == "rizin":
            return shutil.which("rizin") is not None or shutil.which("radare2") is not None
        return False

    def _tool_label(self, slug: str) -> str:
        return {
            "ropgadget": "ROPgadget",
            "ropper": "ropper",
            "rizin": "rizin",
        }.get(slug, slug)

    def _ropgadget(
        self,
        target: Path,
        search: str,
        depth: int,
        arch_key: str,
        arch_meta: Dict[str, str],
        limit: int,
    ) -> str:
        binary = shutil.which("ROPgadget")
        if not binary:
            raise FileNotFoundError("ROPgadget")
        argv = [binary, "--binary", str(target), "--depth", str(depth)]
        if search.strip():
            argv += ["--filter", search.strip()]
        if arch_key != "auto":
            argv += ["--arch", arch_key]
        if limit:
            argv += ["--limit", str(limit)]
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.stdout or result.stderr or "(no output)"

    def _ropper(
        self,
        target: Path,
        search: str,
        depth: int,
        arch_key: str,
        arch_meta: Dict[str, str],
        limit: int,
    ) -> str:
        binary = shutil.which("ropper")
        if not binary:
            raise FileNotFoundError("ropper")
        argv = [binary, "--file", str(target), "--nocolor", "--depth", str(depth)]
        if search.strip():
            argv += ["--search", search.strip()]
        if arch_key != "auto":
            argv += ["--arch", arch_meta.get("ropper_arch", arch_key)]
            if arch_meta.get("bits"):
                argv += ["--bits", str(arch_meta["bits"])]
        if limit:
            argv += ["--limit", str(limit)]
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.stdout or result.stderr or "(no output)"

    def _rizin(
        self,
        target: Path,
        search: str,
        depth: int,
        arch_key: str,
        arch_meta: Dict[str, str],
        limit: int,
    ) -> str:
        binary = shutil.which("rizin") or shutil.which("radare2")
        if not binary:
            raise FileNotFoundError("rizin")
        commands: List[str] = ["aaa"]
        if arch_key != "auto":
            if arch_meta.get("rizin_arch"):
                commands.append(f"e asm.arch={arch_meta['rizin_arch']}")
            if arch_meta.get("bits"):
                commands.append(f"e asm.bits={arch_meta['bits']}")
        if search.strip():
            commands.append(f"/R {search.strip()}")
        else:
            commands.append("/R")
        commands.append("q")
        joined = ";".join(commands)
        argv = [binary, "-q", "-c", joined, str(target)]
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.stdout or result.stderr or "(no output)"

    def _normalise_architecture(self, architecture: str) -> Tuple[str, Dict[str, str]]:
        value = architecture.strip().lower()
        if not value or value == "auto":
            return "auto", {}

        mapping = {
            "x86": {"ropper_arch": "x86", "bits": 32, "rizin_arch": "x86"},
            "i386": {"ropper_arch": "x86", "bits": 32, "rizin_arch": "x86"},
            "x64": {"ropper_arch": "x86", "bits": 64, "rizin_arch": "x86"},
            "amd64": {"ropper_arch": "x86", "bits": 64, "rizin_arch": "x86"},
            "x86_64": {"ropper_arch": "x86", "bits": 64, "rizin_arch": "x86"},
            "arm": {"ropper_arch": "arm", "bits": 32, "rizin_arch": "arm"},
            "arm32": {"ropper_arch": "arm", "bits": 32, "rizin_arch": "arm"},
            "arm64": {"ropper_arch": "arm", "bits": 64, "rizin_arch": "arm64"},
            "aarch64": {"ropper_arch": "arm", "bits": 64, "rizin_arch": "arm64"},
            "mips": {"ropper_arch": "mips", "bits": 32, "rizin_arch": "mips"},
            "mips64": {"ropper_arch": "mips", "bits": 64, "rizin_arch": "mips"},
            "riscv": {"ropper_arch": "riscv", "bits": 32, "rizin_arch": "riscv"},
            "riscv64": {"ropper_arch": "riscv", "bits": 64, "rizin_arch": "riscv"},
        }
        meta = mapping.get(value)
        if meta is None:
            return "auto", {}
        return value if value != "x86_64" else "x86_64", meta

    def _safe_int(self, value: str, default: int, minimum: int, maximum: int) -> int:
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, number))

    def _limit_output(self, text: str, limit: int) -> str:
        if limit <= 0:
            return text
        lines = text.splitlines()
        if len(lines) <= limit:
            return text
        truncated = lines[:limit]
        truncated.append(f"... (truncated, showing first {limit} lines)")
        return "\n".join(truncated)


__all__ = ["ROPGadgetTool"]
