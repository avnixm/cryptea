"""Generate inline disassembly previews using local tooling."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

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
        function: str = "",
        address_range: str = "",
        analyze_flow: str = "false",
    ) -> ToolResult:
        target = Path(file_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        count = self._safe_int(max_instructions, default=400, minimum=32, maximum=4096)
        syntax_choice = syntax.strip().lower()
        func_name = function.strip()
        addr_range = address_range.strip()
        flow_analysis = self._truthy(analyze_flow)

        available = self._available_backends()
        record = self._pick_backend(preferred, available)
        if record is None:
            message = "No disassembly backend was found in PATH.\n" + self._format_available(available)
            raise RuntimeError(message)

        backend, binary_path = record
        
        # Get function list if needed
        functions = []
        if func_name or flow_analysis:
            functions = self._get_function_list(target)
        
        # Disassemble
        if func_name:
            output = self._disassemble_function(binary_path, target, func_name, count, syntax_choice, backend)
        elif addr_range:
            output = self._disassemble_range(binary_path, target, addr_range, count, syntax_choice, backend)
        else:
            output = backend.runner(binary_path, target, count, syntax_choice)
        
        trimmed = self._limit_lines(output, count * 8)
        
        # Analyze control flow if requested
        flow_info: Optional[Dict[str, object]] = None
        if flow_analysis and output:
            flow_info = self._analyze_code_flow(output)
        
        # Build result
        result_parts: List[str] = []
        result_parts.append(f"== {backend.label} via {binary_path} ==")
        result_parts.append("")
        result_parts.append(trimmed.strip() or '(no disassembly output)')
        
        if flow_info:
            result_parts.append("")
            result_parts.append("== Control Flow Analysis ==")
            result_parts.append(json.dumps(flow_info, indent=2))
        
        if functions and (func_name or flow_analysis):
            result_parts.append("")
            result_parts.append(f"== Available Functions ({len(functions)}) ==")
            result_parts.append("\n".join(functions[:50]))  # Limit display
        
        body = "\n".join(result_parts)
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
    # Enhanced disassembly methods
    # ------------------------------------------------------------------
    def _get_function_list(self, target: Path) -> List[str]:
        """Get list of functions from binary."""
        functions: List[str] = []
        
        # Try objdump first
        if shutil.which("objdump"):
            try:
                proc = subprocess.run(
                    ["objdump", "-t", str(target)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                
                if proc.stdout:
                    for line in proc.stdout.splitlines():
                        # Match function symbols (typically in .text section)
                        if ".text" in line or " F " in line:
                            # Extract function name
                            parts = line.split()
                            if len(parts) >= 6:
                                func_name = parts[-1]
                                if func_name and not func_name.startswith("."):
                                    functions.append(func_name)
            except Exception:
                pass
        
        return sorted(set(functions))

    def _disassemble_function(
        self,
        binary: str,
        target: Path,
        func_name: str,
        count: int,
        syntax: str,
        backend: PreviewBackend,
    ) -> str:
        """Disassemble a specific function."""
        if backend.slug == "objdump":
            args = [binary, "-d", "-C", str(target)]
            if syntax in {"intel", "att"}:
                args = [binary, "-M", syntax, "-d", "-C", str(target)]
            
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            
            if proc.stdout:
                # Extract function from objdump output
                lines = proc.stdout.splitlines()
                in_function = False
                result_lines: List[str] = []
                
                for line in lines:
                    if func_name in line and "<" in line and ">:" in line:
                        in_function = True
                    if in_function:
                        result_lines.append(line)
                        # Stop at next function or after count instructions
                        if len(result_lines) > count * 2 and ("<" in line and ">:" in line and func_name not in line):
                            break
                
                return "\n".join(result_lines)
        
        # Fallback to backend runner
        return backend.runner(binary, target, count, syntax)

    def _disassemble_range(
        self,
        binary: str,
        target: Path,
        addr_range: str,
        count: int,
        syntax: str,
        backend: PreviewBackend,
    ) -> str:
        """Disassemble an address range."""
        # Parse address range (format: "start-end" or "start")
        parts = addr_range.split("-")
        start_addr = parts[0].strip()
        end_addr = parts[1].strip() if len(parts) > 1 else ""
        
        if backend.slug == "objdump":
            args = [binary, "-d", "-C", "--start-address", start_addr]
            if end_addr:
                args.extend(["--stop-address", end_addr])
            args.append(str(target))
            
            if syntax in {"intel", "att"}:
                args.insert(1, "-M")
                args.insert(2, syntax)
            
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            
            return proc.stdout or proc.stderr or ""
        
        # Fallback
        return backend.runner(binary, target, count, syntax)

    def _analyze_code_flow(self, disassembly: str) -> Dict[str, object]:
        """Analyze control flow from disassembly."""
        flow: Dict[str, object] = {
            "branches": [],
            "calls": [],
            "jumps": [],
            "returns": [],
        }
        
        lines = disassembly.splitlines()
        
        # Common jump/call patterns
        jump_patterns = [
            r'\b(jmp|jne|je|jz|jnz|jl|jg|jle|jge|ja|jb|jae|jbe|jcxz|jecxz|jrcxz)\b',
            r'\b(call|ret|retn|retf)\b',
        ]
        
        for line in lines:
            line_lower = line.lower()
            
            # Detect calls
            if re.search(r'\bcall\b', line_lower):
                target_match = re.search(r'call\s+([0-9a-fA-Fx]+|<[^>]+>)', line)
                if target_match:
                    flow["calls"].append({
                        "line": line.strip(),
                        "target": target_match.group(1),
                    })
            
            # Detect jumps
            if re.search(r'\bjmp\b|\bj[a-z]{1,3}\b', line_lower):
                target_match = re.search(r'j[a-z]{1,3}\s+([0-9a-fA-Fx]+|<[^>]+>)', line)
                if target_match:
                    flow["jumps"].append({
                        "line": line.strip(),
                        "target": target_match.group(1),
                    })
            
            # Detect returns
            if re.search(r'\bret\b', line_lower):
                flow["returns"].append(line.strip())
        
        flow["branch_count"] = len(flow["jumps"]) + len(flow["calls"])
        flow["total_control_flow"] = flow["branch_count"] + len(flow["returns"])
        
        return flow

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

    def _truthy(self, value: str | bool | None) -> bool:
        """Check if value is truthy."""
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}


__all__ = ["QuickDisassembler"]
