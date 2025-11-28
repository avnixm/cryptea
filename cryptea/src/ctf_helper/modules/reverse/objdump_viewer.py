"""User-friendly objdump viewer for binary analysis."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ..base import ToolResult


class ObjdumpViewerTool:
    """Standalone objdump viewer with section viewer, symbol table, disassembly, and relocations."""

    name = "objdump Viewer"
    description = "User-friendly viewer for objdump output showing sections, symbol tables, imports, disassembly, and relocations."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        view_type: str = "sections",
        function: str = "",
        address_range: str = "",
        syntax: str = "intel",
        max_lines: str = "1000",
    ) -> ToolResult:
        """View objdump output in various formats.
        
        Args:
            file_path: Path to binary file
            view_type: Type of view (sections, symbols, disassembly, relocations, all)
            function: Specific function to view (for disassembly)
            address_range: Address range in format "start-end" (for disassembly)
            syntax: Assembly syntax (intel or att)
            max_lines: Maximum lines to display
        """
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        if not shutil.which("objdump"):
            raise RuntimeError(
                "objdump not found in PATH. Install with:\n"
                "  Fedora/RHEL: sudo dnf install binutils\n"
                "  Ubuntu/Debian: sudo apt install binutils\n"
                "  Arch: sudo pacman -S binutils"
            )

        view = view_type.strip().lower() or "sections"
        max_output = max(100, min(5000, int(max_lines or "1000")))
        syntax_choice = syntax.strip().lower()
        if syntax_choice not in {"intel", "att"}:
            syntax_choice = "intel"

        results: Dict[str, object] = {}
        
        if view in {"sections", "all"}:
            results["sections"] = self._view_sections(path, max_output)
        
        if view in {"symbols", "all"}:
            results["symbols"] = self._view_symbols(path, max_output)
        
        if view in {"disassembly", "all"}:
            results["disassembly"] = self._view_disassembly(
                path, function, address_range, syntax_choice, max_output
            )
        
        if view in {"relocations", "all"}:
            results["relocations"] = self._view_relocations(path, max_output)

        body = json.dumps(results, indent=2)
        return ToolResult(
            title=f"objdump Viewer: {path.name}",
            body=body,
            mime_type="application/json",
        )

    def _view_sections(self, path: Path, max_lines: int) -> Dict[str, object]:
        """View section headers and information."""
        try:
            proc = subprocess.run(
                ["objdump", "-h", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            
            output = proc.stdout or ""
            sections: List[Dict[str, object]] = []
            lines = output.splitlines()
            
            data_started = False
            for line in lines:
                if "Idx Name" in line or "Sections:" in line:
                    data_started = True
                    continue
                if not data_started or not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 7:
                    sections.append({
                        "idx": parts[0],
                        "name": parts[1],
                        "size": parts[2],
                        "vma": parts[3],
                        "lma": parts[4],
                        "file_off": parts[5],
                        "align": parts[6] if len(parts) > 6 else "",
                        "flags": " ".join(parts[7:]) if len(parts) > 7 else "",
                    })

            return {
                "sections": sections[:max_lines // 5],  # Rough limit
                "count": len(sections),
                "raw_output": output[:5000],
            }
        except Exception as e:
            return {"error": str(e)}

    def _view_symbols(self, path: Path, max_lines: int) -> Dict[str, object]:
        """View symbol tables (imports, exports, defined symbols)."""
        result: Dict[str, object] = {
            "imports": [],
            "exports": [],
            "defined": [],
        }
        
        # Get dynamic symbols (imports)
        try:
            proc = subprocess.run(
                ["objdump", "-T", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            
            output = proc.stdout or ""
            lines = output.splitlines()
            
            for line in lines[2:]:  # Skip header
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 7:
                    symbol_type = parts[0]
                    value = parts[1]
                    size = parts[2] if len(parts) > 2 else ""
                    bind = parts[3] if len(parts) > 3 else ""
                    vis = parts[4] if len(parts) > 4 else ""
                    ndx = parts[5] if len(parts) > 5 else ""
                    name = " ".join(parts[6:]) if len(parts) > 6 else ""
                    
                    symbol_info = {
                        "type": symbol_type,
                        "value": value,
                        "size": size,
                        "bind": bind,
                        "vis": vis,
                        "ndx": ndx,
                        "name": name,
                    }
                    
                    if "UND" in ndx:
                        result["imports"].append(symbol_info)
                    elif name:
                        result["exports"].append(symbol_info)
        except Exception:
            pass
        
        # Get defined symbols
        try:
            proc = subprocess.run(
                ["objdump", "-t", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            
            output = proc.stdout or ""
            lines = output.splitlines()
            
            for line in lines[2:]:  # Skip header
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    value = parts[0]
                    flags = parts[1]
                    section = parts[2]
                    size = parts[3] if len(parts) > 3 else ""
                    name = " ".join(parts[4:]) if len(parts) > 4 else ""
                    
                    if name and name not in ["", ".text", ".data", ".bss"]:
                        result["defined"].append({
                            "value": value,
                            "flags": flags,
                            "section": section,
                            "size": size,
                            "name": name,
                        })
        except Exception:
            pass
        
        # Limit results
        result["imports"] = result["imports"][:max_lines // 3]
        result["exports"] = result["exports"][:max_lines // 3]
        result["defined"] = result["defined"][:max_lines // 3]
        
        return result

    def _view_disassembly(
        self,
        path: Path,
        function: str,
        address_range: str,
        syntax: str,
        max_lines: int,
    ) -> Dict[str, object]:
        """View disassembly output."""
        args = ["objdump", "-d", "-C"]  # -C for demangling
        if syntax == "intel":
            args.extend(["-M", "intel"])
        elif syntax == "att":
            args.extend(["-M", "att"])
        
        # Add function or address range filtering
        if function.strip():
            args.extend(["--disassemble", function.strip()])
        elif address_range.strip():
            args.extend(["--start-address", address_range.split("-")[0]])
            if "-" in address_range:
                end_addr = address_range.split("-")[1]
                args.extend(["--stop-address", end_addr])
        
        args.append(str(path))
        
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            
            output = proc.stdout or ""
            lines = output.splitlines()
            
            # Parse disassembly into functions
            functions: List[Dict[str, object]] = []
            current_func: Optional[Dict[str, object]] = None
            current_instructions: List[str] = []
            
            for line in lines:
                # Detect function start
                if "<" in line and ">:" in line:
                    if current_func:
                        current_func["instructions"] = current_instructions
                        functions.append(current_func)
                    
                    func_match = re.search(r'<([^>]+)>', line)
                    func_name = func_match.group(1) if func_match else ""
                    addr_match = re.search(r'([0-9a-fA-F]+):', line)
                    addr = addr_match.group(1) if addr_match else ""
                    
                    current_func = {
                        "name": func_name,
                        "address": addr,
                        "instructions": [],
                    }
                    current_instructions = []
                
                # Add instruction lines
                if current_func and line.strip():
                    current_instructions.append(line.strip())
            
            if current_func:
                current_func["instructions"] = current_instructions
                functions.append(current_func)
            
            # Limit output
            if len(functions) > max_lines // 20:
                functions = functions[:max_lines // 20]
            
            return {
                "functions": functions,
                "function_count": len(functions),
                "raw_output": output[:10000],
                "syntax": syntax,
            }
        except Exception as e:
            return {"error": str(e)}

    def _view_relocations(self, path: Path, max_lines: int) -> Dict[str, object]:
        """View relocation tables."""
        try:
            proc = subprocess.run(
                ["objdump", "-r", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            
            output = proc.stdout or ""
            relocations: List[Dict[str, object]] = []
            lines = output.splitlines()
            
            for line in lines:
                if not line.strip() or "OFFSET" in line:
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    relocations.append({
                        "offset": parts[0],
                        "type": parts[1] if len(parts) > 1 else "",
                        "value": " ".join(parts[2:]) if len(parts) > 2 else "",
                    })

            return {
                "relocations": relocations[:max_lines],
                "count": len(relocations),
                "raw_output": output[:5000],
            }
        except Exception as e:
            return {"error": str(e)}


__all__ = ["ObjdumpViewerTool"]

