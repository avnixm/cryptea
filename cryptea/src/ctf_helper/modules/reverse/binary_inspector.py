"""Aggregate binary metadata via system tooling."""

from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from ..base import ToolResult


class BinaryInspector:
    name = "PE/ELF Inspector"
    description = "Collect headers, sections, symbols, and security flags using local toolchain programs."
    category = "Reverse"

    def run(
        self,
        file_path: str,
        include_sections: str = "true",
        include_symbols: str = "true",
        include_checksec: str = "true",
        include_file: str = "true",
        include_headers: str = "true",
        include_segments: str = "false",
        include_dynamic: str = "false",
        include_libraries: str = "false",
        include_strings: str = "false",
        strings_min_length: str = "4",
        max_lines: str = "400",
        include_imports: str = "false",
        include_exports: str = "false",
        output_format: str = "text",
    ) -> ToolResult:
        target = Path(file_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        limit = self._safe_int(max_lines, default=400, minimum=50, maximum=2000)
        string_min = self._safe_int(strings_min_length, default=4, minimum=2, maximum=32)
        output_fmt = output_format.strip().lower() or "text"
        
        # Detect file type
        file_type = self._detect_file_type(target)
        is_pe = file_type == "PE"
        is_elf = file_type == "ELF"

        # Collect data
        data: Dict[str, object] = {
            "file": str(target.resolve()),
            "file_type": file_type,
        }
        
        snippets: List[str] = []
        
        if self._truthy(include_file):
            file_info = self._run_tool("file", ["file", str(target)], limit=limit, fallback="file utility not found")
            snippets.append(file_info)
            data["file_info"] = file_info.replace("== file ==\n", "")

        if self._truthy(include_headers):
            headers = self._collect_headers(target, limit)
            snippets.append(headers)
            if is_pe:
                pe_headers = self._parse_pe_headers(target)
                if pe_headers:
                    data["pe_headers"] = pe_headers

        if self._truthy(include_segments):
            segments = self._collect_segments(target, limit)
            snippets.append(segments)
            data["segments"] = segments.replace("== readelf -l ==\n", "")

        if self._truthy(include_sections):
            sections = self._collect_sections(target, limit)
            snippets.append(sections)
            section_data = self._parse_sections(target, is_pe)
            if section_data:
                data["sections"] = section_data

        if self._truthy(include_symbols):
            symbols = self._collect_symbols(target, limit)
            snippets.append(symbols)
            symbol_data = self._parse_symbols(target)
            if symbol_data:
                data["symbols"] = symbol_data

        if self._truthy(include_imports) and is_pe:
            imports_data = self._parse_pe_imports(target)
            if imports_data:
                data["imports"] = imports_data
                snippets.append(f"== PE Imports ==\n{json.dumps(imports_data, indent=2)}")

        if self._truthy(include_exports) and is_pe:
            exports_data = self._parse_pe_exports(target)
            if exports_data:
                data["exports"] = exports_data
                snippets.append(f"== PE Exports ==\n{json.dumps(exports_data, indent=2)}")

        if self._truthy(include_dynamic):
            dynamic = self._collect_dynamic(target, limit)
            snippets.append(dynamic)
            data["dynamic"] = dynamic.replace("== readelf -d ==\n", "")

        if self._truthy(include_checksec):
            checksec_output = self._collect_checksec(target, limit)
            snippets.append(checksec_output)
            security_data = self._parse_security_features(target, checksec_output)
            if security_data:
                data["security"] = security_data

        if self._truthy(include_libraries):
            libraries = self._collect_libraries(target, limit)
            snippets.append(libraries)
            data["libraries"] = libraries.replace("== ldd ==\n", "")

        if self._truthy(include_strings):
            strings = self._collect_strings(target, string_min, limit)
            snippets.append(strings)
            data["strings"] = strings.replace("== strings", "").strip()

        # Format output
        if output_fmt == "json":
            body = json.dumps(data, indent=2)
            mime = "application/json"
        else:
            body = "\n\n".join(filter(None, snippets)) or "(no data collected)"
            mime = "text/plain"

        return ToolResult(
            title=f"Inspector results for {target.name}",
            body=body,
            mime_type=mime,
        )

    def _collect_headers(self, target: Path, limit: int) -> str:
        if shutil.which("readelf"):
            return self._run_tool("readelf -h", ["readelf", "-h", str(target)], limit=limit)
        if shutil.which("objdump"):
            return self._run_tool("objdump -f", ["objdump", "-f", str(target)], limit=limit)
        return "Headers: readelf/objdump not found"

    def _collect_segments(self, target: Path, limit: int) -> str:
        if shutil.which("readelf"):
            return self._run_tool("readelf -l", ["readelf", "-l", str(target)], limit=limit)
        return "Segments: readelf not found"

    def _collect_sections(self, target: Path, limit: int) -> str:
        if shutil.which("readelf"):
            return self._run_tool("readelf -S", ["readelf", "-S", str(target)], limit=limit)
        if shutil.which("objdump"):
            return self._run_tool("objdump -h", ["objdump", "-h", str(target)], limit=limit)
        return "Sections: readelf/objdump not found"

    def _collect_symbols(self, target: Path, limit: int) -> str:
        outputs: List[str] = []
        if shutil.which("nm"):
            outputs.append(self._run_tool("nm -g", ["nm", "-g", str(target)], limit=limit))
            outputs.append(self._run_tool("nm -D", ["nm", "-D", str(target)], limit=limit))
        elif shutil.which("objdump"):
            outputs.append(self._run_tool("objdump -t", ["objdump", "-t", str(target)], limit=limit))
        else:
            return "Symbols: nm/objdump not found"
        return "\n\n".join(filter(None, outputs))

    def _collect_dynamic(self, target: Path, limit: int) -> str:
        if shutil.which("readelf"):
            return self._run_tool("readelf -d", ["readelf", "-d", str(target)], limit=limit)
        if shutil.which("objdump"):
            return self._run_tool("objdump -p", ["objdump", "-p", str(target)], limit=limit)
        return "Dynamic section: readelf/objdump not found"

    def _collect_checksec(self, target: Path, limit: int) -> str:
        if shutil.which("checksec"):
            return self._run_tool("checksec", ["checksec", "--file", str(target)], limit=limit)
        if shutil.which("hardening-check"):
            return self._run_tool("hardening-check", ["hardening-check", str(target)], limit=limit)
        return "Security flags: checksec/hardening-check not found"

    def _collect_libraries(self, target: Path, limit: int) -> str:
        if shutil.which("ldd"):
            return self._run_tool("ldd", ["ldd", str(target)], limit=limit)
        if shutil.which("otool"):
            return self._run_tool("otool -L", ["otool", "-L", str(target)], limit=limit)
        return "Linked libraries: ldd/otool not found"

    def _collect_strings(self, target: Path, min_length: int, limit: int) -> str:
        if shutil.which("strings"):
            output = self._run_tool(
                f"strings -n {min_length}",
                ["strings", "-a", "-n", str(min_length), str(target)],
                limit=limit,
            )
            return output
        # Fallback to a simple Python-based extractor
        try:
            data = target.read_bytes()
        except OSError as exc:
            return f"Strings: unable to read file ({exc})"

        printable = set(range(32, 127)) | {9, 10, 13}
        current: List[str] = []
        results: List[str] = []
        for byte in data:
            if byte in printable:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    results.append("".join(current))
                current = []
        if len(current) >= min_length:
            results.append("".join(current))

        formatted = "\n".join(results) or "(no strings found)"
        trimmed = self._limit_lines(formatted, limit)
        return f"== strings (built-in) ==\n{trimmed}"

    def _run_tool(
        self,
        label: str,
        argv: List[str],
        limit: int,
        fallback: str | None = None,
    ) -> str:
        if not shutil.which(Path(argv[0]).name):
            return fallback or f"{label}: tool not found"
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        output = result.stdout or result.stderr or ""
        trimmed = self._limit_lines(output.strip(), limit)
        return f"== {label} ==\n{trimmed}"

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

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
            return text
        truncated = lines[:limit]
        truncated.append(f"... (truncated, showing first {limit} lines)")
        return "\n".join(truncated)

    def _detect_file_type(self, path: Path) -> str:
        """Detect if file is PE, ELF, or other."""
        try:
            with path.open("rb") as fh:
                header = fh.read(16)
                
                # Check for PE signature (MZ header)
                if header[:2] == b"MZ":
                    # Check for PE signature at offset 0x3C
                    try:
                        fh.seek(0x3C)
                        pe_offset_bytes = fh.read(4)
                        if len(pe_offset_bytes) == 4:
                            pe_offset = struct.unpack("<I", pe_offset_bytes)[0]
                            fh.seek(pe_offset)
                            pe_sig = fh.read(4)
                            if pe_sig == b"PE\x00\x00":
                                return "PE"
                    except Exception:
                        pass
                
                # Check for ELF signature
                if header[:4] == b"\x7fELF":
                    return "ELF"
                
                # Check using file command
                if shutil.which("file"):
                    proc = subprocess.run(
                        ["file", str(path)],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if proc.stdout:
                        if "PE32" in proc.stdout or "MS Windows" in proc.stdout:
                            return "PE"
                        if "ELF" in proc.stdout:
                            return "ELF"
        except Exception:
            pass
        
        return "Unknown"

    def _parse_pe_headers(self, path: Path) -> Optional[Dict[str, object]]:
        """Parse PE headers (DOS header, NT headers)."""
        try:
            with path.open("rb") as fh:
                data = fh.read(1024)
                
                # Check DOS header
                if len(data) < 64 or data[:2] != b"MZ":
                    return None
                
                pe_info: Dict[str, object] = {
                    "dos_header": {
                        "magic": data[:2].hex(),
                        "is_pe": True,
                    }
                }
                
                # Get PE offset
                pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
                if pe_offset + 24 > len(data):
                    return pe_info
                
                # Parse PE signature
                pe_sig = data[pe_offset:pe_offset+4]
                if pe_sig != b"PE\x00\x00":
                    return pe_info
                
                pe_info["pe_signature"] = "Valid"
                
                # Parse COFF header
                coff_offset = pe_offset + 4
                if coff_offset + 20 <= len(data):
                    machine, num_sections, timestamp, ptr_to_sym_table, num_symbols, size_of_optional_header, characteristics = struct.unpack("<HHIIIIH", data[coff_offset:coff_offset+20])
                    
                    pe_info["coff_header"] = {
                        "machine": hex(machine),
                        "num_sections": num_sections,
                        "timestamp": timestamp,
                        "characteristics": hex(characteristics),
                    }
                
                return pe_info
        except Exception:
            return None

    def _parse_pe_imports(self, path: Path) -> Optional[Dict[str, object]]:
        """Parse PE import table."""
        try:
            # Use objdump or readpe if available
            if shutil.which("objdump"):
                proc = subprocess.run(
                    ["objdump", "-p", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                
                if proc.stdout:
                    imports: List[Dict[str, object]] = []
                    dll_name = ""
                    
                    for line in proc.stdout.splitlines():
                        if line.strip().startswith("DLL Name:"):
                            dll_name = line.split(":", 1)[1].strip()
                        elif line.strip().startswith("vma:") or line.strip().startswith("Hint"):
                            continue
                        elif dll_name and ("Ordinal" in line or line.strip()):
                            parts = line.split()
                            if len(parts) >= 2:
                                imports.append({
                                    "dll": dll_name,
                                    "ordinal_or_name": parts[-1] if parts else "",
                                })
                    
                    if imports:
                        return {
                            "dlls": list(set(imp.get("dll", "") for imp in imports if isinstance(imp, dict))),
                            "imports": imports[:100],  # Limit
                        }
        except Exception:
            pass
        
        return None

    def _parse_pe_exports(self, path: Path) -> Optional[Dict[str, object]]:
        """Parse PE export table."""
        try:
            if shutil.which("objdump"):
                proc = subprocess.run(
                    ["objdump", "-p", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                
                if proc.stdout:
                    exports: List[Dict[str, object]] = []
                    
                    for line in proc.stdout.splitlines():
                        if "EXPORT" in line.upper() or "Ordinal" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                exports.append({
                                    "ordinal": parts[0] if parts else "",
                                    "name": parts[-1] if parts else "",
                                })
                    
                    if exports:
                        return {
                            "exports": exports[:100],
                            "count": len(exports),
                        }
        except Exception:
            pass
        
        return None

    def _parse_sections(self, path: Path, is_pe: bool) -> Optional[List[Dict[str, object]]]:
        """Parse section information."""
        sections: List[Dict[str, object]] = []
        
        try:
            if is_pe and shutil.which("objdump"):
                proc = subprocess.run(
                    ["objdump", "-h", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                
                if proc.stdout:
                    for line in proc.stdout.splitlines()[2:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 7:
                            sections.append({
                                "idx": parts[0],
                                "name": parts[1],
                                "size": parts[2],
                                "vma": parts[3],
                                "lma": parts[4],
                                "file_off": parts[5],
                                "flags": " ".join(parts[6:]) if len(parts) > 6 else "",
                            })
        except Exception:
            pass
        
        return sections if sections else None

    def _parse_symbols(self, path: Path) -> Optional[Dict[str, object]]:
        """Parse symbol information."""
        symbols: Dict[str, List[Dict[str, object]]] = {
            "defined": [],
            "undefined": [],
        }
        
        try:
            if shutil.which("nm"):
                proc = subprocess.run(
                    ["nm", "-D", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                
                if proc.stdout:
                    for line in proc.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 3:
                            symbol_type = parts[0]
                            addr = parts[1]
                            name = " ".join(parts[2:]) if len(parts) > 2 else ""
                            
                            if "U" in symbol_type:
                                symbols["undefined"].append({
                                    "name": name,
                                    "address": addr,
                                    "type": symbol_type,
                                })
                            else:
                                symbols["defined"].append({
                                    "name": name,
                                    "address": addr,
                                    "type": symbol_type,
                                })
        except Exception:
            pass
        
        return symbols if (symbols["defined"] or symbols["undefined"]) else None

    def _parse_security_features(self, path: Path, checksec_output: str) -> Optional[Dict[str, object]]:
        """Parse and explain security features."""
        security: Dict[str, object] = {
            "features": {},
            "explanations": {},
        }
        
        # Parse checksec output
        lines = checksec_output.splitlines()
        for line in lines:
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    feature = parts[0].strip().lower().replace(" ", "_")
                    value = parts[1].strip()
                    security["features"][feature] = value
                    
                    # Add explanations
                    if "nx" in feature or "no_exec" in feature:
                        security["explanations"]["nx"] = "No Execute: Prevents code execution in data areas (stack/heap)"
                    elif "pie" in feature:
                        security["explanations"]["pie"] = "Position Independent Executable: Randomizes base address to prevent ROP/JOP attacks"
                    elif "relro" in feature:
                        security["explanations"]["relro"] = "Relocation Read-Only: Makes GOT/PLT read-only after initialization"
                    elif "canary" in feature or "stack" in feature:
                        security["explanations"]["canary"] = "Stack Canary: Detects stack buffer overflows"
                    elif "aslr" in feature or "address" in feature:
                        security["explanations"]["aslr"] = "Address Space Layout Randomization: Randomizes memory addresses"
        
        return security if security["features"] else None


__all__ = ["BinaryInspector"]
