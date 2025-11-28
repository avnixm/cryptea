"""Binwalk wrapper for firmware and binary analysis with embedded data extraction."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from ..base import ToolResult
from ...utils.extraction_manager import ExtractionManager


class BinwalkTool:
    """Standalone Binwalk tool for firmware analysis and embedded data extraction."""

    name = "Binwalk"
    description = "Scan files and firmware for embedded data, compressed blocks, and hidden file systems. Automatically carve and extract nested archives."
    category = "Forensics"

    def run(
        self,
        file_path: str,
        extract: str = "false",
        output_dir: str = "",
        scan_depth: str = "1",
        custom_signatures: str = "",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        should_extract = self._truthy(extract)
        depth = max(1, min(5, int(scan_depth or "1")))
        extraction_base: Optional[Path] = None
        if output_dir.strip():
            extraction_base = Path(output_dir).expanduser()
            extraction_base.mkdir(parents=True, exist_ok=True)

        # Run binwalk scan
        scan_result = self._scan_for_embedded_data(path, depth=depth, custom_sigs=custom_signatures)

        # Extract if requested
        extraction_result: Optional[Dict[str, object]] = None
        if should_extract:
            extract_dir = extraction_base or Path(tempfile.mkdtemp(prefix="binwalk_extract_"))
            extraction_result = self._extract_all_embedded_data(path, extract_dir, depth=depth)

        payload: Dict[str, object] = {
            "file": str(path.resolve()),
            "scan": scan_result,
        }
        if extraction_result:
            payload["extraction"] = extraction_result

        body = json.dumps(payload, indent=2)
        return ToolResult(title=f"Binwalk analysis for {path.name}", body=body, mime_type="application/json")

    def _scan_for_embedded_data(
        self,
        path: Path,
        depth: int = 1,
        custom_sigs: str = "",
    ) -> Dict[str, object]:
        """Scan file for embedded data signatures."""
        command = self._resolve_command("binwalk", "CTF_HELPER_BINWALK")
        if not command:
            return {
                "available": False,
                "message": (
                    "binwalk was not detected. Install it with:\n"
                    "  Fedora/RHEL: sudo dnf install binwalk\n"
                    "  Ubuntu/Debian: sudo apt install binwalk\n"
                    "  Arch: sudo pacman -S binwalk\n"
                    "Or set CTF_HELPER_BINWALK environment variable to the binwalk binary path."
                ),
            }

        try:
            cmd = [command, "--signature", "--quiet"]
            if custom_sigs.strip():
                # If custom signatures provided, save to temp file and use --signature option
                # For now, just run with default signatures
                pass
            cmd.append(str(path))

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
                env=self._command_env(),
            )
        except FileNotFoundError:
            return {
                "available": False,
                "message": "binwalk command could not be executed.",
            }
        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "timed_out": True,
                "message": "binwalk scan timed out after 300 seconds.",
            }

        entries = self._parse_binwalk_output(proc.stdout or "")
        
        # Categorize entries
        categorized = self._categorize_entries(entries)

        return {
            "available": True,
            "exit_code": proc.returncode,
            "entries": entries,
            "categories": categorized,
            "total_findings": len(entries),
            "raw_output": self._truncate_output((proc.stdout or "") + (f"\n{proc.stderr}" if proc.stderr else "")),
        }

    def _extract_all_embedded_data(
        self,
        path: Path,
        output_dir: Path,
        depth: int = 1,
    ) -> Dict[str, object]:
        """Extract all embedded data and nested archives."""
        command = self._resolve_command("binwalk", "CTF_HELPER_BINWALK")
        if not command:
            return {
                "available": False,
                "message": "binwalk not available for extraction",
            }

        manager = ExtractionManager(str(output_dir))

        try:
            # Extract with recursive depth
            extract_cmd = [
                command,
                "--quiet",
                "--extract",
                "--directory",
                str(manager.root),
                "--matryoshka",  # Recursive extraction
                str(path),
            ]
            
            proc = subprocess.run(
                extract_cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes for deep extraction
                check=False,
                env=self._command_env(),
            )
        except FileNotFoundError:
            return {
                "available": False,
                "message": "binwalk extract command could not be executed.",
            }
        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "timed_out": True,
                "message": "binwalk extraction timed out after 600 seconds.",
            }

        # Find all extracted files
        extracted_files: List[Dict[str, object]] = []
        for extracted_path in manager.root.rglob("*"):
            if extracted_path.is_file():
                try:
                    size = extracted_path.stat().st_size
                    relative_path = extracted_path.relative_to(manager.root)
                    extracted_files.append({
                        "path": str(relative_path),
                        "name": extracted_path.name,
                        "size_bytes": size,
                    })
                except Exception:
                    pass

        return {
            "available": True,
            "exit_code": proc.returncode,
            "output_dir": str(manager.root),
            "extracted_files": extracted_files,
            "file_count": len(extracted_files),
            "stdout": self._truncate_output(proc.stdout or ""),
            "stderr": self._truncate_output(proc.stderr or ""),
        }

    def _parse_binwalk_output(self, output: str) -> List[Dict[str, object]]:
        """Parse binwalk output into structured entries."""
        entries: List[Dict[str, object]] = []
        lines = output.splitlines()

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("DECIMAL") or stripped.startswith("--"):
                continue

            parts = stripped.split(maxsplit=2)
            if len(parts) < 3:
                continue

            offset_decimal = parts[0]
            offset_hex = parts[1]
            description = parts[2]

            try:
                offset_int = int(offset_decimal)
            except ValueError:
                continue

            # Categorize entry type
            entry_type = self._categorize_entry_type(description)

            entries.append({
                "offset_decimal": offset_int,
                "offset_hex": offset_hex,
                "description": description,
                "type": entry_type,
            })

        return entries

    def _categorize_entry_type(self, description: str) -> str:
        """Categorize binwalk entry by description."""
        desc_lower = description.lower()
        
        if any(x in desc_lower for x in ["zip", "gzip", "bzip2", "lzma", "7zip"]):
            return "archive"
        elif any(x in desc_lower for x in ["filesystem", "squashfs", "cramfs", "jffs2", "romfs"]):
            return "filesystem"
        elif any(x in desc_lower for x in ["elf", "pe", "mach-o", "executable"]):
            return "executable"
        elif any(x in desc_lower for x in ["png", "jpeg", "gif", "image"]):
            return "image"
        elif any(x in desc_lower for x in ["lzma", "zlib", "deflate"]):
            return "compressed"
        elif any(x in desc_lower for x in ["base64", "ascii"]):
            return "encoded_data"
        else:
            return "unknown"

    def _categorize_entries(self, entries: List[Dict[str, object]]) -> Dict[str, List[Dict[str, object]]]:
        """Group entries by category."""
        categorized: Dict[str, List[Dict[str, object]]] = {}
        
        for entry in entries:
            entry_type = str(entry.get("type", "unknown"))
            if entry_type not in categorized:
                categorized[entry_type] = []
            categorized[entry_type].append(entry)
        
        return categorized

    def _resolve_command(self, name: str, env_var: str) -> Optional[str]:
        explicit = os.environ.get(env_var)
        if explicit:
            return explicit
        resolved = shutil.which(name)
        return resolved if resolved else None

    def _command_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        return env

    def _truncate_output(self, text: str, limit: int = 10000) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + f"\n... (truncated, {len(text) - limit} more characters) ..."

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

