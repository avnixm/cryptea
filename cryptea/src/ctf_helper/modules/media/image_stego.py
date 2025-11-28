"""Wrappers around common image steganography tooling."""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..base import ToolResult
from ...utils.extraction_manager import ExtractionManager


class ImageStegoTool:
    """Expose zsteg, steghide, and stegsolve conveniences."""

    name = "Image Stego Toolkit"
    description = "Run zsteg, steghide, and stegsolve helpers against an image."
    category = "Stego & Media"

    def run(
        self,
        image_path: str,
        steghide_password: str = "",
        steghide_extract: str = "false",
        stegsolve_jar: str = "",
        tool_choice: str = "all",
        extraction_dir: str = "",
    ) -> ToolResult:
        path = Path(image_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        should_extract = self._truthy(steghide_extract)
        normalized_choice = (tool_choice or "all").strip().lower()
        operations: Dict[str, Dict[str, object]] = {}
        extraction_output_dir: Optional[Path] = None
        if extraction_dir.strip():
            extraction_output_dir = Path(extraction_dir).expanduser()

        if normalized_choice in {"zsteg", "all"}:
            operations["zsteg"] = self._run_zsteg(path)
        if normalized_choice in {"steghide", "all"}:
            operations["steghide"] = self._run_steghide(path, steghide_password, should_extract)
        if normalized_choice in {"binwalk", "all"}:
            operations["binwalk"] = self._run_binwalk(path)
        if normalized_choice in {"signatures", "all"}:
            operations["signature_scan"] = self._detect_embedded_files(path)
        if normalized_choice == "all":
            operations["stegsolve"] = self._stegsolve_hint(path, stegsolve_jar)

        if should_extract:
            operations["extraction"] = self._extract_all_hidden_files(
                path,
                password=steghide_password,
                output_dir=extraction_output_dir,
            )

        result: Dict[str, object] = {
            "file": str(path.resolve()),
            "operations": operations,
        }

        if len(operations) == 1 and normalized_choice in {"zsteg", "steghide"}:
            tool_name, data = next(iter(operations.items()))
            body = self._format_single_tool_output(tool_name, data)
            title = f"{tool_name.capitalize()} output for {path.name}"
            mime_type = "text/plain"
        else:
            body = json.dumps(result, indent=2)
            title = f"Stego summary for {path.name}"
            mime_type = "application/json"
        return ToolResult(title=title, body=body, mime_type=mime_type)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _run_zsteg(self, path: Path) -> Dict[str, object]:
        command = self._resolve_command("zsteg", "CTF_HELPER_ZSTEG")
        if not command:
            return {
                "available": False,
                "message": "zsteg was not detected. Install it with: gem install zsteg\nOr set CTF_HELPER_ZSTEG environment variable to the zsteg binary path.",
            }
        try:
            proc = subprocess.run(
                [command, "--all", str(path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                env=self._command_env(),
            )
        except FileNotFoundError:
            return {
                "available": False,
                "message": "zsteg command could not be executed.",
            }
        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "timed_out": True,
                "message": "zsteg timed out after 60 seconds.",
            }
        output = (proc.stdout or "") + (f"\n{proc.stderr}" if proc.stderr else "")
        return {
            "available": True,
            "exit_code": proc.returncode,
            "output": self._truncate_output(output),
        }

    def _run_steghide(
        self,
        path: Path,
        password: str,
        extract: bool,
        target_dir: Optional[Path] = None,
    ) -> Dict[str, object]:
        command = self._resolve_command("steghide", "CTF_HELPER_STEGHIDE")
        if not command:
            return {
                "available": False,
                "message": "steghide was not detected. Install it with:\n  Fedora/RHEL: sudo dnf install steghide\n  Ubuntu/Debian: sudo apt install steghide\n  Arch: sudo pacman -S steghide\nOr set CTF_HELPER_STEGHIDE environment variable to the steghide binary path.",
            }
        info_cmd = [command, "info", "-q"]
        if password:
            info_cmd.extend(["-p", password])
        info_cmd.extend(["-sf", str(path)])
        try:
            proc = subprocess.run(
                info_cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                env=self._command_env(),
            )
        except FileNotFoundError:
            return {
                "available": False,
                "message": "steghide command could not be executed.",
            }
        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "timed_out": True,
                "message": "steghide info timed out after 60 seconds.",
            }
        response: Dict[str, object] = {
            "available": True,
            "exit_code": proc.returncode,
            "info": self._truncate_output((proc.stdout or "") + (f"\n{proc.stderr}" if proc.stderr else "")),
        }
        if not extract:
            return response

        extract_dir = target_dir or Path(tempfile.mkdtemp(prefix="steghide_extract_"))
        extract_dir.mkdir(parents=True, exist_ok=True)
        extract_cmd = [command, "extract", "-q"]
        if password:
            extract_cmd.extend(["-p", password])
        extract_cmd.extend(["-sf", str(path), "-xf", str(extract_dir / path.name)])
        try:
            proc_extract = subprocess.run(
                extract_cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                env=self._command_env(),
            )
        except FileNotFoundError:
            response["extraction"] = {
                "started": True,
                "available": False,
                "message": "steghide extract command missing after info succeeded.",
            }
            return response
        except subprocess.TimeoutExpired:
            response["extraction"] = {
                "started": True,
                "timed_out": True,
                "message": "steghide extract timed out after 120 seconds.",
            }
            return response

        files = list(extract_dir.iterdir())
        response["extraction"] = {
            "started": True,
            "exit_code": proc_extract.returncode,
            "output": self._truncate_output(
                (proc_extract.stdout or "") + (f"\n{proc_extract.stderr}" if proc_extract.stderr else "")
            ),
            "output_dir": str(extract_dir),
            "files": [file.name for file in files],
        }
        return response

    def _run_binwalk(
        self,
        path: Path,
        *,
        extract: bool = False,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, object]:
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
            proc = subprocess.run(
                [command, "--signature", "--quiet", str(path)],
                capture_output=True,
                text=True,
                timeout=120,
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
                "message": "binwalk timed out after 120 seconds.",
            }

        parsed_entries = self._parse_binwalk_output(proc.stdout or "")
        response: Dict[str, object] = {
            "available": True,
            "exit_code": proc.returncode,
            "entries": parsed_entries,
            "raw_output": self._truncate_output((proc.stdout or "") + (f"\n{proc.stderr}" if proc.stderr else "")),
        }
        if not extract:
            return response

        extract_dir = output_dir or Path(tempfile.mkdtemp(prefix="binwalk_extract_"))
        extract_dir.mkdir(parents=True, exist_ok=True)
        extract_cmd = [
            command,
            "--quiet",
            "--extract",
            "--directory",
            str(extract_dir),
            str(path),
        ]
        try:
            proc_extract = subprocess.run(
                extract_cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
                env=self._command_env(),
            )
        except FileNotFoundError:
            response["extraction"] = {
                "started": True,
                "available": False,
                "message": "binwalk extract command missing after detection succeeded.",
            }
            return response
        except subprocess.TimeoutExpired:
            response["extraction"] = {
                "started": True,
                "timed_out": True,
                "message": "binwalk extract timed out after 300 seconds.",
            }
            return response

        extracted_files = [
            str(path.relative_to(extract_dir))
            for path in extract_dir.rglob("*")
            if path.is_file()
        ]
        response["extraction"] = {
            "started": True,
            "exit_code": proc_extract.returncode,
            "output_dir": str(extract_dir),
            "files": extracted_files,
            "output": self._truncate_output(
                (proc_extract.stdout or "") + (f"\n{proc_extract.stderr}" if proc_extract.stderr else "")
            ),
        }
        return response

    def _parse_binwalk_output(self, output: str) -> Dict[str, object]:
        entries = []
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
                offset_int = None
            entries.append(
                {
                    "offset_decimal": offset_int if offset_int is not None else offset_decimal,
                    "offset_hex": offset_hex,
                    "description": description,
                }
            )
        return {"matches": entries, "count": len(entries)}

    _EMBEDDED_SIGNATURES: Tuple[Tuple[bytes, str, str], ...] = (
        (b"\x50\x4b\x03\x04", "ZIP archive", ".zip"),
        (b"PK\x05\x06", "ZIP (end of central directory)", ".zip"),
        (b"\x52\x61\x72\x21\x1A\x07\x00", "RAR archive", ".rar"),
        (b"\x1F\x8B\x08", "GZIP archive", ".gz"),
        (b"%PDF", "PDF document", ".pdf"),
        (b"\x89PNG\r\n\x1a\n", "PNG image", ".png"),
        (b"\xFF\xD8\xFF", "JPEG image", ".jpg"),
        (b"GIF89a", "GIF image", ".gif"),
        (b"GIF87a", "GIF image", ".gif"),
        (b"RIFF", "RIFF container (WAV/AVI)", ".riff"),
        (b"\x00\x00\x01\x00", "ICO image", ".ico"),
        (b"\x25\x21\x50\x53", "Postscript", ".ps"),
    )

    def _detect_embedded_files(self, path: Path) -> Dict[str, object]:
        try:
            data = path.read_bytes()
        except Exception as exc:  # pragma: no cover - defensive
            return {
                "available": False,
                "message": f"Unable to read file for signature scan: {exc}",
            }

        matches = []
        for magic, description, extension in self._EMBEDDED_SIGNATURES:
            start = 0
            while True:
                idx = data.find(magic, start)
                if idx == -1:
                    break
                matches.append(
                    {
                        "offset": idx,
                        "offset_hex": hex(idx),
                        "description": description,
                        "suggested_extension": extension,
                    }
                )
                start = idx + 1

        appended = self._detect_appended_data(data)
        result: Dict[str, object] = {
            "available": True,
            "match_count": len(matches),
            "matches": matches,
        }
        if appended:
            result["appended_data"] = appended
        return result

    def _detect_appended_data(self, data: bytes) -> Optional[Dict[str, object]]:
        detectors = [
            ("PNG", b"\x00\x00\x00\x00IEND\xaeB`\x82"),
            ("JPEG", b"\xff\xd9"),
            ("GIF", b"\x00\x3b"),
        ]
        for name, marker in detectors:
            idx = data.find(marker)
            if idx != -1:
                end_idx = idx + len(marker)
                if end_idx < len(data) - 16:
                    appended_length = len(data) - end_idx
                    return {
                        "format": name,
                        "eof_offset": idx,
                        "marker_length": len(marker),
                        "start_of_extra": end_idx,
                        "extra_bytes": appended_length,
                        "message": f"{appended_length} bytes detected after {name} EOF marker",
                    }
        return None

    def _extract_all_hidden_files(
        self,
        path: Path,
        *,
        password: str = "",
        output_dir: Optional[Path] = None,
    ) -> Dict[str, object]:
        base_dir_str = str(output_dir) if output_dir else None
        manager = ExtractionManager(base_dir_str, prefix="image_stego_all_")
        root_dir = manager.root
        extracted_files: List[Dict[str, object]] = []
        errors: List[str] = []

        # Binwalk extraction
        binwalk_dir = root_dir / "binwalk"
        binwalk_result = self._run_binwalk(path, extract=True, output_dir=binwalk_dir)
        if isinstance(binwalk_result, dict):
            extraction_info = binwalk_result.get("extraction")
            if isinstance(extraction_info, dict) and extraction_info.get("files"):
                files_value = extraction_info["files"]
                if isinstance(files_value, list):
                    for rel_path in files_value:
                        file_path = (binwalk_dir / str(rel_path)).resolve()
                        if file_path.is_file():
                            extracted_files.append(manager.record(file_path, method="binwalk"))
            elif binwalk_result.get("message"):
                errors.append(str(binwalk_result["message"]))

        # Steghide extraction
        steghide_dir = root_dir / "steghide"
        steghide_result = self._run_steghide(path, password, True, target_dir=steghide_dir)
        if isinstance(steghide_result, dict):
            steghide_info = steghide_result.get("extraction")
            if isinstance(steghide_info, dict) and steghide_info.get("files"):
                files_value = steghide_info["files"]
                if isinstance(files_value, list):
                    for name in files_value:
                        file_path = (steghide_dir / str(name)).resolve()
                        if file_path.is_file():
                            extracted_files.append(manager.record(file_path, method="steghide"))
            elif steghide_result.get("message"):
                errors.append(str(steghide_result["message"]))

        # Signature-based carving
        signature_scan = self._detect_embedded_files(path)
        carved_dir = root_dir / "signature_carve"
        carved_info = self._carve_signature_matches(path, signature_scan, carved_dir, manager)
        carved_files_value = carved_info.get("files") if isinstance(carved_info, dict) else None
        if isinstance(carved_files_value, list):
            extracted_files.extend(carved_files_value)
        if carved_info.get("message"):
            errors.append(str(carved_info["message"]))

        return {
            "output_dir": str(root_dir),
            "files": extracted_files,
            "errors": errors,
            "binwalk": binwalk_result,
            "steghide": steghide_result,
            "signature_carving": carved_info,
        }

    def _carve_signature_matches(
        self,
        path: Path,
        signature_scan: Dict[str, object],
        output_dir: Path,
        manager: ExtractionManager,
    ) -> Dict[str, object]:
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            data = path.read_bytes()
        except Exception as exc:  # pragma: no cover - defensive
            return {"files": [], "message": f"Failed to read file for carving: {exc}"}

        matches_obj = signature_scan.get("matches") if isinstance(signature_scan, dict) else None
        if isinstance(matches_obj, list):
            carved = self._carve_from_matches(data, path, matches_obj, output_dir, manager)
        else:
            carved = []

        appended = signature_scan.get("appended_data") if isinstance(signature_scan, dict) else None
        appended_file_info = []
        if isinstance(appended, dict) and appended.get("extra_bytes") and appended.get("start_of_extra") is not None:
            start = appended["start_of_extra"]
            chunk = data[start:]
            if chunk:
                appended_path = output_dir / "appended_data.bin"
                with appended_path.open("wb") as fh:
                    fh.write(chunk)
                appended_file_info.append(
                    manager.record(
                        appended_path,
                        method="appended-bytes",
                        extra={"description": appended.get("message")},
                    )
                )

        return {
            "files": carved + appended_file_info,
            "carved_count": len(carved) + len(appended_file_info),
        }

    def _carve_from_matches(
        self,
        data: bytes,
        source_path: Path,
        matches: List[Dict[str, object]],
        output_dir: Path,
        manager: ExtractionManager,
    ) -> List[Dict[str, object]]:
        filtered_matches = [m for m in matches if isinstance(m, dict) and isinstance(m.get("offset"), int)]
        sorted_matches = sorted(filtered_matches, key=lambda m: int(m["offset"]))  # type: ignore[arg-type]
        carved_files: List[Dict[str, object]] = []
        primary_label = source_path.suffix.lower().lstrip(".")
        count = 0
        for idx, entry in enumerate(sorted_matches):
            offset = entry.get("offset")
            if not isinstance(offset, int):
                continue
            description_value = entry.get("description")
            description_text = str(description_value) if description_value is not None else ""
            description_lower = description_text.lower()
            if offset == 0 and primary_label and primary_label in description_lower:
                continue
            next_offset = (
                sorted_matches[idx + 1]["offset"]  # type: ignore[index]
                if idx + 1 < len(sorted_matches)
                else len(data)
            )
            if not isinstance(next_offset, int) or next_offset <= offset:
                next_offset = len(data)
            length = next_offset - offset
            if length <= 32:
                continue
            ext = entry.get("suggested_extension") or ".bin"
            file_name = f"carved_{count}{ext}"
            count += 1
            out_path = output_dir / file_name
            with out_path.open("wb") as fh:
                fh.write(data[offset:next_offset])
            carved_files.append(
                manager.record(
                    out_path,
                    method="signature",
                    extra={
                        "offset": offset,
                        "description": entry.get("description"),
                    },
                )
            )
        return carved_files

    def _stegsolve_hint(self, path: Path, jar: str) -> Dict[str, object]:
        jar_path: Optional[Path] = None
        if jar.strip():
            jar_path = Path(jar).expanduser()
        elif os.environ.get("CTF_HELPER_STEGSOLVE"):
            jar_path = Path(os.environ["CTF_HELPER_STEGSOLVE"]).expanduser()
        if jar_path and jar_path.exists():
            return {
                "available": True,
                "launch_command": ["java", "-jar", str(jar_path), str(path)],
                "note": "Stegsolve is an interactive GUI. Launching it opens a separate window.",
            }
        return {
            "available": False,
            "message": "Provide a stegsolve.jar path to generate a launch command.",
        }

    def _resolve_command(self, name: str, env_var: str) -> Optional[str]:
        explicit = os.environ.get(env_var)
        if explicit:
            return explicit

        resolved = shutil.which(name)
        if resolved:
            return resolved

        for candidate in self._common_command_candidates(name):
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)

        return None

    def _common_command_candidates(self, name: str) -> Iterable[Path]:
        home = Path.home()
        static_dirs = [
            home / ".local/bin",
            home / "bin",
            Path("/usr/local/bin"),
            Path("/usr/bin"),
        ]
        for directory in static_dirs:
            yield directory / name

        gem_patterns = [
            home / ".local/share/gem/ruby" / "*" / "bin",
            home / ".gem/ruby" / "*" / "bin",
        ]
        for pattern in gem_patterns:
            for folder in glob.glob(str(pattern)):
                yield Path(folder) / name

    def _command_env(self) -> Dict[str, str]:
        env = dict(os.environ)
        env.setdefault("LC_ALL", "C")
        return env

    def _format_single_tool_output(self, tool_name: str, data: Dict[str, Any]) -> str:
        heading = tool_name.upper()
        lines = [f"=== {heading} ==="]
        if not data.get("available", False):
            message = data.get("message", "Tool unavailable.")
            lines.append(message)
            return "\n".join(lines)

        for key, value in data.items():
            if key == "available":
                continue
            pretty_value: str
            if isinstance(value, str):
                pretty_value = value
            else:
                pretty_value = json.dumps(value, indent=2, ensure_ascii=False)
            lines.append(f"{key}: {pretty_value}")

        return "\n".join(lines)

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _truncate_output(self, text: str, limit: int = 12_000) -> str:
        if len(text) <= limit:
            return text.strip()
        return text[: limit - 1].rstrip() + "…"
