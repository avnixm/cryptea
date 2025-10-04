"""Wrappers around common image steganography tooling."""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from ..base import ToolResult


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
    ) -> ToolResult:
        path = Path(image_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        should_extract = self._truthy(steghide_extract)
        normalized_choice = (tool_choice or "all").strip().lower()
        operations: Dict[str, Dict[str, object]] = {}

        if normalized_choice in {"zsteg", "all"}:
            operations["zsteg"] = self._run_zsteg(path)
        if normalized_choice in {"steghide", "all"}:
            operations["steghide"] = self._run_steghide(path, steghide_password, should_extract)
        if normalized_choice == "all":
            operations["stegsolve"] = self._stegsolve_hint(path, stegsolve_jar)

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
                "message": "zsteg was not detected. Install it or provide CTF_HELPER_ZSTEG.",
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

    def _run_steghide(self, path: Path, password: str, extract: bool) -> Dict[str, object]:
        command = self._resolve_command("steghide", "CTF_HELPER_STEGHIDE")
        if not command:
            return {
                "available": False,
                "message": "steghide was not detected. Install it or provide CTF_HELPER_STEGHIDE.",
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

        extract_dir = Path(tempfile.mkdtemp(prefix="steghide_extract_"))
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
