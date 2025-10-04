"""Batch QR and barcode decoding helpers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..base import ToolResult


class QRScannerTool:
    """Use zbarimg (if available) to decode QR and barcodes."""

    name = "QR/Barcode Scanner"
    description = "Scan files or folders for QR/Barcode payloads with zbarimg."
    category = "Stego & Media"

    SUPPORTED_SUFFIXES = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".webp",
        ".tif",
        ".tiff",
        ".pbm",
        ".pgm",
        ".ppm",
    }

    def run(self, target_path: str, recursive: str = "false", include_raw_output: str = "false") -> ToolResult:
        path = Path(target_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        recursive_scan = self._truthy(recursive)
        keep_raw = self._truthy(include_raw_output)
        command = self._resolve_command("zbarimg", "CTF_HELPER_ZBARIMG")

        results: List[Dict[str, object]] = []
        summary: Dict[str, object] = {
            "target": str(path.resolve()),
            "recursive": recursive_scan,
            "include_raw": keep_raw,
            "available": bool(command),
            "results": results,
        }

        if not command:
            summary["message"] = "zbarimg not detected. Install it or set CTF_HELPER_ZBARIMG."
            return ToolResult(
                title=f"QR scan for {path.name}",
                body=json.dumps(summary, indent=2),
                mime_type="application/json",
            )

        files = self._collect_files(path, recursive_scan)
        for file in files:
            result = self._scan_file(command, file, keep_raw)
            results.append(result)

        return ToolResult(
            title=f"QR scan for {path.name}",
            body=json.dumps(summary, indent=2),
            mime_type="application/json",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _collect_files(self, path: Path, recursive: bool) -> List[Path]:
        if path.is_file():
            return [path]
        candidates: Iterable[Path]
        if recursive:
            candidates = path.rglob("*")
        else:
            candidates = path.glob("*")
        return [item for item in candidates if item.is_file() and item.suffix.lower() in self.SUPPORTED_SUFFIXES]

    def _scan_file(self, command: str, file: Path, keep_raw: bool) -> Dict[str, object]:
        try:
            proc = subprocess.run(
                [command, "--quiet", "--raw", str(file)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                env=self._command_env(),
            )
        except FileNotFoundError:
            return {
                "file": str(file.resolve()),
                "error": "zbarimg command missing during execution.",
            }
        except subprocess.TimeoutExpired:
            return {
                "file": str(file.resolve()),
                "error": "zbarimg timed out after 60 seconds.",
            }
        raw_output = (proc.stdout or "").strip()
        decoded: List[Dict[str, str]] = []
        for line in raw_output.splitlines():
            if ":" in line:
                kind, payload = line.split(":", 1)
                decoded.append({"type": kind.strip(), "data": payload.strip()})
            elif line:
                decoded.append({"type": "unknown", "data": line.strip()})
        result: Dict[str, object] = {
            "file": str(file.resolve()),
            "exit_code": proc.returncode,
            "decoded": decoded,
        }
        if keep_raw:
            result["raw"] = raw_output
        if proc.stderr:
            result["stderr"] = proc.stderr.strip()
        return result

    def _resolve_command(self, name: str, env_var: str) -> Optional[str]:
        explicit = os.environ.get(env_var)
        if explicit:
            return explicit
        return shutil.which(name)

    def _command_env(self) -> Dict[str, str]:
        env = dict(os.environ)
        env.setdefault("LC_ALL", "C")
        return env

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
