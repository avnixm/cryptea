"""Frame extraction helpers for video files."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from ..base import ToolResult


class VideoFrameExporterTool:
    """Use ffmpeg when available to export still frames."""

    name = "Video Frame Exporter"
    description = "Export frames at fixed intervals and optionally hash the results."
    category = "Stego & Media"

    def run(
        self,
        file_path: str,
        output_dir: str = "",
        interval_seconds: str = "2",
        max_frames: str = "0",
        analyze_frames: str = "false",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        interval = max(float(interval_seconds or "2"), 0.1)
        limit = max(int(max_frames or "0"), 0)
        needs_analysis = self._truthy(analyze_frames)

        destination = Path(output_dir).expanduser() if output_dir.strip() else self._default_output_dir(path)
        destination.mkdir(parents=True, exist_ok=True)

        command = self._resolve_command("ffmpeg", "CTF_HELPER_FFMPEG")
        summary: Dict[str, object] = {
            "file": str(path.resolve()),
            "output_dir": str(destination.resolve()),
            "interval_seconds": interval,
            "max_frames": limit,
            "analyze_frames": needs_analysis,
        }

        if not command:
            summary["ffmpeg"] = {
                "available": False,
                "message": "ffmpeg not detected. Install it or set CTF_HELPER_FFMPEG.",
            }
            return ToolResult(
                title=f"Frame export for {path.name}",
                body=json.dumps(summary, indent=2),
                mime_type="application/json",
            )

        pattern = destination / "frame_%06d.png"
        args = [
            command,
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(path),
            "-vf",
            f"fps=1/{interval}",
        ]
        if limit:
            args.extend(["-frames:v", str(limit)])
        args.append(str(pattern))

        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=240, check=False)
        except FileNotFoundError:
            summary["ffmpeg"] = {
                "available": False,
                "message": "Failed to execute ffmpeg command.",
            }
            return ToolResult(
                title=f"Frame export for {path.name}",
                body=json.dumps(summary, indent=2),
                mime_type="application/json",
            )
        except subprocess.TimeoutExpired:
            summary["ffmpeg"] = {
                "available": True,
                "timed_out": True,
                "message": "ffmpeg timed out after 240 seconds.",
            }
            return ToolResult(
                title=f"Frame export for {path.name}",
                body=json.dumps(summary, indent=2),
                mime_type="application/json",
            )

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        summary["ffmpeg"] = {
            "available": True,
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }

        frames = sorted(destination.glob("frame_*.png"))
        summary["frames_found"] = len(frames)
        if needs_analysis:
            summary["frames"] = [self._analyse_frame(frame) for frame in frames]

        return ToolResult(
            title=f"Frame export for {path.name}",
            body=json.dumps(summary, indent=2),
            mime_type="application/json",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _analyse_frame(self, frame: Path) -> Dict[str, object]:
        sha256 = hashlib.sha256()
        try:
            data = frame.read_bytes()
        except FileNotFoundError:
            return {"file": frame.name, "missing": True}
        sha256.update(data)
        return {
            "file": frame.name,
            "size_bytes": len(data),
            "sha256": sha256.hexdigest(),
        }

    def _default_output_dir(self, path: Path) -> Path:
        base = path.with_suffix("")
        candidate = Path(f"{base}_frames")
        if not candidate.exists():
            return candidate
        parent = path.parent
        for index in range(1, 100):
            fallback = parent / f"{base.name}_frames_{index}"
            if not fallback.exists():
                return fallback
        return Path(tempfile.mkdtemp(prefix=f"{base.name}_frames_"))

    def _resolve_command(self, name: str, env_var: str) -> Optional[str]:
        explicit = os.environ.get(env_var)
        if explicit:
            return explicit
        return shutil.which(name)

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
