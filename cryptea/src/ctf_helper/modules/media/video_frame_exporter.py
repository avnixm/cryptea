"""Frame extraction helpers for video files."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from ..base import ToolResult

try:
    from PIL import Image  # type: ignore
    HAS_PIL = True
except ImportError:
    Image = None  # type: ignore
    HAS_PIL = False

try:
    from pyzbar import pyzbar  # type: ignore
    HAS_PYZBAR = True
except ImportError:
    pyzbar = None  # type: ignore
    HAS_PYZBAR = False

try:
    import pytesseract  # type: ignore
    HAS_TESSERACT = True
except ImportError:
    pytesseract = None  # type: ignore
    HAS_TESSERACT = False


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
        detect_qr_codes: str = "false",
        detect_text: str = "false",
        detect_artifacts: str = "false",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        interval = max(float(interval_seconds or "2"), 0.1)
        limit = max(int(max_frames or "0"), 0)
        needs_analysis = self._truthy(analyze_frames)
        detect_qr = self._truthy(detect_qr_codes)
        detect_text_ocr = self._truthy(detect_text)
        detect_artifacts_flag = self._truthy(detect_artifacts)

        destination = Path(output_dir).expanduser() if output_dir.strip() else self._default_output_dir(path)
        destination.mkdir(parents=True, exist_ok=True)

        command = self._resolve_command("ffmpeg", "CTF_HELPER_FFMPEG")
        summary: Dict[str, object] = {
            "file": str(path.resolve()),
            "output_dir": str(destination.resolve()),
            "interval_seconds": interval,
            "max_frames": limit,
            "analyze_frames": needs_analysis,
            "detect_qr_codes": detect_qr,
            "detect_text": detect_text_ocr,
            "detect_artifacts": detect_artifacts_flag,
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
        
        if needs_analysis or detect_qr or detect_text_ocr or detect_artifacts_flag:
            frame_analyses = []
            for frame in frames:
                frame_data = self._analyse_frame(frame)
                if detect_qr:
                    frame_data["qr_codes"] = self._scan_frame_qr(frame)
                if detect_text_ocr:
                    frame_data["text"] = self._extract_frame_text(frame)
                if detect_artifacts_flag:
                    frame_data["artifacts"] = self._detect_frame_artifacts(frame)
                frame_analyses.append(frame_data)
            summary["frames"] = frame_analyses

        return ToolResult(
            title=f"Frame export for {path.name}",
            body=json.dumps(summary, indent=2),
            mime_type="application/json",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _analyse_frame(self, frame: Path) -> Dict[str, object]:
        """Basic frame analysis with hash and metadata."""
        sha256 = hashlib.sha256()
        try:
            data = frame.read_bytes()
        except FileNotFoundError:
            return {"file": frame.name, "missing": True}
        sha256.update(data)
        
        result: Dict[str, object] = {
            "file": frame.name,
            "size_bytes": len(data),
            "sha256": sha256.hexdigest(),
        }

        # Enhanced metadata if PIL is available
        if HAS_PIL:
            try:
                with Image.open(frame) as img:
                    result["image_size"] = {"width": img.width, "height": img.height}
                    result["image_mode"] = img.mode
                    
                    # Dominant color analysis
                    if img.mode in ("RGB", "RGBA"):
                        dominant_colors = self._get_dominant_colors(img)
                        result["dominant_colors"] = dominant_colors
            except Exception:
                pass

        return result

    def _scan_frame_qr(self, frame: Path) -> Dict[str, object]:
        """Scan frame for QR codes."""
        if not HAS_PYZBAR:
            return {"available": False, "message": "pyzbar not available"}

        try:
            with Image.open(frame) as img:
                codes = pyzbar.decode(img)
                decoded = [
                    {
                        "type": code.type.decode() if isinstance(code.type, bytes) else str(code.type),
                        "data": code.data.decode() if isinstance(code.data, bytes) else str(code.data),
                        "rect": {
                            "left": code.rect.left,
                            "top": code.rect.top,
                            "width": code.rect.width,
                            "height": code.rect.height,
                        },
                    }
                    for code in codes
                ]
                return {"available": True, "count": len(decoded), "codes": decoded}
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    def _extract_frame_text(self, frame: Path) -> Dict[str, object]:
        """Extract text from frame using OCR."""
        if not HAS_TESSERACT:
            return {"available": False, "message": "pytesseract not available"}

        try:
            text = pytesseract.image_to_string(str(frame))
            text_clean = text.strip()
            
            # Detect flag patterns in extracted text
            flag_patterns = [
                re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
                re.compile(r"FLAG\{[^}]+\}", re.IGNORECASE),
                re.compile(r"ctf\{[^}]+\}", re.IGNORECASE),
            ]
            flags_found = []
            for pattern in flag_patterns:
                matches = pattern.findall(text_clean)
                flags_found.extend(matches)

            return {
                "available": True,
                "text": text_clean[:500],  # Limit text length
                "text_length": len(text_clean),
                "flags_detected": flags_found,
            }
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    def _detect_frame_artifacts(self, frame: Path) -> Dict[str, object]:
        """Detect artifacts and anomalies in frame."""
        artifacts: Dict[str, object] = {
            "available": True,
            "anomalies": [],
        }

        if not HAS_PIL:
            artifacts["available"] = False
            artifacts["message"] = "PIL not available"
            return artifacts

        try:
            with Image.open(frame) as img:
                # Check for unusual dimensions
                if img.width < 100 or img.height < 100:
                    artifacts["anomalies"].append("Very small frame dimensions")

                # Detect if frame is mostly static (single color)
                if img.mode in ("RGB", "RGBA"):
                    unique_colors = len(img.getcolors(maxcolors=256 * 256 * 256))
                    if unique_colors and unique_colors < 100:
                        artifacts["anomalies"].append(f"Very few unique colors ({unique_colors}), possibly static frame")

                # Detect flag patterns in pixel data (check first few rows/columns)
                if img.mode in ("RGB", "RGBA"):
                    pixels = img.load()
                    # Check top row
                    top_row_text = ""
                    for x in range(min(100, img.width)):
                        pixel = pixels[x, 0]
                        if isinstance(pixel, tuple) and len(pixel) >= 3:
                            # Convert RGB values to ASCII if printable
                            for val in pixel[:3]:
                                if 32 <= val <= 126:
                                    top_row_text += chr(val)
                    
                    flag_patterns = [
                        re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
                        re.compile(r"FLAG\{[^}]+\}", re.IGNORECASE),
                    ]
                    for pattern in flag_patterns:
                        matches = pattern.findall(top_row_text)
                        if matches:
                            artifacts["anomalies"].append(f"Possible flag pattern in pixel data: {matches[0]}")

        except Exception as exc:
            artifacts["error"] = str(exc)

        return artifacts

    def _get_dominant_colors(self, img: Image.Image, num_colors: int = 5) -> List[Dict[str, int]]:
        """Get dominant colors from image."""
        try:
            # Resize for faster processing
            img_small = img.resize((150, 150))
            colors = img_small.getcolors(maxcolors=256 * 256 * 256)
            if not colors:
                return []

            # Sort by frequency
            colors_sorted = sorted(colors, key=lambda x: x[0], reverse=True)
            dominant = []
            for count, color in colors_sorted[:num_colors]:
                if isinstance(color, tuple) and len(color) >= 3:
                    dominant.append({
                        "r": color[0],
                        "g": color[1],
                        "b": color[2],
                        "frequency": count,
                    })
            return dominant
        except Exception:
            return []

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
