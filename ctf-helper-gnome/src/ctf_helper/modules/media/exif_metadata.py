"""Metadata extraction helpers for images."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..base import ToolResult

try:  # Optional dependency for richer metadata
    from PIL import Image, ExifTags  # type: ignore
except ImportError:  # pragma: no cover - exercised when Pillow missing
    Image = None  # type: ignore
    ExifTags = None  # type: ignore


class ExifMetadataTool:
    """Inspect metadata via exiftool when available with safe fallbacks."""

    name = "EXIF Metadata Viewer"
    description = "Inspect metadata, detect GPS hints, and prepare mapping links."
    category = "Stego & Media"

    def run(self, file_path: str, prefer_exiftool: str = "true") -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        prefer = self._truthy(prefer_exiftool)
        sources: List[Dict[str, Any]] = []
        warnings: List[str] = []

        if prefer:
            exiftool_data = self._extract_with_exiftool(path)
            if exiftool_data.get("available"):
                sources.append({"source": "exiftool", "data": exiftool_data["data"]})
            else:
                warning = exiftool_data.get("message")
                if warning:
                    warnings.append(str(warning))

        if not sources:
            pillow_data = self._extract_with_pillow(path)
            if pillow_data:
                sources.append({"source": "pillow", "data": pillow_data})
            else:
                warnings.append("Pillow not available or file lacks EXIF data")

        basic_stats = self._basic_file_stats(path)
        sources.append({"source": "filesystem", "data": basic_stats})

        gps = self._extract_gps_from_sources(sources)
        body = {
            "file": str(path.resolve()),
            "sources": sources,
            "gps": gps,
            "warnings": warnings,
        }
        return ToolResult(
            title=f"Metadata for {path.name}",
            body=json.dumps(body, indent=2),
            mime_type="application/json",
        )

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------
    def _extract_with_exiftool(self, path: Path) -> Dict[str, Any]:
        command = self._resolve_command("exiftool", "CTF_HELPER_EXIFTOOL")
        if not command:
            return {"available": False, "message": "exiftool not detected in PATH."}
        try:
            proc = subprocess.run(
                [command, "-json", str(path)],
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
        except FileNotFoundError:
            return {"available": False, "message": "Failed to execute exiftool."}
        except subprocess.TimeoutExpired:
            return {"available": False, "message": "exiftool timed out after 45 seconds."}
        if proc.returncode != 0:
            message = proc.stderr.strip() or "exiftool returned a non-zero exit status"
            return {"available": False, "message": message}
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return {"available": False, "message": f"Failed to parse exiftool output: {exc}"}
        data = payload[0] if isinstance(payload, list) and payload else payload
        return {"available": True, "data": data}

    def _extract_with_pillow(self, path: Path) -> Optional[Dict[str, Any]]:
        if Image is None:
            return None
        try:
            with Image.open(path) as img:
                info = getattr(img, "_getexif", None)
                if callable(info):
                    raw = info()
                else:  # pragma: no cover - pillow without _getexif
                    raw = None
                if not raw:
                    return {
                        "format": img.format,
                        "mode": img.mode,
                        "size": img.size,
                    }
                if ExifTags is not None and getattr(ExifTags, "TAGS", None):
                    def _tag_name(tag: int) -> str:
                        return ExifTags.TAGS.get(tag, str(tag))  # type: ignore[index]
                else:
                    def _tag_name(tag: int) -> str:
                        return str(tag)

                try:
                    raw_items = dict(raw).items()  # type: ignore[arg-type]
                except Exception:
                    raw_items = []

                tag_map = {_tag_name(int(tag)): value for tag, value in raw_items}
                tag_map["format"] = img.format
                tag_map["mode"] = img.mode
                tag_map["size"] = img.size
                return tag_map
        except Exception as exc:  # pragma: no cover - pillow edge cases
            return {"error": f"Pillow failed to parse image: {exc}"}

    def _basic_file_stats(self, path: Path) -> Dict[str, Any]:
        stat = path.stat()
        return {
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
        }

    def _extract_gps_from_sources(self, sources: List[Dict[str, Any]]) -> Dict[str, Any]:
        latitude: Optional[float] = None
        longitude: Optional[float] = None
        for source in sources:
            data = source.get("data")
            if not isinstance(data, dict):
                continue
            lat, lon = self._gps_from_dict(data)
            if latitude is None and lat is not None:
                latitude = lat
            if longitude is None and lon is not None:
                longitude = lon
        if latitude is None or longitude is None:
            return {}
        return {
            "latitude": latitude,
            "longitude": longitude,
            "google_maps": f"https://maps.google.com/?q={latitude},{longitude}",
            "openstreetmap": f"https://www.openstreetmap.org/?mlat={latitude}&mlon={longitude}&zoom=16",
        }

    def _gps_from_dict(self, data: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
        keys = list(data.keys())
        lat = self._find_first(data, keys, ["GPSLatitude", "Composite:GPSLatitude", "GPS:GPSLatitude"])
        lon = self._find_first(data, keys, ["GPSLongitude", "Composite:GPSLongitude", "GPS:GPSLongitude"])
        lat_ref = self._find_first(data, keys, ["GPSLatitudeRef", "GPS:GPSLatitudeRef"])
        lon_ref = self._find_first(data, keys, ["GPSLongitudeRef", "GPS:GPSLongitudeRef"])
        return (
            self._parse_coordinate(lat, lat_ref),
            self._parse_coordinate(lon, lon_ref),
        )

    def _find_first(self, data: Dict[str, Any], keys: List[str], candidates: List[str]) -> Any:
        for candidate in candidates:
            if candidate in data:
                return data[candidate]
            for key in keys:
                if key.lower() == candidate.lower():
                    return data[key]
        return None

    def _parse_coordinate(self, value: Any, ref: Any) -> Optional[float]:
        if value is None:
            return None
        sign = 1.0
        ref_str = str(ref).strip().upper() if ref else ""
        if ref_str in {"S", "W"}:
            sign = -1.0
        if isinstance(value, (int, float)):
            return float(value) * sign
        if isinstance(value, str):
            stripped = value.strip()
            try:
                return float(stripped) * sign
            except ValueError:
                match = re.match(
                    r"(?P<deg>-?\d+(?:\.\d+)?)\s*deg\s*(?P<min>\d+(?:\.\d+)?)'?\s*(?P<sec>\d+(?:\.\d+)?)\"?\s*(?P<dir>[NSEW])?",
                    stripped,
                )
                if match:
                    deg = float(match.group("deg"))
                    minutes = float(match.group("min"))
                    seconds = float(match.group("sec"))
                    direction = match.group("dir") or ref_str
                    if direction in {"S", "W"}:
                        sign = -1.0
                    return sign * (deg + (minutes / 60.0) + (seconds / 3600.0))
        if isinstance(value, (list, tuple)) and len(value) == 3:
            try:
                deg, minutes, seconds = (float(part) for part in value)
                return sign * (deg + (minutes / 60.0) + (seconds / 3600.0))
            except Exception:  # pragma: no cover - defensive
                return None
        return None

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
