"""Batch QR and barcode decoding helpers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..base import ToolResult

try:
    from PIL import Image, ImageEnhance, ImageOps  # type: ignore
    HAS_PIL = True
except ImportError:
    Image = None  # type: ignore
    ImageEnhance = None  # type: ignore
    ImageOps = None  # type: ignore
    HAS_PIL = False

try:
    from pyzbar import pyzbar  # type: ignore
    HAS_PYZBAR = True
except ImportError:
    pyzbar = None  # type: ignore
    HAS_PYZBAR = False


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

    def run(
        self,
        target_path: str,
        recursive: str = "false",
        include_raw_output: str = "false",
        enable_preprocessing: str = "false",
        scan_modes: str = "all",
    ) -> ToolResult:
        path = Path(target_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        recursive_scan = self._truthy(recursive)
        keep_raw = self._truthy(include_raw_output)
        use_preprocessing = self._truthy(enable_preprocessing)
        modes = [m.strip().lower() for m in scan_modes.split(",") if m.strip()] if scan_modes != "all" else ["all"]
        
        command = self._resolve_command("zbarimg", "CTF_HELPER_ZBARIMG")
        use_pyzbar_fallback = not command and HAS_PYZBAR

        results: List[Dict[str, object]] = []
        summary: Dict[str, object] = {
            "target": str(path.resolve()),
            "recursive": recursive_scan,
            "include_raw": keep_raw,
            "preprocessing_enabled": use_preprocessing,
            "zbarimg_available": bool(command),
            "pyzbar_fallback": use_pyzbar_fallback,
            "results": results,
        }

        if not command and not use_pyzbar_fallback:
            summary["message"] = "Neither zbarimg nor pyzbar detected. Install one:\n  - zbarimg: sudo dnf install zbar\n  - pyzbar: pip install pyzbar"
            return ToolResult(
                title=f"QR scan for {path.name}",
                body=json.dumps(summary, indent=2),
                mime_type="application/json",
            )

        files = self._collect_files(path, recursive_scan)
        for file in files:
            if command:
                result = self._scan_file(command, file, keep_raw, use_preprocessing)
            else:
                result = self._scan_file_pyzbar(file, keep_raw, use_preprocessing)
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

    def _scan_file(self, command: str, file: Path, keep_raw: bool, use_preprocessing: bool) -> Dict[str, object]:
        """Scan file with zbarimg, optionally with preprocessing."""
        decoded: List[Dict[str, object]] = []
        scan_attempts: List[Dict[str, object]] = []

        # First attempt: original image
        attempt_result = self._scan_file_direct(command, file, keep_raw)
        scan_attempts.append({"method": "original", **attempt_result})
        decoded.extend(attempt_result.get("decoded", []))

        # If preprocessing enabled, try multiple variations
        if use_preprocessing and HAS_PIL:
            variations = self._generate_image_variations(file)
            for variation_name, variation_path in variations.items():
                var_result = self._scan_file_direct(command, variation_path, keep_raw)
                scan_attempts.append({"method": variation_name, **var_result})
                decoded.extend(var_result.get("decoded", []))
                # Clean up temporary file
                if variation_path != file and variation_path.exists():
                    try:
                        variation_path.unlink()
                    except Exception:
                        pass

        return {
            "file": str(file.resolve()),
            "decoded": decoded,
            "scan_attempts": scan_attempts,
        }

    def _scan_file_direct(self, command: str, file: Path, keep_raw: bool) -> Dict[str, object]:
        """Direct scan with zbarimg."""
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
                "error": "zbarimg command missing during execution.",
                "decoded": [],
            }
        except subprocess.TimeoutExpired:
            return {
                "error": "zbarimg timed out after 60 seconds.",
                "decoded": [],
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
            "exit_code": proc.returncode,
            "decoded": decoded,
        }
        if keep_raw:
            result["raw"] = raw_output
        if proc.stderr:
            result["stderr"] = proc.stderr.strip()
        return result

    def _scan_file_pyzbar(self, file: Path, keep_raw: bool, use_preprocessing: bool) -> Dict[str, object]:
        """Scan file using pyzbar as fallback."""
        if not HAS_PYZBAR:
            return {
                "file": str(file.resolve()),
                "error": "pyzbar not available",
                "decoded": [],
            }

        decoded: List[Dict[str, object]] = []
        scan_attempts: List[Dict[str, object]] = []

        try:
            # Original image
            with Image.open(file) as img:
                codes = pyzbar.decode(img)
                decoded.extend([{"type": code.type.decode(), "data": code.data.decode()} for code in codes])
                scan_attempts.append({"method": "original", "count": len(codes)})

            # Preprocessing variations
            if use_preprocessing:
                variations = self._generate_image_variations(file)
                for variation_name, variation_path in variations.items():
                    if variation_path != file and variation_path.exists():
                        try:
                            with Image.open(variation_path) as var_img:
                                var_codes = pyzbar.decode(var_img)
                                decoded.extend([{"type": code.type.decode(), "data": code.data.decode()} for code in var_codes])
                                scan_attempts.append({"method": variation_name, "count": len(var_codes)})
                        except Exception:
                            pass
                        finally:
                            try:
                                variation_path.unlink()
                            except Exception:
                                pass
        except Exception as exc:
            return {
                "file": str(file.resolve()),
                "error": f"pyzbar scan failed: {exc}",
                "decoded": [],
            }

        return {
            "file": str(file.resolve()),
            "decoded": decoded,
            "scan_attempts": scan_attempts,
        }

    def _generate_image_variations(self, file: Path) -> Dict[str, Path]:
        """Generate image variations for better QR code detection."""
        variations: Dict[str, Path] = {}
        if not HAS_PIL:
            return variations

        try:
            with Image.open(file) as img:
                base_name = file.stem
                parent = file.parent

                # Inverted colors
                try:
                    if img.mode == "RGBA":
                        rgb_img = Image.new("RGB", img.size, (255, 255, 255))
                        rgb_img.paste(img, mask=img.split()[3])
                        inverted = ImageOps.invert(rgb_img)
                    else:
                        inverted = ImageOps.invert(img.convert("RGB"))
                    inv_path = parent / f"{base_name}_inverted.png"
                    inverted.save(inv_path)
                    variations["inverted"] = inv_path
                except Exception:
                    pass

                # High contrast
                try:
                    enhancer = ImageEnhance.Contrast(img.convert("RGB"))
                    high_contrast = enhancer.enhance(5.0)
                    hc_path = parent / f"{base_name}_high_contrast.png"
                    high_contrast.save(hc_path)
                    variations["high_contrast"] = hc_path
                except Exception:
                    pass

                # Threshold (black and white)
                try:
                    gray = img.convert("L")
                    threshold = gray.point(lambda x: 0 if x < 128 else 255, "1")
                    thresh_path = parent / f"{base_name}_threshold.png"
                    threshold.convert("RGB").save(thresh_path)
                    variations["threshold"] = thresh_path
                except Exception:
                    pass

                # Grayscale
                try:
                    gray_path = parent / f"{base_name}_grayscale.png"
                    img.convert("L").convert("RGB").save(gray_path)
                    variations["grayscale"] = gray_path
                except Exception:
                    pass

                # Rotations (90, 180, 270 degrees)
                for angle in [90, 180, 270]:
                    try:
                        rotated = img.rotate(angle, expand=True)
                        rot_path = parent / f"{base_name}_rot{angle}.png"
                        rotated.save(rot_path)
                        variations[f"rotated_{angle}"] = rot_path
                    except Exception:
                        pass

        except Exception:
            pass

        return variations

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
