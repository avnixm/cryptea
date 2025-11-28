"""Offline file inspection helpers."""

from __future__ import annotations

import hashlib
import io
import json
import math
import mimetypes
import re
import struct
import subprocess
import tarfile
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..base import ToolResult


class FileInspectorTool:
    name = "File Inspector"
    description = "Summarise metadata, hashes, and magic bytes for a local file."
    category = "Forensics"

    def run(
        self,
        file_path: str,
        preview_bytes: str = "256",
        include_entropy: str = "false",
        include_strings: str = "false",
        strings_min_length: str = "4",
        strings_limit: str = "15",
        detect_anomalies: str = "false",
        detect_containers: str = "false",
        enhanced_metadata: str = "false",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)
        data = path.read_bytes()

        stats = path.stat()
        preview_len = max(0, int(preview_bytes or "0"))
        preview_slice = data[:preview_len] if preview_len else b""

        info: Dict[str, object] = {
            "path": str(path.resolve()),
            "name": path.name,
            "size_bytes": stats.st_size,
            "permissions": oct(stats.st_mode & 0o777),
            "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
            "mimetype": mimetypes.guess_type(path.name)[0],
            "hashes": {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            "signatures": self._comprehensive_signature_analysis(data),
            "preview": {
                "bytes": preview_len,
                "hex": preview_slice.hex(),
                "ascii": preview_slice.decode("latin-1", errors="replace"),
            },
        }

        if self._truthy(include_entropy):
            info["entropy"] = round(self._shannon_entropy(data), 4)

        if self._truthy(include_strings):
            strings_payload = self._strings_preview(
                data,
                min_length=max(1, int(strings_min_length or "4")),
                limit=max(0, int(strings_limit or "0")),
            )
            if strings_payload:
                info["strings_preview"] = strings_payload

        if self._truthy(detect_containers):
            containers = self._detect_containers(data, path)
            if containers:
                info["containers"] = containers

        if self._truthy(detect_anomalies):
            anomalies = self._detect_anomalies(data, path)
            if anomalies:
                info["anomalies"] = anomalies

        if self._truthy(enhanced_metadata):
            enhanced = self._extract_enhanced_metadata(path, data)
            if enhanced:
                info["enhanced_metadata"] = enhanced

        archive_summary = self._archive_listing(path)
        if archive_summary:
            info["archive"] = archive_summary

        # Format validation
        validation = self._validate_format(data, path)
        if validation:
            info["format_validation"] = validation

        body = json.dumps(info, indent=2)
        return ToolResult(title=f"Metadata for {path.name}", body=body, mime_type="application/json")

    def _signature_hints(self, data: bytes) -> List[str]:
        """Legacy method for backward compatibility."""
        sigs = self._comprehensive_signature_analysis(data)
        return [str(sig.get("type", "Unknown")) for sig in sigs]

    def _comprehensive_signature_analysis(self, data: bytes) -> List[Dict[str, object]]:
        """Comprehensive magic byte database with verification."""
        signatures: List[Dict[str, object]] = []
        
        # Comprehensive magic byte database
        magic_signatures = [
            # Executables
            (b"\x7fELF", "ELF executable", 0, "binary"),
            (b"MZ", "PE executable (DOS/Windows)", 0, "binary"),
            (b"#!", "Shell script", 0, "text"),
            (b"\xfe\xed\xfa\xce", "Mach-O binary (32-bit)", 0, "binary"),
            (b"\xfe\xed\xfa\xcf", "Mach-O binary (64-bit)", 0, "binary"),
            (b"\xce\xfa\xed\xfe", "Mach-O binary (reverse endian)", 0, "binary"),
            
            # Archives
            (b"PK\x03\x04", "ZIP archive", 0, "archive"),
            (b"PK\x05\x06", "ZIP archive (empty)", 0, "archive"),
            (b"PK\x07\x08", "ZIP archive (spanned)", 0, "archive"),
            (b"Rar!\x1a\x07", "RAR archive (v1.5+)", 0, "archive"),
            (b"Rar!\x1a\x07\x00", "RAR archive (v5.0+)", 0, "archive"),
            (b"\x1f\x8b\x08", "GZIP archive", 0, "archive"),
            (b"BZ", "BZIP2 archive", 0, "archive"),
            (b"\x5d\x00\x00\x80", "LZMA archive", 0, "archive"),
            (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", 0, "archive"),
            (b"\x1f\x9d", "Z compressed file", 0, "archive"),
            (b"x\x9c", "Zlib compressed", 0, "archive"),
            
            # Images
            (b"\x89PNG\r\n\x1a\n", "PNG image", 0, "image"),
            (b"\xff\xd8\xff", "JPEG image", 0, "image"),
            (b"GIF87a", "GIF image (87a)", 0, "image"),
            (b"GIF89a", "GIF image (89a)", 0, "image"),
            (b"BM", "Windows bitmap", 0, "image"),
            (b"RIFF", "RIFF container (WAV/AVI/WEBP)", 0, "media"),
            (b"WEBP", "WebP image", 8, "image"),
            (b"ftyp", "QuickTime/MOV/MP4", 4, "media"),
            (b"\x00\x00\x00\x18ftyp", "MP4 video", 0, "media"),
            (b"\x00\x00\x00\x20ftyp", "MP4 video", 0, "media"),
            (b"\x42\x4d", "Windows bitmap", 0, "image"),
            
            # Documents
            (b"%PDF", "PDF document", 0, "document"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Microsoft Office/OLE2", 0, "document"),
            (b"PK\x03\x04", "Office Open XML", 0, "document"),  # Also ZIP
            (b"{\\rtf1", "Rich Text Format", 0, "document"),
            
            # Audio
            (b"ID3", "MP3 (ID3v2)", 0, "audio"),
            (b"\xff\xfb", "MP3 (no ID3)", 0, "audio"),
            (b"\xff\xf3", "MP3 (no ID3)", 0, "audio"),
            (b"\xff\xf2", "MP3 (no ID3)", 0, "audio"),
            (b"OggS", "Ogg Vorbis/Opus", 0, "audio"),
            (b"fLaC", "FLAC audio", 0, "audio"),
            (b"RIFF", "WAV audio", 0, "audio"),
            
            # Video
            (b"\x1a\x45\xdf\xa3", "Matroska (MKV/WebM)", 0, "video"),
            (b"FLV", "Flash Video", 0, "video"),
            (b"\x00\x00\x00\x20ftyp", "MP4/M4V", 0, "video"),
            
            # Databases
            (b"SQLite format 3\x00", "SQLite database", 0, "database"),
            (b"Standard Jet DB", "Microsoft Access", 0, "database"),
            
            # Disk images
            (b"BOOTMGR", "Windows boot manager", 0, "disk"),
            (b"\x55\xaa", "Boot sector (MBR)", 510, "disk"),
            (b"EFI PART", "GPT partition table", 0, "disk"),
            
            # Network/capture
            (b"\xd4\xc3\xb2\xa1", "PCAP capture", 0, "network"),
            (b"\xa1\xb2\xc3\xd4", "PCAP capture (big-endian)", 0, "network"),
            (b"\x0a\x0d\x0d\x0a", "PCAPNG capture", 0, "network"),
            
            # Other
            (b"#!/bin/sh", "Shell script", 0, "script"),
            (b"#!/bin/bash", "Bash script", 0, "script"),
            (b"#!/usr/bin/env python", "Python script", 0, "script"),
            (b"#!/usr/bin/env perl", "Perl script", 0, "script"),
            (b"<?xml", "XML document", 0, "markup"),
            (b"<!DOCTYPE html", "HTML document", 0, "markup"),
            (b"<!DOCTYPE HTML", "HTML document", 0, "markup"),
            (b"<?php", "PHP script", 0, "script"),
            (b"#define", "C/C++ header", 0, "code"),
            (b"import ", "Python script", 0, "code"),
            (b"package ", "Java/Go source", 0, "code"),
        ]
        
        for magic, label, offset, category in magic_signatures:
            if len(data) < len(magic) + offset:
                continue
            if data[offset:offset+len(magic)] == magic:
                signatures.append({
                    "type": label,
                    "category": category,
                    "confidence": "high",
                    "offset": offset,
                    "magic_bytes": magic.hex(),
                })
                break
        
        # Also check for embedded signatures within file
        embedded = self._scan_for_embedded_signatures(data)
        if embedded:
            signatures.extend(embedded)
        
        if not signatures:
            signatures.append({
                "type": "Unknown/opaque",
                "category": "unknown",
                "confidence": "low",
                "offset": 0,
                "magic_bytes": "",
            })
        
        return signatures

    def _scan_for_embedded_signatures(self, data: bytes) -> List[Dict[str, object]]:
        """Scan for embedded file signatures within the file."""
        embedded: List[Dict[str, object]] = []
        
        # Common embedded signatures to look for
        embedded_patterns = [
            (b"PNG", "Possible embedded PNG", 1),
            (b"JFIF", "Possible embedded JPEG", 6),
            (b"PK\x03\x04", "Possible embedded ZIP/archive", 2),
            (b"%PDF", "Possible embedded PDF", 1),
        ]
        
        for i in range(0, min(len(data), 1024 * 1024), 512):  # Scan first MB in 512-byte chunks
            chunk = data[i:i+512]
            for pattern, label, min_count in embedded_patterns:
                count = chunk.count(pattern)
                if count >= min_count:
                    embedded.append({
                        "type": label,
                        "category": "embedded",
                        "confidence": "medium" if count > min_count else "low",
                        "offset": i,
                        "occurrences": count,
                    })
        
        return embedded[:5]  # Limit to 5 results

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((count / total) * math.log2(count / total) for count in counts.values())

    def _strings_preview(self, data: bytes, *, min_length: int, limit: int) -> List[str]:
        results: List[str] = []
        current: bytearray = bytearray()
        for byte in data:
            if 32 <= byte <= 126:
                current.append(byte)
            else:
                if len(current) >= min_length:
                    results.append(current.decode("ascii", errors="ignore"))
                current.clear()
        if len(current) >= min_length:
            results.append(current.decode("ascii", errors="ignore"))
        if limit > 0:
            results = results[:limit]
        return results

    def _archive_listing(self, path: Path) -> Dict[str, object] | None:
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    members = archive.namelist()
                    return {"member_count": len(members), "members": members[:20]}
            if tarfile.is_tarfile(path):
                with tarfile.open(path) as archive:
                    members = archive.getmembers()
                    return {
                        "member_count": len(members),
                        "members": [member.name for member in members[:20]],
                    }
        except (OSError, tarfile.ReadError, zipfile.BadZipFile):
            return {"error": "Archive detected but couldn't be read"}
        return None

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _detect_anomalies(self, data: bytes, path: Path) -> List[Dict[str, object]]:
        """Detect file corruption, mis-labeling, and format inconsistencies."""
        anomalies: List[Dict[str, object]] = []
        
        # Check extension vs actual content
        ext = path.suffix.lower()
        signatures = self._comprehensive_signature_analysis(data)
        
        if signatures:
            detected_type = signatures[0].get("category", "unknown")
            extension_map = {
                ".exe": "binary",
                ".bin": "binary",
                ".dll": "binary",
                ".so": "binary",
                ".jpg": "image",
                ".jpeg": "image",
                ".png": "image",
                ".gif": "image",
                ".pdf": "document",
                ".zip": "archive",
                ".rar": "archive",
                ".tar": "archive",
                ".gz": "archive",
                ".txt": "text",
                ".html": "markup",
                ".xml": "markup",
            }
            
            expected_category = extension_map.get(ext, "unknown")
            if expected_category != "unknown" and detected_type != "unknown":
                if expected_category != detected_type:
                    anomalies.append({
                        "type": "extension_mismatch",
                        "severity": "medium",
                        "message": f"File extension '{ext}' suggests {expected_category}, but content appears to be {detected_type}",
                    })
        
        # Check for corruption in common formats
        if data.startswith(b"%PDF"):
            if not self._validate_pdf_structure(data):
                anomalies.append({
                    "type": "pdf_corruption",
                    "severity": "high",
                    "message": "PDF structure appears corrupted or invalid",
                })
        
        if data.startswith(b"PK\x03\x04"):
            if not self._validate_zip_structure(data):
                anomalies.append({
                    "type": "zip_corruption",
                    "severity": "high",
                    "message": "ZIP archive structure appears corrupted or invalid",
                })
        
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            if not self._validate_png_structure(data):
                anomalies.append({
                    "type": "png_corruption",
                    "severity": "high",
                    "message": "PNG structure appears corrupted or invalid",
                })
        
        # Check for suspicious patterns
        if len(data) > 100:
            # High entropy suggests encryption/compression
            entropy = self._shannon_entropy(data[:1024])
            if entropy > 7.5:
                anomalies.append({
                    "type": "high_entropy",
                    "severity": "low",
                    "message": f"High entropy ({entropy:.2f}) suggests encryption or compression",
                })
            
            # Check for null bytes in text-like files
            if ext in [".txt", ".html", ".xml", ".json", ".csv"]:
                null_count = data.count(b"\x00")
                if null_count > len(data) * 0.01:  # More than 1% null bytes
                    anomalies.append({
                        "type": "unexpected_null_bytes",
                        "severity": "medium",
                        "message": f"Text file contains {null_count} null bytes (may be binary)",
                    })
        
        # Check file size vs content consistency
        if len(data) < 10:
            anomalies.append({
                "type": "suspiciously_small",
                "severity": "low",
                "message": "File is very small (< 10 bytes)",
            })
        
        return anomalies

    def _detect_containers(self, data: bytes, path: Path) -> List[Dict[str, object]]:
        """Identify nested archives and containerized files."""
        containers: List[Dict[str, object]] = []
        
        # Check if file itself is a container
        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as zf:
                    for member in zf.namelist()[:20]:  # Limit to 20
                        member_data = zf.read(member)
                        nested_sigs = self._comprehensive_signature_analysis(member_data)
                        if nested_sigs and nested_sigs[0].get("category") != "unknown":
                            containers.append({
                                "path": member,
                                "type": nested_sigs[0].get("type", "unknown"),
                                "size": len(member_data),
                                "nested": True,
                            })
            except Exception:
                pass
        
        if tarfile.is_tarfile(path):
            try:
                with tarfile.open(path) as tar:
                    for member in tar.getmembers()[:20]:
                        if member.isfile():
                            containers.append({
                                "path": member.name,
                                "type": "tar_member",
                                "size": member.size,
                                "nested": True,
                            })
            except Exception:
                pass
        
        # Check for embedded containers in binary files
        embedded_containers = self._find_embedded_containers(data)
        containers.extend(embedded_containers)
        
        return containers[:30]  # Limit results

    def _find_embedded_containers(self, data: bytes) -> List[Dict[str, object]]:
        """Find embedded archive/file signatures in binary data."""
        containers: List[Dict[str, object]] = []
        
        # Look for ZIP signatures
        zip_sig = b"PK\x03\x04"
        offset = 0
        while True:
            offset = data.find(zip_sig, offset)
            if offset == -1 or offset > len(data) - 30:
                break
            # Try to read ZIP header
            try:
                if offset + 30 <= len(data):
                    # Check for valid ZIP local file header
                    header = data[offset:offset+30]
                    if len(header) >= 30:
                        filename_len = struct.unpack("<H", header[26:28])[0]
                        extra_len = struct.unpack("<H", header[28:30])[0]
                        if filename_len < 256 and offset + 30 + filename_len + extra_len < len(data):
                            containers.append({
                                "path": f"<embedded@{offset}>",
                                "type": "ZIP archive (embedded)",
                                "offset": offset,
                                "size": "unknown",
                                "nested": True,
                            })
            except Exception:
                pass
            offset += 1
            if len(containers) >= 5:
                break
        
        return containers

    def _extract_enhanced_metadata(self, path: Path, data: bytes) -> Dict[str, object]:
        """Extract enhanced metadata (EXIF, IPTC, document properties)."""
        metadata: Dict[str, object] = {}
        
        # Try to extract EXIF data using exiftool if available
        try:
            exiftool_path = self._resolve_exiftool()
            if exiftool_path:
                proc = subprocess.run(
                    [exiftool_path, "-j", "-g", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout:
                    import json
                    exif_data = json.loads(proc.stdout)
                    if exif_data and len(exif_data) > 0:
                        metadata["exif"] = exif_data[0]
        except Exception:
            pass
        
        # Extract basic metadata from file signatures
        if data.startswith(b"PK\x03\x04"):
            metadata["container"] = "ZIP"
            metadata["zip_info"] = self._extract_zip_metadata(path)
        
        if data.startswith(b"%PDF"):
            metadata["container"] = "PDF"
            pdf_meta = self._extract_pdf_metadata(data)
            if pdf_meta:
                metadata["pdf_info"] = pdf_meta
        
        return metadata

    def _resolve_exiftool(self) -> Optional[str]:
        """Resolve exiftool command path."""
        import shutil
        path = shutil.which("exiftool")
        return path if path else None

    def _extract_zip_metadata(self, path: Path) -> Dict[str, object]:
        """Extract ZIP metadata."""
        try:
            with zipfile.ZipFile(path) as zf:
                return {
                    "file_count": len(zf.namelist()),
                    "comment": zf.comment.decode("utf-8", errors="ignore") if zf.comment else "",
                    "compression_methods": list(set(info.compress_type for info in zf.infolist())),
                }
        except Exception:
            return {}

    def _extract_pdf_metadata(self, data: bytes) -> Dict[str, object]:
        """Extract basic PDF metadata."""
        try:
            # Look for PDF metadata
            text_data = data[:min(8192, len(data))].decode("latin-1", errors="ignore")
            
            metadata = {}
            
            # Extract PDF version
            version_match = re.search(r"%PDF-(\d\.\d)", text_data)
            if version_match:
                metadata["version"] = version_match.group(1)
            
            # Look for common PDF metadata keys
            metadata_keys = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"]
            for key in metadata_keys:
                pattern = rf"/{key}\s*\(([^)]+)\)"
                match = re.search(pattern, text_data)
                if match:
                    metadata[key.lower()] = match.group(1).strip()
            
            return metadata
        except Exception:
            return {}

    def _validate_format(self, data: bytes, path: Path) -> Dict[str, object]:
        """Verify file integrity based on format specifications."""
        issues: List[str] = []
        validation: Dict[str, object] = {
            "valid": True,
            "issues": issues,
        }
        
        if data.startswith(b"%PDF"):
            pdf_valid = self._validate_pdf_structure(data)
            validation["valid"] = pdf_valid
            if not pdf_valid:
                issues.append("PDF structure validation failed")
        
        elif data.startswith(b"PK\x03\x04"):
            zip_valid = self._validate_zip_structure(data)
            validation["valid"] = zip_valid
            if not zip_valid:
                issues.append("ZIP structure validation failed")
        
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            png_valid = self._validate_png_structure(data)
            validation["valid"] = png_valid
            if not png_valid:
                issues.append("PNG structure validation failed")
        
        elif data.startswith(b"\xff\xd8\xff"):
            jpeg_valid = self._validate_jpeg_structure(data)
            validation["valid"] = jpeg_valid
            if not jpeg_valid:
                issues.append("JPEG structure validation failed")
        
        if not issues:
            validation.pop("issues")
        
        return validation

    def _validate_pdf_structure(self, data: bytes) -> bool:
        """Validate PDF structure."""
        if not data.startswith(b"%PDF-"):
            return False
        # Check for EOF marker
        if b"%%EOF" not in data[-1024:]:
            return False
        return True

    def _validate_zip_structure(self, data: bytes) -> bool:
        """Validate ZIP structure."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.testzip()
            return True
        except Exception:
            return False

    def _validate_png_structure(self, data: bytes) -> bool:
        """Validate PNG structure."""
        if len(data) < 8:
            return False
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return False
        # Check for IEND chunk at end
        if len(data) < 12:
            return False
        if data[-12:-4] != b"IEND":
            return False
        return True

    def _validate_jpeg_structure(self, data: bytes) -> bool:
        """Validate JPEG structure."""
        if len(data) < 4:
            return False
        if data[:2] != b"\xff\xd8":
            return False
        # Check for JPEG end marker
        if data[-2:] != b"\xff\xd9":
            return False
        return True
