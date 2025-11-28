"""Disk image inspection helpers."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

from ..base import ToolResult


class DiskImageToolkit:
    """Offline-friendly parser for raw disk images (MBR/GPT)."""

    name = "Disk Image Tools"
    description = "Parse partition tables, estimate layouts, and compute optional hashes."
    category = "Forensics"

    def run(
        self,
        file_path: str,
        sector_size: str = "512",
        include_hashes: str = "false",
        max_partitions: str = "16",
        detect_hidden: str = "false",
        navigate_filesystems: str = "false",
        partition_index: str = "",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        sector = max(128, int(sector_size or "512"))
        include_hash = self._truthy(include_hashes)
        partition_limit = max(1, int(max_partitions or "16"))
        detect_hidden_partitions = self._truthy(detect_hidden)
        navigate_fs = self._truthy(navigate_filesystems)
        
        # Check for E01 format
        e01_info = self._detect_e01_format(path)
        
        # Use ewfmount if E01, otherwise use raw image
        if e01_info.get("is_e01"):
            # For E01, we'd need to mount it first, but we'll provide basic info
            summary = self._analyze_e01(path, e01_info)
        else:
            summary = self._analyze_disk(path, sector=sector, include_hashes=include_hash, max_partitions=partition_limit)
        
        # Detect hidden partitions
        if detect_hidden_partitions:
            hidden = self._detect_hidden_partitions(path, summary, sector)
            if hidden:
                summary["hidden_partitions"] = hidden
        
        # Navigate file systems
        if navigate_fs:
            partition_idx = int(partition_index) if partition_index.strip() else None
            filesystem_info = self._navigate_file_systems(path, summary, partition_idx)
            if filesystem_info:
                summary["filesystems"] = filesystem_info
        
        body = json.dumps(summary, indent=2)
        title = f"Disk analysis for {path.name}"
        return ToolResult(title=title, body=body, mime_type="application/json")

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def _analyze_disk(
        self,
        path: Path,
        *,
        sector: int,
        include_hashes: bool,
        max_partitions: int,
    ) -> Dict[str, object]:
        stats = path.stat()
        header_len = max(sector * 2, 4096)
        with path.open("rb") as fh:
            header = fh.read(header_len)

        if len(header) < 512:
            raise ValueError("Image is too small to contain an MBR header")

        warnings: List[str] = []
        partitions: List[Dict[str, object]] = []
        scheme = "Unknown"

        mbr_signature = header[510:512]
        mbr_info: Dict[str, object] | None = None
        if mbr_signature == b"\x55\xaa":
            mbr_info = self._parse_mbr(header, sector)
            mbr_parts = cast(List[Dict[str, object]], mbr_info.get("partitions", []))
            partitions.extend(mbr_parts)
            scheme = "MBR"
        else:
            warnings.append("No legacy MBR signature detected")

        gpt_info: Dict[str, object] | None = None
        if len(header) >= sector * 2:
            gpt_header = header[sector : sector + 92]
            if gpt_header.startswith(b"EFI PART"):
                try:
                    gpt_info = self._parse_gpt(path, sector, max_partitions)
                    scheme = "GPT"
                    partitions = cast(List[Dict[str, object]], gpt_info.get("partitions", []))
                except ValueError as exc:
                    warnings.append(f"GPT parsing failed: {exc}")

        partitions = partitions[:max_partitions]
        allocated_bytes = sum(int(cast(Any, part.get("size_bytes", 0)) or 0) for part in partitions)
        unallocated = max(0, stats.st_size - allocated_bytes)

        payload: Dict[str, object] = {
            "file": str(path.resolve()),
            "size_bytes": stats.st_size,
            "modified": datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat(),
            "partition_scheme": scheme,
            "partitions": partitions,
            "unallocated_bytes": unallocated,
        }
        if mbr_info is not None:
            payload["mbr"] = mbr_info
        if gpt_info is not None:
            payload["gpt"] = gpt_info
        if warnings:
            payload["warnings"] = warnings
        if include_hashes:
            payload["hashes"] = self._compute_hashes(path)
        return payload

    def _parse_mbr(self, header: bytes, sector: int) -> Dict[str, object]:
        entries: List[Dict[str, object]] = []
        for index in range(4):
            offset = 446 + index * 16
            entry = header[offset : offset + 16]
            status = entry[0]
            part_type = entry[4]
            first_lba = int.from_bytes(entry[8:12], "little")
            sector_count = int.from_bytes(entry[12:16], "little")
            if part_type == 0 and first_lba == 0 and sector_count == 0:
                continue
            entry_info = {
                "index": index,
                "status": self._partition_status(status),
                "type_id": f"0x{part_type:02x}",
                "label": self._mbr_type_label(part_type),
                "first_lba": first_lba,
                "sector_count": sector_count,
                "start_bytes": first_lba * sector,
                "size_bytes": sector_count * sector,
            }
            entries.append(entry_info)
        return {"partitions": entries}

    def _parse_gpt(self, path: Path, sector: int, max_partitions: int) -> Dict[str, object]:
        with path.open("rb") as fh:
            fh.seek(sector)
            header = fh.read(92)
            if not header.startswith(b"EFI PART"):
                raise ValueError("Invalid GPT signature")
            (
                signature,
                revision,
                header_size,
                header_crc,
                _reserved,
                current_lba,
                backup_lba,
                first_usable,
                last_usable,
                disk_guid_raw,
                entries_lba,
                entry_count,
                entry_size,
                entries_crc,
            ) = struct.unpack("<8sIIIIQQQQ16sQIII", header)

            fh.seek(entries_lba * sector)
            entries_data = fh.read(entry_size * min(entry_count, max_partitions))

        partitions: List[Dict[str, object]] = []
        for idx in range(min(entry_count, max_partitions)):
            start = idx * entry_size
            chunk = entries_data[start : start + entry_size]
            if len(chunk) < entry_size:
                break
            part_type_guid = chunk[0:16]
            if set(part_type_guid) == {0}:
                continue
            unique_guid = chunk[16:32]
            first_lba = int.from_bytes(chunk[32:40], "little")
            last_lba = int.from_bytes(chunk[40:48], "little")
            attrs = int.from_bytes(chunk[48:56], "little")
            name_bytes = chunk[56:entry_size]
            try:
                name = name_bytes.decode("utf-16le").rstrip("\x00")
            except UnicodeDecodeError:
                name = name_bytes.decode("latin-1", errors="replace").rstrip("\x00")
            partitions.append(
                {
                    "index": idx,
                    "type_guid": self._format_guid(part_type_guid),
                    "type_label": self._gpt_type_label(part_type_guid),
                    "unique_guid": self._format_guid(unique_guid),
                    "first_lba": first_lba,
                    "last_lba": last_lba,
                    "sector_count": (last_lba - first_lba + 1) if last_lba >= first_lba else 0,
                    "size_bytes": (last_lba - first_lba + 1) * sector if last_lba >= first_lba else 0,
                    "attributes": attrs,
                    "name": name or None,
                }
            )

        gpt_info: Dict[str, object] = {
            "revision": f"{revision >> 16}.{revision & 0xFFFF}",
            "header_size": header_size,
            "header_crc32": header_crc,
            "current_lba": current_lba,
            "backup_lba": backup_lba,
            "first_usable_lba": first_usable,
            "last_usable_lba": last_usable,
            "disk_guid": self._format_guid(disk_guid_raw),
            "entry_count": entry_count,
            "entry_size": entry_size,
            "entries_crc32": entries_crc,
            "partitions": partitions,
        }
        return gpt_info

    def _compute_hashes(self, path: Path) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        chunk_size = 1 << 20
        with path.open("rb") as fh:
            while chunk := fh.read(chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    def _partition_status(self, status: int) -> str:
        if status == 0x80:
            return "bootable"
        if status == 0x00:
            return "inactive"
        return f"0x{status:02x}"

    def _mbr_type_label(self, part_type: int) -> str:
        mapping = {
            0x00: "Empty",
            0x01: "FAT12",
            0x04: "FAT16 (<=32M)",
            0x05: "Extended",
            0x06: "FAT16",
            0x07: "NTFS/HPFS/exFAT",
            0x0b: "FAT32 (CHS)",
            0x0c: "FAT32 (LBA)",
            0x0e: "FAT16 (LBA)",
            0x0f: "Extended (LBA)",
            0x11: "Hidden FAT12",
            0x17: "Hidden NTFS",
            0x1b: "Hidden FAT32",
            0x1e: "Hidden FAT16",
            0x27: "Windows RE/Hidden NTFS",
            0x82: "Linux swap",
            0x83: "Linux",
            0x85: "Linux extended",
            0x86: "NTFS volume set",
            0x87: "NTFS volume set",
            0xa5: "FreeBSD",
            0xa6: "OpenBSD",
            0xa8: "Mac OS X",
            0xab: "Mac OS X boot",
            0xaf: "Mac OS X HFS+",
            0xee: "GPT protective",
            0xef: "EFI system",
        }
        return mapping.get(part_type, "Unknown/Custom")

    def _gpt_type_label(self, guid_bytes: bytes) -> str:
        guid = self._format_guid(guid_bytes).lower()
        mapping = {
            "00000000-0000-0000-0000-000000000000": "Unused",
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System Partition",
            "21686148-6449-6e6f-744e-656564454649": "BIOS boot partition",
            "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Windows Basic Data",
            "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "Windows Logical Disk Manager",
            "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
            "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
            "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "Linux /home",
            "8da63339-0007-60c0-c436-083ac8230908": "Linux reserved",
            "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
            "55465300-0000-11aa-aa11-00306543ecac": "Apple APFS",
            "6a898cc3-1dd2-11b2-99a6-080020736631": "Solaris /usr",
        }
        return mapping.get(guid, "Unknown/Custom GUID")

    def _format_guid(self, raw: bytes) -> str:
        if len(raw) != 16:
            return raw.hex()
        data1 = int.from_bytes(raw[0:4], "little")
        data2 = int.from_bytes(raw[4:6], "little")
        data3 = int.from_bytes(raw[6:8], "little")
        data4 = raw[8:10]
        data5 = raw[10:16]
        return f"{data1:08x}-{data2:04x}-{data3:04x}-{data4.hex()}-{data5.hex()}"

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _detect_e01_format(self, path: Path) -> Dict[str, object]:
        """Detect if file is in E01 (Expert Witness Disk Image) format."""
        try:
            with path.open("rb") as fh:
                header = fh.read(64)
        except Exception:
            return {"is_e01": False, "message": "Could not read file header"}
        
        # E01 files start with "EVF" signature
        if header[:3] == b"EVF":
            return {
                "is_e01": True,
                "version": header[4:8].decode("ascii", errors="ignore") if len(header) >= 8 else "unknown",
                "message": "E01 (Expert Witness Disk Image) format detected",
            }
        
        # Check for E01 segment file pattern
        if path.suffix.lower() == ".e01":
            return {
                "is_e01": True,
                "message": "E01 format (based on extension)",
                "note": "Full E01 parsing requires ewftools or pyewf library",
            }
        
        return {"is_e01": False}

    def _analyze_e01(self, path: Path, e01_info: Dict[str, object]) -> Dict[str, object]:
        """Analyze E01 format disk image."""
        ewf_path = self._resolve_ewftools()
        
        if not ewf_path:
            return {
                "file": str(path.resolve()),
                "format": "E01",
                "error": "ewftools not available. Install with:\n  Fedora/RHEL: sudo dnf install libewf-tools\n  Ubuntu/Debian: sudo apt install ewf-tools\n  Arch: sudo pacman -S libewf-tools",
            }
        
        # Use ewfinfo to get basic information
        try:
            proc = subprocess.run(
                [ewf_path, str(path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            
            info: Dict[str, object] = {
                "file": str(path.resolve()),
                "format": "E01",
                "ewfinfo_available": True,
                "raw_output": proc.stdout or "",
            }
            
            # Parse ewfinfo output (simplified)
            if proc.stdout:
                lines = proc.stdout.splitlines()
                for line in lines[:50]:  # First 50 lines
                    if ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip()
                            info[key.lower().replace(" ", "_")] = value
            
            return info
            
        except Exception as e:
            return {
                "file": str(path.resolve()),
                "format": "E01",
                "error": f"Could not analyze E01 file: {str(e)}",
            }

    def _resolve_ewftools(self) -> Optional[str]:
        """Resolve ewfinfo command path."""
        path = shutil.which("ewfinfo")
        return path if path else None

    def _detect_hidden_partitions(self, path: Path, summary: Dict[str, object], sector: int) -> List[Dict[str, object]]:
        """Detect hidden partitions in unallocated space."""
        hidden: List[Dict[str, object]] = []
        
        partitions = summary.get("partitions", [])
        if not isinstance(partitions, list):
            return hidden
        
        # Get partition ranges
        partition_ranges: List[Tuple[int, int]] = []
        for part in partitions:
            if not isinstance(part, dict):
                continue
            start_val = part.get("start_bytes", 0)
            size_val = part.get("size_bytes", 0)
            start = int(start_val) if start_val else 0
            size = int(size_val) if size_val else 0
            if start > 0 and size > 0:
                partition_ranges.append((start, start + size))
        
        # Sort ranges
        partition_ranges.sort()
        
        # Look for gaps or suspicious areas
        stats = path.stat()
        total_size = stats.st_size
        current_offset = 0
        
        # Check gaps between partitions
        for start, end in partition_ranges:
            if current_offset < start:
                gap_size = start - current_offset
                if gap_size > sector * 100:  # Gap larger than 100 sectors
                    # Scan gap for partition signatures
                    signature = self._scan_for_partition_signature(path, current_offset, gap_size, sector)
                    if signature:
                        hidden.append({
                            "offset": current_offset,
                            "size_bytes": gap_size,
                            "type": signature["type"],
                            "signature": signature["description"],
                            "confidence": "medium",
                        })
            current_offset = max(current_offset, end)
        
        # Check unallocated space at end
        unallocated = summary.get("unallocated_bytes", 0)
        if unallocated and isinstance(unallocated, (int, float)):
            unalloc_val = int(unallocated)
            if unalloc_val > sector * 100:
                last_partition_end = partition_ranges[-1][1] if partition_ranges else 0
                signature = self._scan_for_partition_signature(path, last_partition_end, unalloc_val, sector)
                if signature:
                    hidden.append({
                        "offset": last_partition_end,
                        "size_bytes": unalloc_val,
                        "type": signature["type"],
                        "signature": signature["description"],
                        "confidence": "medium",
                    })
        
        return hidden

    def _scan_for_partition_signature(self, path: Path, offset: int, size: int, sector: int) -> Optional[Dict[str, str]]:
        """Scan a region for partition table signatures."""
        try:
            with path.open("rb") as fh:
                fh.seek(offset)
                # Read first few sectors
                sample = fh.read(min(size, sector * 4))
                
                # Check for MBR signature
                if len(sample) >= 512:
                    if sample[510:512] == b"\x55\xaa":
                        return {"type": "MBR", "description": "Legacy MBR partition table detected"}
                    
                    # Check for GPT signature
                    if sample[sector:sector+8] == b"EFI PART":
                        return {"type": "GPT", "description": "GPT partition table detected"}
                    
                    # Check for common file system signatures
                    fs_signatures = [
                        (b"\xEB\x58\x90", "FAT32"),
                        (b"NTFS", "NTFS"),
                        (b"\x53\xEF", "ext2/3/4"),
                        (b"FAT12", "FAT12"),
                        (b"FAT16", "FAT16"),
                    ]
                    
                    for sig_bytes, fs_type in fs_signatures:
                        if sig_bytes in sample[:1024]:
                            return {"type": fs_type, "description": f"{fs_type} file system signature detected"}
        except Exception:
            pass
        
        return None

    def _navigate_file_systems(self, path: Path, summary: Dict[str, object], partition_idx: Optional[int]) -> Dict[str, object]:
        """Navigate and list files in detected file systems."""
        filesystems: Dict[str, object] = {}
        
        partitions = summary.get("partitions", [])
        if not isinstance(partitions, list):
            return filesystems
        
        # If specific partition index provided, only analyze that
        partitions_to_analyze = []
        if partition_idx is not None and 0 <= partition_idx < len(partitions):
            partitions_to_analyze = [partitions[partition_idx]]
        else:
            partitions_to_analyze = partitions[:10]  # Limit to first 10
        
        for part in partitions_to_analyze:
            if not isinstance(part, dict):
                continue
            
            idx = part.get("index", -1)
            start_val = part.get("start_bytes", 0)
            size_val = part.get("size_bytes", 0)
            part_type = str(part.get("label", "")).lower()
            
            start = int(start_val) if start_val else 0
            size = int(size_val) if size_val else 0
            
            if start == 0 or size == 0:
                continue
            
            # Detect file system type
            fs_type = self._detect_file_system(path, start, size)
            if not fs_type:
                continue
            
            # List files (basic implementation)
            files = self._list_files_in_partition(path, start, size, fs_type)
            
            partition_key = f"partition_{idx}"
            filesystems[partition_key] = {
                "partition_index": idx,
                "filesystem_type": fs_type,
                "files": files[:100],  # Limit to 100 files
                "file_count": len(files),
            }
        
        return filesystems

    def _detect_file_system(self, path: Path, offset: int, size: int) -> Optional[str]:
        """Detect file system type in a partition."""
        try:
            with path.open("rb") as fh:
                fh.seek(offset)
                boot_sector = fh.read(1024)
                
                # Check for NTFS
                if boot_sector[3:7] == b"NTFS":
                    return "NTFS"
                
                # Check for FAT32
                if boot_sector[82:90] == b"FAT32   " or boot_sector[54:62] == b"FAT32   ":
                    return "FAT32"
                
                # Check for FAT16
                if boot_sector[54:62] == b"FAT16   ":
                    return "FAT16"
                
                # Check for FAT12
                if boot_sector[54:62] == b"FAT12   ":
                    return "FAT12"
                
                # Check for ext2/3/4 (magic at offset 0x438)
                if len(boot_sector) > 1080:
                    ext_magic = boot_sector[1080:1084]
                    if ext_magic in [b"\x53\xef", b"\xef\x53"]:
                        return "ext2/3/4"
                
        except Exception:
            pass
        
        return None

    def _list_files_in_partition(self, path: Path, offset: int, size: int, fs_type: str) -> List[Dict[str, object]]:
        """List files in a partition (basic implementation)."""
        files: List[Dict[str, object]] = []
        
        # This is a simplified implementation
        # Full implementation would require mounting or using libraries like pytsk3
        
        # For now, we'll search for file signatures in the partition
        try:
            with path.open("rb") as fh:
                fh.seek(offset)
                # Sample first 10MB of partition
                sample = fh.read(min(size, 10 * 1024 * 1024))
                
                # Search for common file signatures
                file_signatures = [
                    (b"\x89PNG\r\n\x1a\n", ".png"),
                    (b"\xff\xd8\xff", ".jpg"),
                    (b"%PDF", ".pdf"),
                    (b"PK\x03\x04", ".zip"),
                    (b"<!DOCTYPE html", ".html"),
                    (b"<?xml", ".xml"),
                ]
                
                for sig, ext in file_signatures:
                    idx = 0
                    while True:
                        idx = sample.find(sig, idx)
                        if idx == -1:
                            break
                        files.append({
                            "name": f"file{len(files)}{ext}",
                            "offset": offset + idx,
                            "type": ext,
                            "method": "signature_carving",
                        })
                        idx += len(sig)
                        if len(files) >= 50:
                            break
                    if len(files) >= 50:
                        break
        except Exception:
            pass
        
        return files
