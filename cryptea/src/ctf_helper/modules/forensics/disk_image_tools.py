"""Disk image inspection helpers."""

from __future__ import annotations

import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, cast

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
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        sector = max(128, int(sector_size or "512"))
        include_hash = self._truthy(include_hashes)
        partition_limit = max(1, int(max_partitions or "16"))
        summary = self._analyze_disk(path, sector=sector, include_hashes=include_hash, max_partitions=partition_limit)
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
