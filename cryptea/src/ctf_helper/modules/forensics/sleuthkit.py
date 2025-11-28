"""Sleuthkit/Autopsy wrapper for disk analysis."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence

from ..base import ToolResult


def is_sleuthkit_available() -> bool:
    return shutil.which("fls") is not None and shutil.which("icat") is not None


def is_autopsy_available() -> bool:
    return shutil.which("autopsy") is not None


class SleuthkitProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    command: str


PROFILE_CHOICES: Sequence[SleuthkitProfile] = (
    SleuthkitProfile(
        "mmls",
        "Partition Layout",
        "Display partition table",
        "mmls",
    ),
    SleuthkitProfile(
        "fsstat",
        "Filesystem Info",
        "Display filesystem statistics",
        "fsstat",
    ),
    SleuthkitProfile(
        "fls",
        "File Listing",
        "List files and directories",
        "fls",
    ),
    SleuthkitProfile(
        "ils",
        "Inode Listing",
        "List inode information",
        "ils",
    ),
)


class SleuthkitTool:
    name = "Sleuthkit"
    description = "Disk analysis and file system forensics tools."
    category = "Forensics"

    def run(
        self,
        image_file: str,
        profile: str = "fls",
        offset: str = "",
        inode: str = "",
        recursive: str = "0",
        deleted: str = "0",
        extra: str = "",
        analyze_inode: str = "false",
        recover_deleted: str = "false",
        output_dir: str = "",
    ) -> ToolResult:
        if not is_sleuthkit_available():
            raise RuntimeError("sleuthkit tools not found in PATH. Install sleuthkit locally.")
        
        image_path = Path(image_file).expanduser()
        if not image_path.exists():
            raise FileNotFoundError(f"Image file not found: {image_file}")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[2]  # fls

        args: List[str] = [selected_profile.command]

        # Offset for partition
        if offset.strip():
            args.extend(["-o", offset.strip()])

        # Command-specific options
        if selected_profile.command == "fls":
            if _is_truthy(recursive):
                args.append("-r")
            if _is_truthy(deleted):
                args.append("-d")
        elif selected_profile.command == "ils":
            if _is_truthy(deleted):
                args.append("-e")

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Image file
        args.append(str(image_path))

        # Inode for fls
        if inode.strip() and selected_profile.command == "fls":
            args.append(inode.strip())

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        # Enhanced analysis
        analyze_inode_flag = _is_truthy(analyze_inode)
        recover_deleted_flag = _is_truthy(recover_deleted)
        
        # Inode analysis
        if analyze_inode_flag and inode.strip():
            inode_info = self._analyze_inode(image_path, inode.strip(), offset)
            if inode_info:
                body_lines.append("")
                body_lines.append("Inode Analysis:")
                body_lines.append(json.dumps(inode_info, indent=2))
        
        # Deleted file recovery
        if recover_deleted_flag:
            deleted_files = self._recover_deleted_files(image_path, offset, output_dir)
            if deleted_files:
                body_lines.append("")
                body_lines.append("Deleted File Recovery:")
                body_lines.append(json.dumps(deleted_files, indent=2))
        
        # Parse fls output for deleted files info
        if deleted and proc.stdout.strip() and selected_profile.command == "fls":
            deleted_analysis = self._analyze_deleted_files(proc.stdout)
            if deleted_analysis:
                body_lines.append("")
                body_lines.append("Deleted Files Analysis:")
                body_lines.append(json.dumps(deleted_analysis, indent=2))
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"Sleuthkit failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Sleuthkit {selected_profile.command}: {image_path.name}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

    def _analyze_inode(self, image_path: Path, inode: str, offset: str) -> Optional[Dict[str, object]]:
        """Analyze inode structure in detail."""
        if not shutil.which("istat"):
            return None
        
        args: List[str] = ["istat"]
        if offset.strip():
            args.extend(["-o", offset.strip()])
        args.extend([str(image_path), inode])
        
        try:
            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            
            if proc.returncode != 0:
                return None
            
            output = proc.stdout.strip()
            inode_info: Dict[str, object] = {
                "inode": inode,
                "raw_output": output,
            }
            
            # Parse istat output
            lines = output.splitlines()
            for line in lines:
                if ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        key = parts[0].strip().lower().replace(" ", "_")
                        value = parts[1].strip()
                        
                        # Extract specific fields
                        if "size" in key:
                            inode_info["size"] = value
                        elif "mode" in key or "permissions" in key:
                            inode_info["mode"] = value
                        elif "uid" in key or "user" in key:
                            inode_info["uid"] = value
                        elif "gid" in key or "group" in key:
                            inode_info["gid"] = value
                        elif "mtime" in key or "modified" in key:
                            inode_info["modified"] = value
                        elif "atime" in key or "accessed" in key:
                            inode_info["accessed"] = value
                        elif "ctime" in key or "created" in key:
                            inode_info["created"] = value
            
            # Get block information
            blocks = self._extract_inode_blocks(output)
            if blocks:
                inode_info["blocks"] = blocks
                inode_info["block_count"] = len(blocks)
            
            return inode_info
            
        except Exception:
            return None

    def _extract_inode_blocks(self, istat_output: str) -> List[str]:
        """Extract block numbers from istat output."""
        blocks: List[str] = []
        lines = istat_output.splitlines()
        
        for line in lines:
            # Look for block numbers (hexadecimal or decimal)
            block_matches = re.findall(r'\b(0x[0-9a-fA-F]+|\d+)\b', line)
            if "block" in line.lower() or "cluster" in line.lower():
                blocks.extend(block_matches[:10])  # Limit to 10 blocks per line
        
        return blocks[:50]  # Limit total blocks

    def _recover_deleted_files(self, image_path: Path, offset: str, output_dir: str) -> Optional[Dict[str, object]]:
        """Recover deleted files from the image."""
        if not shutil.which("icat"):
            return None
        
        # First, find deleted files using fls
        if not shutil.which("fls"):
            return None
        
        fls_args: List[str] = ["fls", "-d"]  # -d for deleted files
        if offset.strip():
            fls_args.extend(["-o", offset.strip()])
        fls_args.append(str(image_path))
        
        try:
            proc = subprocess.run(
                fls_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
            )
            
            if proc.returncode != 0:
                return None
            
            deleted_files = self._parse_deleted_files_list(proc.stdout)
            
            # Recover files if output directory specified
            recovered: List[Dict[str, object]] = []
            if output_dir.strip() and deleted_files:
                out_path = Path(output_dir.strip()).expanduser()
                out_path.mkdir(parents=True, exist_ok=True)
                
                for file_info in deleted_files[:20]:  # Limit to 20 files
                    inode_num_val = file_info.get("inode", "")
                    inode_num = str(inode_num_val) if inode_num_val else ""
                    if inode_num:
                        recovered_file = self._recover_file_by_inode(image_path, inode_num, offset, out_path)
                        if recovered_file:
                            recovered.append(recovered_file)
            
            return {
                "deleted_files_found": len(deleted_files),
                "files": deleted_files[:50],  # First 50
                "recovered": recovered if recovered else None,
            }
            
        except Exception:
            return None

    def _parse_deleted_files_list(self, fls_output: str) -> List[Dict[str, object]]:
        """Parse fls output to extract deleted file information."""
        deleted_files: List[Dict[str, object]] = []
        lines = fls_output.splitlines()
        
        for line in lines:
            # fls format: mode/uid/gid size mtime mtime_nano path
            # Deleted files are marked with * prefix
            if line.strip().startswith("*"):
                parts = line.split()
                if len(parts) >= 5:
                    mode = parts[0].replace("*", "")
                    inode_match = re.search(r'/(\d+):', parts[-1])
                    inode = inode_match.group(1) if inode_match else ""
                    
                    deleted_files.append({
                        "inode": inode,
                        "mode": mode,
                        "path": parts[-1].replace(f"/{inode}:", "") if inode else parts[-1],
                        "full_line": line.strip(),
                    })
        
        return deleted_files

    def _recover_file_by_inode(self, image_path: Path, inode: str, offset: str, output_dir: Path) -> Optional[Dict[str, object]]:
        """Recover a single file by inode number."""
        if not shutil.which("icat"):
            return None
        
        args: List[str] = ["icat"]
        if offset.strip():
            args.extend(["-o", offset.strip()])
        args.extend([str(image_path), inode])
        
        output_file = output_dir / f"recovered_inode_{inode}"
        
        try:
            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            
            if proc.returncode == 0 and proc.stdout:
                output_file.write_bytes(proc.stdout)
                return {
                    "inode": inode,
                    "output_file": str(output_file),
                    "size_bytes": len(proc.stdout),
                    "recovered": True,
                }
        except Exception:
            pass
        
        return None

    def _analyze_deleted_files(self, fls_output: str) -> Optional[Dict[str, object]]:
        """Analyze deleted files from fls output."""
        deleted_files = self._parse_deleted_files_list(fls_output)
        
        if not deleted_files:
            return None
        
        # Categorize by file type
        file_types: Dict[str, int] = {}
        for file_info in deleted_files:
            path = str(file_info.get("path", ""))
            ext = Path(path).suffix.lower() if path else ""
            file_type = ext if ext else "unknown"
            file_types[file_type] = file_types.get(file_type, 0) + 1
        
        return {
            "total_deleted": len(deleted_files),
            "by_type": file_types,
            "sample_files": deleted_files[:10],
        }


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}

