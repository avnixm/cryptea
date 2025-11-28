"""Foremost wrapper for file carving from disk images."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence

from ..base import ToolResult


def is_foremost_available() -> bool:
    return shutil.which("foremost") is not None


class ForemostProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[ForemostProfile] = (
    ForemostProfile(
        "all",
        "All Types",
        "Carve all supported file types",
        ("-t", "all"),
    ),
    ForemostProfile(
        "images",
        "Images",
        "Carve image files (jpg, png, gif, bmp)",
        ("-t", "jpg,png,gif,bmp"),
    ),
    ForemostProfile(
        "documents",
        "Documents",
        "Carve document files (pdf, doc, xls, ppt)",
        ("-t", "pdf,doc,xls,ppt"),
    ),
    ForemostProfile(
        "archives",
        "Archives",
        "Carve archive files (zip, rar, gz)",
        ("-t", "zip,rar,gz"),
    ),
    ForemostProfile(
        "executables",
        "Executables",
        "Carve executable files (exe, elf)",
        ("-t", "exe,elf"),
    ),
)


class ForemostTool:
    name = "Foremost"
    description = "File carving tool for recovering files from disk images."
    category = "Forensics"

    def run(
        self,
        input_file: str,
        profile: str = "all",
        output_dir: str = "",
        file_types: str = "",
        extra: str = "",
        custom_header: str = "",
        custom_footer: str = "",
        custom_config: str = "",
    ) -> ToolResult:
        if not is_foremost_available():
            raise RuntimeError("foremost not found in PATH. Install foremost locally.")
        
        input_path = Path(input_file).expanduser()
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[0]  # all

        # Output directory
        if output_dir.strip():
            out_path = Path(output_dir.strip()).expanduser()
        else:
            out_path = input_path.parent / f"foremost_output_{input_path.stem}"
        
        out_path.mkdir(parents=True, exist_ok=True)

        args: List[str] = ["foremost", "-i", str(input_path), "-o", str(out_path)]

        # Add profile args
        args.extend(selected_profile.args)

        # Override file types if specified
        if file_types.strip():
            args = [a for i, a in enumerate(args) if not (a == "-t" or (i > 0 and args[i-1] == "-t"))]
            args.extend(["-t", file_types.strip()])

        # Custom signatures
        custom_config_file: Optional[Path] = None
        if custom_config.strip():
            # Use provided config file
            custom_config_file = Path(custom_config.strip()).expanduser()
            if not custom_config_file.exists():
                raise FileNotFoundError(f"Custom config file not found: {custom_config_file}")
            args.extend(["-c", str(custom_config_file)])
        elif custom_header.strip() or custom_footer.strip():
            # Create temporary config file with custom signatures
            custom_config_file = self._create_custom_config(custom_header, custom_footer, out_path)
            if custom_config_file:
                args.extend(["-c", str(custom_config_file)])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,  # 10 minute timeout
        )

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append(f"Output directory: {out_path}")
        body_lines.append("")
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        # Check audit.txt for summary
        audit_file = out_path / "audit.txt"
        if audit_file.exists():
            body_lines.append("")
            body_lines.append("Audit Summary:")
            body_lines.append(audit_file.read_text())
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0:
            raise RuntimeError(f"Foremost failed: {proc.stderr.strip()}")

        # Analyze carved files
        carved_files = self._analyze_carved_files(out_path)
        if carved_files:
            body_lines.append("")
            body_lines.append("Carved Files Summary:")
            body_lines.append(json.dumps(carved_files, indent=2))

        return ToolResult(
            title=f"Foremost: {input_path.name}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

    def _create_custom_config(self, header: str, footer: str, output_dir: Path) -> Optional[Path]:
        """Create a temporary foremost config file with custom header/footer signatures."""
        try:
            # Create config directory in output
            config_dir = output_dir / "custom_config"
            config_dir.mkdir(exist_ok=True)
            
            config_file = config_dir / "custom.conf"
            
            # Foremost config format:
            # extension y [header_bytes] [footer_bytes] [header_max] [footer_max]
            config_lines = ["# Custom Foremost Configuration"]
            config_lines.append(f"# Header: {header[:50]}")
            config_lines.append(f"# Footer: {footer[:50]}")
            config_lines.append("")
            
            # Convert hex strings to bytes if needed
            header_bytes = self._parse_signature(header)
            footer_bytes = self._parse_signature(footer)
            
            if header_bytes or footer_bytes:
                ext = "custom"
                header_hex = header_bytes.hex() if header_bytes else ""
                footer_hex = footer_bytes.hex() if footer_bytes else ""
                
                # Foremost config format
                config_line = f"{ext} y {header_hex} {footer_hex}"
                config_lines.append(config_line)
            
            config_file.write_text("\n".join(config_lines))
            return config_file
        except Exception:
            return None

    def _parse_signature(self, sig: str) -> bytes:
        """Parse signature string (hex or raw) into bytes."""
        if not sig.strip():
            return b""
        
        sig_clean = sig.strip()
        
        # Try hex format first
        if all(c in "0123456789abcdefABCDEF " for c in sig_clean):
            # Remove spaces
            hex_clean = sig_clean.replace(" ", "").replace(":", "")
            try:
                return bytes.fromhex(hex_clean)
            except ValueError:
                pass
        
        # Try as raw string
        return sig_clean.encode("latin-1", errors="ignore")

    def _analyze_carved_files(self, output_dir: Path) -> Dict[str, object]:
        """Analyze carved files and generate statistics."""
        stats: Dict[str, object] = {
            "total_files": 0,
            "by_type": {},
            "total_size": 0,
        }
        
        # Foremost creates subdirectories by file type
        if not output_dir.exists():
            return stats
        
        type_dirs = [d for d in output_dir.iterdir() if d.is_dir() and d.name not in ["custom_config"]]
        
        for type_dir in type_dirs:
            files = list(type_dir.rglob("*"))
            file_list = [f for f in files if f.is_file()]
            
            type_name = type_dir.name
            count = len(file_list)
            size = sum(f.stat().st_size for f in file_list)
            
            stats["total_files"] = int(stats.get("total_files", 0)) + count
            stats["total_size"] = int(stats.get("total_size", 0)) + size
            
            if isinstance(stats["by_type"], dict):
                stats["by_type"][type_name] = {
                    "count": count,
                    "size_bytes": size,
                    "files": [f.name for f in file_list[:10]],  # First 10 filenames
                }
        
        return stats

 