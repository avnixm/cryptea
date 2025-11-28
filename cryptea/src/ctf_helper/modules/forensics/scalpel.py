"""Scalpel wrapper for file carving with configuration presets."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence

from ..base import ToolResult


def is_scalpel_available() -> bool:
    return shutil.which("scalpel") is not None


class ScalpelProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    comment: str


PROFILE_CHOICES: Sequence[ScalpelProfile] = (
    ScalpelProfile(
        "images",
        "Images",
        "Carve image files",
        "jpg,png,gif,bmp",
    ),
    ScalpelProfile(
        "documents",
        "Documents",
        "Carve document files",
        "pdf,doc,xls,ppt",
    ),
    ScalpelProfile(
        "archives",
        "Archives",
        "Carve archive files",
        "zip,rar,gz,tar",
    ),
    ScalpelProfile(
        "all",
        "All Types",
        "Carve all configured file types",
        "all",
    ),
)


class ScalpelTool:
    name = "Scalpel"
    description = "Fast file carving tool with configuration support."
    category = "Forensics"

    def run(
        self,
        input_file: str,
        profile: str = "all",
        output_dir: str = "",
        config_file: str = "",
        extra: str = "",
        custom_header: str = "",
        custom_footer: str = "",
        custom_ext: str = "custom",
        use_template: str = "",
    ) -> ToolResult:
        if not is_scalpel_available():
            raise RuntimeError("scalpel not found in PATH. Install scalpel locally.")
        
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
            selected_profile = PROFILE_CHOICES[3]  # all

        # Output directory
        if output_dir.strip():
            out_path = Path(output_dir.strip()).expanduser()
        else:
            out_path = input_path.parent / f"scalpel_output_{input_path.stem}"
        
        out_path.mkdir(parents=True, exist_ok=True)

        args: List[str] = ["scalpel"]

        # Config file - check for custom signature or template first
        conf_path: Optional[Path] = None
        
        if config_file.strip():
            conf_path = Path(config_file.strip()).expanduser()
            if not conf_path.exists():
                raise FileNotFoundError(f"Config file not found: {config_file}")
        elif custom_header.strip() or custom_footer.strip():
            # Create custom config with user-defined signature
            conf_path = self._create_custom_config(
                out_path,
                custom_header,
                custom_footer,
                custom_ext,
            )
        elif use_template.strip():
            # Use template
            conf_path = self._get_template_config(use_template.strip(), out_path)
        
        # If no custom config, use default
        if conf_path is None:
            default_conf = Path("/etc/scalpel/scalpel.conf")
            if default_conf.exists():
                conf_path = default_conf
        
        if conf_path:
            args.extend(["-c", str(conf_path)])

        # Output directory
        args.extend(["-o", str(out_path)])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Input file
        args.append(str(input_path))

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
        body_lines.append(f"Profile: {selected_profile.label} ({selected_profile.comment})")
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
        
        # Analyze carved files and verify integrity
        carved_files = self._analyze_carved_files(out_path)
        if carved_files:
            body_lines.append("")
            body_lines.append("Carved Files Analysis:")
            body_lines.append(json.dumps(carved_files, indent=2))
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0:
            raise RuntimeError(f"Scalpel failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Scalpel: {input_path.name}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

    def _create_custom_config(
        self,
        output_dir: Path,
        header: str,
        footer: str,
        extension: str,
    ) -> Path:
        """Create a custom Scalpel config file with user-defined signatures."""
        config_dir = output_dir / "custom_config"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "custom_signatures.conf"
        
        # Scalpel config format:
        # extension y [header_bytes] [footer_bytes] [header_max] [footer_max]
        config_lines = ["# Custom Scalpel Configuration"]
        config_lines.append(f"# Extension: .{extension}")
        config_lines.append(f"# Header: {header[:50]}")
        config_lines.append(f"# Footer: {footer[:50]}")
        config_lines.append("")
        
        # Convert signatures to hex
        header_bytes = self._parse_signature(header)
        footer_bytes = self._parse_signature(footer)
        
        header_hex = header_bytes.hex() if header_bytes else ""
        footer_hex = footer_bytes.hex() if footer_bytes else ""
        
        # Scalpel config line format
        # extension y header footer header_max footer_max
        header_max = len(header_bytes) if header_bytes else 0
        footer_max = len(footer_bytes) if footer_bytes else 0
        
        config_line = f"{extension}\ty\t{header_hex}\t{footer_hex}\t{header_max}\t{footer_max}"
        config_lines.append(config_line)
        
        config_file.write_text("\n".join(config_lines))
        return config_file

    def _parse_signature(self, sig: str) -> bytes:
        """Parse signature string (hex or raw) into bytes."""
        if not sig.strip():
            return b""
        
        sig_clean = sig.strip()
        
        # Try hex format first
        if all(c in "0123456789abcdefABCDEF :" for c in sig_clean):
            hex_clean = sig_clean.replace(" ", "").replace(":", "")
            try:
                return bytes.fromhex(hex_clean)
            except ValueError:
                pass
        
        # Try as raw string
        return sig_clean.encode("latin-1", errors="ignore")

    def _get_template_config(self, template_name: str, output_dir: Path) -> Optional[Path]:
        """Get or create a config file from a template."""
        templates = self._get_signature_templates()
        
        if template_name not in templates:
            return None
        
        template = templates[template_name]
        config_dir = output_dir / "templates"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / f"{template_name}.conf"
        
        if config_file.exists():
            return config_file
        
        # Create config from template
        config_lines = [f"# Scalpel template: {template['label']}"]
        config_lines.append(f"# {template['description']}")
        config_lines.append("")
        
        signatures_val = template.get("signatures", [])
        if not isinstance(signatures_val, list):
            return config_file
        
        for sig in signatures_val:
            if not isinstance(sig, dict):
                continue
            ext = str(sig.get("extension", ""))
            header = str(sig.get("header", ""))
            footer = str(sig.get("footer", ""))
            
            header_bytes = bytes.fromhex(header.replace(" ", "")) if header else b""
            footer_bytes = bytes.fromhex(footer.replace(" ", "")) if footer else b""
            
            header_hex = header_bytes.hex() if header_bytes else ""
            footer_hex = footer_bytes.hex() if footer_bytes else ""
            header_max = len(header_bytes)
            footer_max = len(footer_bytes)
            
            config_lines.append(f"{ext}\ty\t{header_hex}\t{footer_hex}\t{header_max}\t{footer_max}")
        
        config_file.write_text("\n".join(config_lines))
        return config_file

    def _get_signature_templates(self) -> Dict[str, Dict[str, object]]:
        """Get common signature templates for CTF challenges."""
        return {
            "ctf_images": {
                "label": "CTF Images",
                "description": "Common image formats used in CTF challenges",
                "signatures": [
                    {"extension": "jpg", "header": "ff d8 ff", "footer": "ff d9"},
                    {"extension": "png", "header": "89 50 4e 47 0d 0a 1a 0a", "footer": ""},
                    {"extension": "gif", "header": "47 49 46 38", "footer": "00 3b"},
                    {"extension": "bmp", "header": "42 4d", "footer": ""},
                ],
            },
            "ctf_documents": {
                "label": "CTF Documents",
                "description": "Document formats commonly found in CTF challenges",
                "signatures": [
                    {"extension": "pdf", "header": "25 50 44 46", "footer": "0a 25 25 45 4f 46"},
                    {"extension": "doc", "header": "d0 cf 11 e0 a1 b1 1a e1", "footer": ""},
                    {"extension": "zip", "header": "50 4b 03 04", "footer": "50 4b 05 06"},
                ],
            },
            "ctf_archives": {
                "label": "CTF Archives",
                "description": "Archive formats used in CTF challenges",
                "signatures": [
                    {"extension": "zip", "header": "50 4b 03 04", "footer": "50 4b 05 06"},
                    {"extension": "rar", "header": "52 61 72 21 1a 07", "footer": ""},
                    {"extension": "gz", "header": "1f 8b 08", "footer": ""},
                    {"extension": "tar", "header": "", "footer": "00 00 00 00"},
                ],
            },
            "ctf_executables": {
                "label": "CTF Executables",
                "description": "Executable file signatures",
                "signatures": [
                    {"extension": "elf", "header": "7f 45 4c 46", "footer": ""},
                    {"extension": "pe", "header": "4d 5a", "footer": ""},
                ],
            },
        }

    def _analyze_carved_files(self, output_dir: Path) -> Dict[str, object]:
        """Analyze carved files and verify integrity."""
        verified_list: List[Dict[str, object]] = []
        analysis: Dict[str, object] = {
            "total_files": 0,
            "by_type": {},
            "verified": verified_list,
        }
        
        # Scalpel creates files with pattern: {offset}-{extension}
        if not output_dir.exists():
            return analysis
        
        carved_files = list(output_dir.glob("*"))
        file_list = [f for f in carved_files if f.is_file() and f.name != "audit.txt"]
        
        analysis["total_files"] = len(file_list)
        
        # Categorize by extension
        file_types: Dict[str, List[Dict[str, object]]] = {}
        
        for file_path in file_list:
            # Extract extension from filename (format: offset-extension)
            parts = file_path.stem.split("-")
            ext = parts[-1] if len(parts) > 1 else "unknown"
            
            if ext not in file_types:
                file_types[ext] = []
            
            try:
                size = file_path.stat().st_size
                file_types[ext].append({
                    "name": file_path.name,
                    "size_bytes": size,
                    "path": str(file_path),
                })
                
                # Verify file integrity based on extension
                verification = self._verify_file_integrity(file_path, ext)
                if verification:
                    verified_list.append({
                        "file": file_path.name,
                        "valid": verification.get("valid", False),
                        "issues": verification.get("issues", []),
                    })
            except Exception:
                pass
        
        by_type_dict: Dict[str, Dict[str, object]] = {}
        for ext, files in file_types.items():
            if isinstance(files, list):
                total_size = 0
                for f in files:
                    if isinstance(f, dict):
                        size_val = f.get("size_bytes", 0)
                        if isinstance(size_val, (int, float)):
                            total_size += int(size_val)
                by_type_dict[ext] = {
                    "count": len(files),
                    "total_size": total_size,
                    "files": files[:10],  # First 10 files
                }
        analysis["by_type"] = by_type_dict
        
        return analysis

    def _verify_file_integrity(self, file_path: Path, extension: str) -> Optional[Dict[str, object]]:
        """Verify integrity of a carved file."""
        issues_list: List[str] = []
        verification: Dict[str, object] = {
            "valid": False,
            "issues": issues_list,
        }
        
        try:
            data = file_path.read_bytes()
            
            if not data:
                issues_list.append("File is empty")
                return verification
            
            # Check magic bytes based on extension
            if extension.lower() == "jpg" or extension.lower() == "jpeg":
                if data[:2] == b"\xff\xd8":
                    verification["valid"] = True
                else:
                    issues_list.append("Invalid JPEG header")
            
            elif extension.lower() == "png":
                if data[:8] == b"\x89PNG\r\n\x1a\n":
                    verification["valid"] = True
                else:
                    issues_list.append("Invalid PNG header")
            
            elif extension.lower() == "pdf":
                if data[:4] == b"%PDF":
                    verification["valid"] = True
                else:
                    issues_list.append("Invalid PDF header")
            
            elif extension.lower() == "zip":
                if data[:2] == b"PK":
                    verification["valid"] = True
                else:
                    issues_list.append("Invalid ZIP header")
            
            else:
                verification["valid"] = True  # Unknown type, assume valid
            
        except Exception as e:
            issues_list.append(f"Verification error: {str(e)}")
        
        return verification

 