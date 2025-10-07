"""
Attachment Manager for Cryptea
Handles screenshots, PCAPs, and related files for CTF challenges
All data stored locally and offline
"""

import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import mimetypes

from ..db import Database


class AttachmentManager:
    """Manages challenge attachments (screenshots, PCAPs, files) stored locally"""
    
    # Allowed file types for security
    ALLOWED_EXTENSIONS = {
        # Images
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp', '.tiff', '.tif', '.ico',
        # Audio (steganography, forensics)
        '.wav', '.mp3', '.ogg', '.flac', '.m4a', '.aac', '.wma',
        # Video (steganography, forensics)
        '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v',
        # Network captures
        '.pcap', '.pcapng', '.cap',
        # Archives
        '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.tar.gz', '.tar.bz2', '.tar.xz',
        # Text/logs
        '.txt', '.log', '.md', '.json', '.xml', '.yaml', '.yml', '.csv', '.tsv',
        # Documents
        '.pdf', '.html', '.htm', '.doc', '.docx', '.odt', '.rtf',
        # Executables (reverse engineering)
        '.exe', '.dll', '.so', '.dylib', '.elf', '.bin', '.out', '.app',
        # Binary/hex dumps
        '.hex', '.dump', '.raw', '.img', '.iso',
        # Disk images (forensics)
        '.vhd', '.vhdx', '.vmdk', '.qcow2', '.vdi', '.dd',
        # Memory dumps (forensics)
        '.dmp', '.mem', '.core',
        # CTF specific
        '.flag', '.key', '.pem', '.crt', '.cer', '.der', '.p12', '.pfx', '.pub',
        # Source code (reverse engineering, web)
        '.py', '.sh', '.bash', '.zsh', '.c', '.cpp', '.h', '.hpp', '.java', '.class', 
        '.js', '.php', '.rb', '.pl', '.lua', '.go', '.rs', '.asm', '.s',
        # Web files
        '.css', '.scss', '.sass', '.less', '.jsx', '.tsx', '.vue', '.sql',
        # Configuration files
        '.conf', '.cfg', '.ini', '.env', '.properties',
        # Database files
        '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
        # Android/Mobile
        '.apk', '.dex', '.smali',
        # Windows specific
        '.bat', '.ps1', '.cmd', '.vbs', '.reg',
        # Other forensics
        '.eml', '.msg', '.pst', '.ost',
    }
    
    # MIME types for image preview
    IMAGE_MIMES = {
        'image/png', 'image/jpeg', 'image/gif', 
        'image/bmp', 'image/webp', 'image/svg+xml'
    }
    
    # Maximum file size (50MB)
    MAX_FILE_SIZE = 50 * 1024 * 1024
    
    def __init__(self, base_dir: Optional[str] = None):
        """
        Initialize attachment manager
        
        Args:
            base_dir: Base directory for attachments (default: ~/.local/share/cryptea/attachments)
        """
        if base_dir is None:
            self.base_dir = Path.home() / ".local" / "share" / "cryptea" / "attachments"
        else:
            self.base_dir = Path(base_dir).expanduser()
        
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db = Database()
        
        # Initialize mimetypes
        mimetypes.init()
    
    def _get_challenge_dir(self, challenge_id: int) -> Path:
        """Get or create directory for challenge attachments"""
        challenge_dir = self.base_dir / str(challenge_id)
        challenge_dir.mkdir(exist_ok=True)
        return challenge_dir
    
    def _validate_file(self, file_path: Path) -> tuple[bool, str]:
        """
        Validate file for security and size constraints
        
        Returns:
            (is_valid, error_message)
        """
        # Check if file exists
        if not file_path.exists():
            return False, "File does not exist"
        
        # Check if it's a file (not directory)
        if not file_path.is_file():
            return False, "Not a regular file"
        
        # Check extension
        if file_path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            return False, f"File type {file_path.suffix} not allowed"
        
        # No file size limit - allow files of any size
        # file_size = file_path.stat().st_size
        # if file_size > self.MAX_FILE_SIZE:
        #     size_mb = file_size / (1024 * 1024)
        #     return False, f"File too large ({size_mb:.1f}MB, max 50MB)"
        
        return True, ""
    
    def add_attachment(self, challenge_id: int, src_path: str) -> Optional[Dict[str, Any]]:
        """
        Add an attachment to a challenge
        
        Args:
            challenge_id: ID of the challenge
            src_path: Source file path
            
        Returns:
            Attachment record dict or None on error
        """
        src_path_obj = Path(src_path)
        
        # Validate file
        is_valid, error_msg = self._validate_file(src_path_obj)
        if not is_valid:
            raise ValueError(error_msg)
        
        # Get destination directory
        dest_dir = self._get_challenge_dir(challenge_id)
        
        # Handle filename conflicts
        dest_name = src_path_obj.name
        dest_path = dest_dir / dest_name
        counter = 1
        while dest_path.exists():
            stem = src_path_obj.stem
            suffix = src_path_obj.suffix
            dest_name = f"{stem}_{counter}{suffix}"
            dest_path = dest_dir / dest_name
            counter += 1
        
        # Copy file
        try:
            shutil.copy2(src_path_obj, dest_path)
        except Exception as e:
            raise IOError(f"Failed to copy file: {e}")
        
        # Get file metadata
        file_size = dest_path.stat().st_size
        file_type, _ = mimetypes.guess_type(str(dest_path))
        if not file_type:
            # Fallback to file command
            try:
                file_type = subprocess.getoutput(f"file --mime-type -b '{dest_path}'").strip()
            except:
                file_type = "application/octet-stream"
        
        # Store in database
        with self.db.cursor() as cur:
            cur.execute(
                "INSERT INTO attachments (challenge_id, file_name, file_path, file_type, file_size, added_at) VALUES (?, ?, ?, ?, ?, ?)",
                (challenge_id, dest_path.name, str(dest_path), file_type, file_size, datetime.now().isoformat())
            )
            attachment_id = cur.lastrowid
        
        return {
            "id": attachment_id,
            "challenge_id": challenge_id,
            "file_name": dest_path.name,
            "file_path": str(dest_path),
            "file_type": file_type,
            "file_size": file_size,
            "added_at": datetime.now().isoformat()
        }
    
    def list_attachments(self, challenge_id: int) -> List[Dict[str, Any]]:
        """
        List all attachments for a challenge
        
        Args:
            challenge_id: ID of the challenge
            
        Returns:
            List of attachment records
        """
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT * FROM attachments WHERE challenge_id=? ORDER BY added_at DESC",
                (challenge_id,)
            )
            return [dict(row) for row in cur.fetchall()]
    
    def get_attachment(self, attachment_id: int) -> Optional[Dict[str, Any]]:
        """Get a single attachment by ID"""
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT * FROM attachments WHERE id=?",
                (attachment_id,)
            )
            row = cur.fetchone()
            return dict(row) if row else None
    
    def delete_attachment(self, attachment_id: int) -> bool:
        """
        Delete an attachment
        
        Args:
            attachment_id: ID of the attachment
            
        Returns:
            True if deleted successfully
        """
        record = self.get_attachment(attachment_id)
        if not record:
            return False
        
        # Delete file from filesystem
        file_path = Path(record["file_path"])
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            print(f"Warning: Failed to delete file {file_path}: {e}")
        
        # Delete from database
        with self.db.cursor() as cur:
            cur.execute("DELETE FROM attachments WHERE id=?", (attachment_id,))
        return True
    
    def delete_challenge_attachments(self, challenge_id: int) -> int:
        """
        Delete all attachments for a challenge
        
        Args:
            challenge_id: ID of the challenge
            
        Returns:
            Number of attachments deleted
        """
        attachments = self.list_attachments(challenge_id)
        count = 0
        
        for attachment in attachments:
            if self.delete_attachment(attachment["id"]):
                count += 1
        
        # Clean up empty directory
        challenge_dir = self._get_challenge_dir(challenge_id)
        try:
            if challenge_dir.exists() and not any(challenge_dir.iterdir()):
                challenge_dir.rmdir()
        except:
            pass
        
        return count
    
    def take_screenshot(self, challenge_id: int, interactive: bool = True) -> Optional[Dict[str, Any]]:
        """
        Take a screenshot and attach it to a challenge
        
        Args:
            challenge_id: ID of the challenge
            interactive: If True, allow user to select area (default: True)
            
        Returns:
            Attachment record dict or None on error
        """
        dest_dir = self._get_challenge_dir(challenge_id)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = f"screenshot_{timestamp}.png"
        dest_path = dest_dir / fname
        
        # Determine screenshot tool based on session type
        session_type = os.environ.get('XDG_SESSION_TYPE', 'x11').lower()
        
        try:
            if session_type == 'wayland' and shutil.which('grim'):
                # Use grim for Wayland
                if interactive and shutil.which('slurp'):
                    # Interactive selection with slurp
                    result = subprocess.run(
                        ["grim", "-g", "$(slurp)", str(dest_path)],
                        shell=True,
                        capture_output=True,
                        timeout=30
                    )
                else:
                    # Full screen
                    result = subprocess.run(
                        ["grim", str(dest_path)],
                        capture_output=True,
                        timeout=10
                    )
            elif shutil.which('gnome-screenshot'):
                # Use gnome-screenshot for X11
                if interactive:
                    result = subprocess.run(
                        ["gnome-screenshot", "-a", "-f", str(dest_path)],
                        capture_output=True,
                        timeout=30
                    )
                else:
                    result = subprocess.run(
                        ["gnome-screenshot", "-f", str(dest_path)],
                        capture_output=True,
                        timeout=10
                    )
            elif shutil.which('scrot'):
                # Fallback to scrot
                if interactive:
                    result = subprocess.run(
                        ["scrot", "-s", str(dest_path)],
                        capture_output=True,
                        timeout=30
                    )
                else:
                    result = subprocess.run(
                        ["scrot", str(dest_path)],
                        capture_output=True,
                        timeout=10
                    )
            else:
                raise RuntimeError("No screenshot tool found (install gnome-screenshot, grim, or scrot)")
            
            # Check if screenshot was taken
            if not dest_path.exists() or dest_path.stat().st_size == 0:
                if dest_path.exists():
                    dest_path.unlink()
                return None
            
            # Add to database
            return self.add_attachment(challenge_id, str(dest_path))
            
        except subprocess.TimeoutExpired:
            print("Screenshot capture timed out or was cancelled")
            if dest_path.exists():
                dest_path.unlink()
            return None
        except Exception as e:
            print(f"Failed to take screenshot: {e}")
            if dest_path.exists():
                dest_path.unlink()
            return None
    
    def is_image(self, attachment: Dict[str, Any]) -> bool:
        """Check if attachment is an image"""
        file_type = attachment.get("file_type", "")
        return file_type in self.IMAGE_MIMES
    
    def get_attachment_count(self, challenge_id: int) -> int:
        """Get number of attachments for a challenge"""
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) as count FROM attachments WHERE challenge_id=?",
                (challenge_id,)
            )
            row = cur.fetchone()
            return row["count"] if row else 0
    
    def open_attachment(self, attachment_id: int) -> bool:
        """
        Open attachment with system default application
        
        Args:
            attachment_id: ID of the attachment
            
        Returns:
            True if opened successfully
        """
        record = self.get_attachment(attachment_id)
        if not record:
            return False
        
        file_path = Path(record["file_path"])
        if not file_path.exists():
            return False
        
        try:
            subprocess.Popen(["xdg-open", str(file_path)])
            return True
        except Exception as e:
            print(f"Failed to open attachment: {e}")
            return False
    
    def open_challenge_folder(self, challenge_id: int) -> bool:
        """
        Open challenge attachment folder in file manager
        
        Args:
            challenge_id: ID of the challenge
            
        Returns:
            True if opened successfully
        """
        challenge_dir = self._get_challenge_dir(challenge_id)
        
        try:
            subprocess.Popen(["xdg-open", str(challenge_dir)])
            return True
        except Exception as e:
            print(f"Failed to open folder: {e}")
            return False
    
    def rename_attachment(self, attachment_id: int, new_name: str) -> bool:
        """
        Rename an attachment
        
        Args:
            attachment_id: ID of the attachment
            new_name: New filename
            
        Returns:
            True if renamed successfully
        """
        record = self.get_attachment(attachment_id)
        if not record:
            return False
        
        old_path = Path(record["file_path"])
        if not old_path.exists():
            return False
        
        # Validate new name
        new_path = old_path.parent / new_name
        if new_path.exists():
            raise ValueError("File with this name already exists")
        
        # Validate extension
        if new_path.suffix.lower() not in self.ALLOWED_EXTENSIONS:
            raise ValueError(f"File type {new_path.suffix} not allowed")
        
        try:
            # Rename file
            old_path.rename(new_path)
            
            # Update database
            with self.db.cursor() as cur:
                cur.execute(
                    "UPDATE attachments SET file_name=?, file_path=? WHERE id=?",
                    (new_name, str(new_path), attachment_id)
                )
            return True
        except Exception as e:
            print(f"Failed to rename attachment: {e}")
            return False
    
    def export_attachments(self, challenge_id: int, export_dir: str) -> int:
        """
        Export all attachments for a challenge to a directory
        
        Args:
            challenge_id: ID of the challenge
            export_dir: Destination directory
            
        Returns:
            Number of files exported
        """
        export_path = Path(export_dir)
        export_path.mkdir(parents=True, exist_ok=True)
        
        attachments = self.list_attachments(challenge_id)
        count = 0
        
        for attachment in attachments:
            src_path = Path(attachment["file_path"])
            if src_path.exists():
                dest_path = export_path / attachment["file_name"]
                try:
                    shutil.copy2(src_path, dest_path)
                    count += 1
                except Exception as e:
                    print(f"Failed to export {attachment['file_name']}: {e}")
        
        return count
    
    def clean_orphaned_attachments(self) -> int:
        """
        Remove attachment files that are no longer in the database
        
        Returns:
            Number of orphaned files removed
        """
        count = 0
        
        # Get all attachment file paths from database
        db_paths = set()
        with self.db.cursor() as cur:
            cur.execute("SELECT file_path FROM attachments")
            all_attachments = [dict(row) for row in cur.fetchall()]
        
        for record in all_attachments:
            db_paths.add(Path(record["file_path"]))
        
        # Scan filesystem
        for challenge_dir in self.base_dir.iterdir():
            if not challenge_dir.is_dir():
                continue
            
            for file_path in challenge_dir.iterdir():
                if file_path.is_file() and file_path not in db_paths:
                    try:
                        file_path.unlink()
                        count += 1
                    except Exception as e:
                        print(f"Failed to delete orphaned file {file_path}: {e}")
            
            # Remove empty directories
            try:
                if not any(challenge_dir.iterdir()):
                    challenge_dir.rmdir()
            except:
                pass
        
        return count
    
    def get_total_size(self, challenge_id: Optional[int] = None) -> int:
        """
        Get total size of attachments
        
        Args:
            challenge_id: If provided, get size for specific challenge only
            
        Returns:
            Total size in bytes
        """
        if challenge_id is not None:
            with self.db.cursor() as cur:
                cur.execute(
                    "SELECT SUM(file_size) as total FROM attachments WHERE challenge_id=?",
                    (challenge_id,)
                )
                result = cur.fetchone()
        else:
            with self.db.cursor() as cur:
                cur.execute("SELECT SUM(file_size) as total FROM attachments")
                result = cur.fetchone()
        
        return result["total"] if result and result["total"] else 0
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size in human-readable format"""
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
