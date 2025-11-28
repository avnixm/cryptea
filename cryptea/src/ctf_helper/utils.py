"""Utility functions for security and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def validate_path(path: Path, allowed_base: Path) -> Path:
    """
    Validate that path is within allowed_base directory (SEC-005).
    
    Prevents path traversal attacks by ensuring the resolved path
    stays within the allowed base directory.
    
    Args:
        path: Path to validate
        allowed_base: Base directory that path must be within
        
    Returns:
        Resolved path if valid
        
    Raises:
        ValueError: If path is outside allowed_base directory
    """
    resolved = path.expanduser().resolve()
    base_resolved = allowed_base.expanduser().resolve()
    
    try:
        resolved.relative_to(base_resolved)
    except ValueError:
        raise ValueError(
            f"Path {resolved} is outside allowed directory {base_resolved}. "
            "Path traversal attempts are blocked for security."
        )
    
    return resolved


def sanitize_import_path(path: str, base_dir: Path) -> Path:
    """
    Sanitize and validate path from imported data to prevent Zip Slip (SEC-007).
    
    Args:
        path: Path string from imported data
        base_dir: Base directory that path must be within
        
    Returns:
        Sanitized and validated Path
        
    Raises:
        ValueError: If path attempts directory traversal
    """
    # Remove any leading path separators
    path = path.lstrip("/")
    
    # Resolve relative to base directory
    resolved = (base_dir / path).resolve()
    
    # Ensure it's still within base directory
    try:
        resolved.relative_to(base_dir.resolve())
    except ValueError:
        raise ValueError(f"Path {path} attempts directory traversal")
    
    return resolved

