"""
Custom Cheat Sheets Manager
Manages user-created cheat sheets stored in JSON format.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, List, Optional

from ..data_paths import user_data_dir

logger = logging.getLogger(__name__)


class CustomCheatSheet:
    """Represents a custom cheat sheet."""
    
    def __init__(
        self,
        id: str,
        title: str,
        content: str,
        date_modified: Optional[str] = None,
    ):
        self.id = id
        self.title = title
        self.content = content
        self.date_modified = date_modified or datetime.now(UTC).isoformat()
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "date_modified": self.date_modified,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> CustomCheatSheet:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            content=data["content"],
            date_modified=data.get("date_modified"),
        )
    
    def get_snippet(self, max_length: int = 150) -> str:
        """Get a short snippet of content for display."""
        if not self.content:
            return ""
        # Remove newlines and extra whitespace
        snippet = " ".join(self.content.split())
        if len(snippet) <= max_length:
            return snippet
        return snippet[:max_length] + "..."


class CustomCheatSheetManager:
    """Manages custom cheat sheets stored in JSON file."""
    
    def __init__(self, storage_path: Optional[Path] = None):
        """Initialize the manager."""
        if storage_path is None:
            storage_path = user_data_dir() / "cheatsheets.json"
        self.storage_path = Path(storage_path)
        self._cheatsheets: Dict[str, CustomCheatSheet] = {}
        self.load()
    
    def load(self) -> None:
        """Load cheat sheets from JSON file."""
        if not self.storage_path.exists():
            logger.info(f"Cheat sheets file does not exist: {self.storage_path}")
            self._cheatsheets = {}
            return
        
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self._cheatsheets = {}
            for item in data.get("cheatsheets", []):
                sheet = CustomCheatSheet.from_dict(item)
                self._cheatsheets[sheet.id] = sheet
            
            logger.info(f"Loaded {len(self._cheatsheets)} custom cheat sheets")
        except Exception as e:
            logger.error(f"Error loading cheat sheets: {e}", exc_info=True)
            self._cheatsheets = {}
    
    def save(self) -> None:
        """Save cheat sheets to JSON file."""
        try:
            # Ensure directory exists
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                "version": 1,
                "cheatsheets": [sheet.to_dict() for sheet in self._cheatsheets.values()]
            }
            
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Saved {len(self._cheatsheets)} custom cheat sheets to {self.storage_path}")
        except Exception as e:
            logger.error(f"Error saving cheat sheets: {e}", exc_info=True)
            raise
    
    def get_all(self) -> List[CustomCheatSheet]:
        """Get all cheat sheets, sorted by date modified (newest first)."""
        sheets = list(self._cheatsheets.values())
        sheets.sort(key=lambda s: s.date_modified, reverse=True)
        return sheets
    
    def get(self, sheet_id: str) -> Optional[CustomCheatSheet]:
        """Get a cheat sheet by ID."""
        return self._cheatsheets.get(sheet_id)
    
    def create(self, title: str, content: str) -> CustomCheatSheet:
        """Create a new cheat sheet."""
        sheet_id = str(uuid.uuid4())
        sheet = CustomCheatSheet(
            id=sheet_id,
            title=title,
            content=content,
        )
        self._cheatsheets[sheet_id] = sheet
        self.save()
        logger.info(f"Created cheat sheet: {title} ({sheet_id})")
        return sheet
    
    def update(self, sheet_id: str, title: str, content: str) -> Optional[CustomCheatSheet]:
        """Update an existing cheat sheet."""
        if sheet_id not in self._cheatsheets:
            return None
        
        sheet = self._cheatsheets[sheet_id]
        sheet.title = title
        sheet.content = content
        sheet.date_modified = datetime.now(UTC).isoformat()
        self.save()
        logger.info(f"Updated cheat sheet: {title} ({sheet_id})")
        return sheet
    
    def delete(self, sheet_id: str) -> bool:
        """Delete a cheat sheet."""
        if sheet_id not in self._cheatsheets:
            return False
        
        title = self._cheatsheets[sheet_id].title
        del self._cheatsheets[sheet_id]
        self.save()
        logger.info(f"Deleted cheat sheet: {title} ({sheet_id})")
        return True
    
    def search(self, query: str) -> List[CustomCheatSheet]:
        """Search cheat sheets by title or content."""
        if not query:
            return self.get_all()
        
        query_lower = query.lower()
        results = []
        
        for sheet in self._cheatsheets.values():
            if query_lower in sheet.title.lower() or query_lower in sheet.content.lower():
                results.append(sheet)
        
        # Sort by relevance (title matches first) then by date
        results.sort(
            key=lambda s: (
                0 if query_lower in s.title.lower() else 1,
                s.date_modified
            ),
            reverse=True
        )
        
        return results

