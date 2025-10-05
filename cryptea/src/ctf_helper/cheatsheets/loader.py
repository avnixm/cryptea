"""
Cheat Sheet Loader Module
Loads and manages offline cheat sheet data from JSON files.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CheatSheet:
    """Represents a single cheat sheet."""
    
    id: str
    title: str
    category: str
    description: str
    type: str  # 'table' or 'code'
    searchable: bool
    columns: Optional[List[str]] = None
    entries: Optional[List[Dict[str, Any]]] = None
    
    def matches_search(self, query: str) -> bool:
        """Check if this sheet matches the search query."""
        if not query:
            return True
        
        query = query.lower()
        
        # Search in title and description
        if query in self.title.lower() or query in self.description.lower():
            return True
        
        # Search in category
        if query in self.category.lower():
            return True
        
        # Search in entries (if searchable)
        if self.searchable and self.entries:
            for entry in self.entries:
                # Search all values in the entry
                for value in entry.values():
                    if query in str(value).lower():
                        return True
        
        return False


class CheatSheetLoader:
    """Loads and manages cheat sheets from the data directory."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialize the cheat sheet loader.
        
        Args:
            data_dir: Path to the cheatsheets data directory
        """
        if data_dir is None:
            # Try to find data directory
            # First check system installation locations
            system_paths = [
                Path("/usr/local/share/cryptea/cheatsheets/cheatsheets"),
                Path("/usr/share/cryptea/cheatsheets/cheatsheets"),
                Path("/usr/local/share/cryptea/cheatsheets"),
                Path("/usr/share/cryptea/cheatsheets"),
            ]
            
            for path in system_paths:
                if path.exists() and any(path.glob("*.json")):
                    data_dir = path
                    break
            
            # Fall back to user data directory
            if data_dir is None:
                from ..data_paths import cheatsheets_dir
                data_dir = cheatsheets_dir()
        
        self.data_dir = Path(data_dir)
        self._sheets: Dict[str, CheatSheet] = {}
        self._categories: Dict[str, List[CheatSheet]] = {}
        self._loaded = False
    
    def load_all(self) -> None:
        """Load all cheat sheets from the data directory."""
        if self._loaded:
            return
        
        if not self.data_dir.exists():
            logger.warning(f"Cheat sheets directory not found: {self.data_dir}")
            return
        
        logger.info(f"Loading cheat sheets from: {self.data_dir}")
        
        # Load all JSON files
        for json_file in self.data_dir.glob("*.json"):
            try:
                self._load_sheet(json_file)
            except Exception as e:
                logger.error(f"Error loading cheat sheet {json_file}: {e}")
        
        # Organize by category
        self._organize_categories()
        
        self._loaded = True
        logger.info(f"Loaded {len(self._sheets)} cheat sheets in {len(self._categories)} categories")
    
    def _load_sheet(self, json_file: Path) -> None:
        """Load a single cheat sheet from a JSON file."""
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        sheet_id = json_file.stem
        
        sheet = CheatSheet(
            id=sheet_id,
            title=data.get('title', sheet_id),
            category=data.get('category', 'General'),
            description=data.get('description', ''),
            type=data.get('type', 'table'),
            searchable=data.get('searchable', True),
            columns=data.get('columns'),
            entries=data.get('entries', [])
        )
        
        self._sheets[sheet_id] = sheet
        logger.debug(f"Loaded cheat sheet: {sheet.title} ({sheet_id})")
    
    def _organize_categories(self) -> None:
        """Organize sheets by category."""
        self._categories.clear()
        
        for sheet in self._sheets.values():
            if sheet.category not in self._categories:
                self._categories[sheet.category] = []
            self._categories[sheet.category].append(sheet)
        
        # Sort sheets within each category by title
        for category in self._categories:
            self._categories[category].sort(key=lambda s: s.title)
    
    def get_sheet(self, sheet_id: str) -> Optional[CheatSheet]:
        """Get a cheat sheet by its ID."""
        if not self._loaded:
            self.load_all()
        return self._sheets.get(sheet_id)
    
    def get_all_sheets(self) -> List[CheatSheet]:
        """Get all loaded cheat sheets."""
        if not self._loaded:
            self.load_all()
        return list(self._sheets.values())
    
    def get_categories(self) -> List[str]:
        """Get all categories sorted alphabetically."""
        if not self._loaded:
            self.load_all()
        return sorted(self._categories.keys())
    
    def get_sheets_by_category(self, category: str) -> List[CheatSheet]:
        """Get all sheets in a specific category."""
        if not self._loaded:
            self.load_all()
        return self._categories.get(category, [])
    
    def search(self, query: str) -> List[CheatSheet]:
        """
        Search for cheat sheets matching the query.
        
        Args:
            query: Search query string
        
        Returns:
            List of matching cheat sheets
        """
        if not self._loaded:
            self.load_all()
        
        if not query:
            return self.get_all_sheets()
        
        results = []
        for sheet in self._sheets.values():
            if sheet.matches_search(query):
                results.append(sheet)
        
        return results
    
    def get_category_count(self, category: str) -> int:
        """Get the number of sheets in a category."""
        if not self._loaded:
            self.load_all()
        return len(self._categories.get(category, []))
    
    def reload(self) -> None:
        """Reload all cheat sheets from disk."""
        self._sheets.clear()
        self._categories.clear()
        self._loaded = False
        self.load_all()
