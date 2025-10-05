"""Challenge template management."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..data_paths import templates_dir as get_templates_dir
from ..logger import configure_logging

_LOG = configure_logging()


@dataclass(slots=True)
class ChallengeTemplate:
    """Template for creating challenges."""

    title: str
    category: str
    difficulty: str
    description: str
    tags: List[str]
    filename: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert template to dictionary."""
        return {
            "title": self.title,
            "category": self.category,
            "difficulty": self.difficulty,
            "description": self.description,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], filename: Optional[str] = None) -> ChallengeTemplate:
        """Create template from dictionary."""
        return cls(
            title=data.get("title", "Untitled"),
            category=data.get("category", "misc"),
            difficulty=data.get("difficulty", "medium"),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            filename=filename,
        )


class TemplateManager:
    """Manager for challenge templates."""

    def __init__(self, templates_dir: Optional[Path] = None) -> None:
        """Initialize template manager.

        Args:
            templates_dir: Directory containing template JSON files.
                          Defaults to user data directory templates/
        """
        if templates_dir is None:
            templates_dir = get_templates_dir()
        self.templates_dir = templates_dir
        self.templates_dir.mkdir(parents=True, exist_ok=True)

    def list_templates(self) -> List[ChallengeTemplate]:
        """List all available templates.

        Returns:
            List of ChallengeTemplate objects sorted by title.
        """
        templates: List[ChallengeTemplate] = []

        if not self.templates_dir.exists():
            _LOG.warning("Templates directory does not exist: %s", self.templates_dir)
            return templates

        for template_file in sorted(self.templates_dir.glob("*.json")):
            try:
                with template_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    template = ChallengeTemplate.from_dict(data, filename=template_file.name)
                    templates.append(template)
            except (json.JSONDecodeError, OSError) as e:
                _LOG.error("Failed to load template %s: %s", template_file, e)

        return sorted(templates, key=lambda t: t.title.lower())

    def get_template(self, filename: str) -> Optional[ChallengeTemplate]:
        """Get a specific template by filename.

        Args:
            filename: Name of the template file (e.g., "rsa-basics.json")

        Returns:
            ChallengeTemplate if found, None otherwise.
        """
        template_file = self.templates_dir / filename
        if not template_file.exists():
            _LOG.warning("Template file not found: %s", template_file)
            return None

        try:
            with template_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
                return ChallengeTemplate.from_dict(data, filename=filename)
        except (json.JSONDecodeError, OSError) as e:
            _LOG.error("Failed to load template %s: %s", template_file, e)
            return None

    def save_template(self, template: ChallengeTemplate, filename: Optional[str] = None) -> bool:
        """Save a template to disk.

        Args:
            template: Template to save
            filename: Optional filename. If not provided, generates from title.

        Returns:
            True if successful, False otherwise.
        """
        if filename is None:
            # Generate filename from title
            safe_title = "".join(c if c.isalnum() or c in ("-", "_") else "-" for c in template.title.lower())
            filename = f"{safe_title}.json"

        template_file = self.templates_dir / filename

        try:
            with template_file.open("w", encoding="utf-8") as f:
                json.dump(template.to_dict(), f, indent=2, ensure_ascii=False)
            _LOG.info("Saved template to %s", template_file)
            return True
        except OSError as e:
            _LOG.error("Failed to save template %s: %s", template_file, e)
            return False

    def delete_template(self, filename: str) -> bool:
        """Delete a template file.

        Args:
            filename: Name of the template file to delete

        Returns:
            True if successful, False otherwise.
        """
        template_file = self.templates_dir / filename
        if not template_file.exists():
            _LOG.warning("Template file not found: %s", template_file)
            return False

        try:
            template_file.unlink()
            _LOG.info("Deleted template %s", template_file)
            return True
        except OSError as e:
            _LOG.error("Failed to delete template %s: %s", template_file, e)
            return False

    def export_challenge_as_template(
        self,
        title: str,
        category: str,
        difficulty: str,
        description: str,
        tags: List[str],
        filename: Optional[str] = None,
    ) -> bool:
        """Export challenge data as a template.

        Args:
            title: Challenge title
            category: Challenge category
            difficulty: Challenge difficulty
            description: Challenge description
            tags: List of tags
            filename: Optional filename

        Returns:
            True if successful, False otherwise.
        """
        template = ChallengeTemplate(
            title=title,
            category=category,
            difficulty=difficulty,
            description=description,
            tags=tags,
        )
        return self.save_template(template, filename)


__all__ = ["ChallengeTemplate", "TemplateManager"]
