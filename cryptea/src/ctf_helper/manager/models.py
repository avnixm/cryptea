"""Data models for challenges, notes, and flags."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass(slots=True)
class Challenge:
    id: int
    title: str
    project: str
    category: str
    difficulty: str
    status: str
    description: str
    notes: str
    created_at: datetime
    updated_at: datetime
    flag: Optional[str] = None
    favorite: bool = False
    tags: List[str] = field(default_factory=list)


@dataclass(slots=True)
class Attachment:
    id: int
    challenge_id: int
    file_name: str
    stored_path: str
    created_at: datetime = field(default_factory=datetime.utcnow)
