"""Markdown note persistence and autosave management."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from ..data_paths import snapshots_dir
from ..logger import configure_logging
from ..manager.challenge_manager import ChallengeManager

_LOG = configure_logging()


class NoteManager:
    """Wraps challenge manager note persistence with autosave support."""

    def __init__(self, challenges: ChallengeManager) -> None:
        self._challenges = challenges

    def load_markdown(self, challenge_id: int) -> str:
        return self._challenges.notes_for_challenge(challenge_id)

    def save_markdown(self, challenge_id: int, markdown: str) -> None:
        self._challenges.save_note(challenge_id, markdown)
        _LOG.info("Saved note for challenge %s", challenge_id)

    def autosave_snapshot(self, challenge_id: int, markdown: str) -> Path:
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        path = snapshots_dir() / f"challenge-{challenge_id}-{timestamp}.md"
        path.write_text(markdown, encoding="utf-8")
        _LOG.debug("Autosaved note for challenge %s to %s", challenge_id, path)
        return path

    def latest_snapshot(self, challenge_id: int) -> Optional[Path]:
        directory = snapshots_dir()
        candidates = sorted(directory.glob(f"challenge-{challenge_id}-*.md"))
        return candidates[-1] if candidates else None
