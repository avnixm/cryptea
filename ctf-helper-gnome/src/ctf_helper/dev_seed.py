"""Development fixtures for offline UI testing."""

from __future__ import annotations

from datetime import datetime

from . import config
from .logger import configure_logging
from .manager.challenge_manager import ChallengeManager
from .notes.manager import NoteManager

_LOG = configure_logging()


def seed_if_requested(challenges: ChallengeManager, notes: NoteManager) -> None:
    if not config.DEV_PROFILE_ENABLED:
        return
    if challenges.list_challenges():
        _LOG.info("Dev profile requested but database already populated; skipping seed")
        return

    sample = challenges.create_challenge(
        title="Warmup Crypto",
        project="Practice",
        category="Crypto",
        difficulty="easy",
        status="In Progress",
        description="Use the bundled Caesar tool to decode the provided message.",
    )
    challenges.set_flag(sample.id, "flag{offline-caesar}")
    notes.save_markdown(
        sample.id,
        """# Notes\n\n- Check the cipher text for simple shifts\n- Document your approach""",
    )
    _LOG.info("Seeded development challenge data at %s", datetime.utcnow().isoformat())
