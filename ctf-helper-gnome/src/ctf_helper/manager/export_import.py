"""Local export/import of challenges as .ctfpack archives."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Iterable, List

from ..logger import configure_logging
from .challenge_manager import ChallengeManager

_LOG = configure_logging()

EXPORT_MANIFEST = "manifest.json"
ASSET_DIR = "attachments"


class ExportImportManager:
    """Handles .ctfpack archives for offline backup and restore."""

    def __init__(self, challenge_manager: ChallengeManager) -> None:
        self.challenge_manager = challenge_manager

    def export_to_path(self, destination: Path) -> Path:
        entries = self.challenge_manager.export_all()
        payload = json.dumps({"version": 1, "challenges": entries}, indent=2)
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(EXPORT_MANIFEST, payload)
        _LOG.info("Exported %s challenges to %s", len(entries), destination)
        return destination

    def import_from_path(self, source: Path) -> List[int]:
        with zipfile.ZipFile(source, "r") as archive:
            manifest = json.loads(archive.read(EXPORT_MANIFEST).decode("utf-8"))
        challenges = manifest.get("challenges", [])
        imported = self.challenge_manager.import_from(challenges)
        _LOG.info("Imported %s challenges from %s", len(imported), source)
        return [challenge.id for challenge in imported]
