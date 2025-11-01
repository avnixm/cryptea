"""Local export/import of challenges as .ctfpack archives."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Iterable, List

from ..logger import configure_logging
from ..utils import sanitize_import_path
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
        
        # Sanitize attachment paths to prevent Zip Slip (SEC-007)
        from ...data_paths import user_data_dir
        base_dir = user_data_dir() / "attachments"
        base_dir.mkdir(parents=True, exist_ok=True)
        
        for challenge in challenges:
            # If attachments are included in manifest, sanitize paths
            if "attachments" in challenge:
                sanitized_attachments = []
                for att in challenge.get("attachments", []):
                    if isinstance(att, dict) and "file_path" in att:
                        try:
                            att["file_path"] = str(sanitize_import_path(
                                att["file_path"],
                                base_dir=base_dir
                            ))
                        except ValueError as e:
                            _LOG.warning(
                                f"Rejected unsafe attachment path in challenge {challenge.get('title', 'unknown')}: {e}"
                            )
                            continue
                    sanitized_attachments.append(att)
                challenge["attachments"] = sanitized_attachments
        
        imported = self.challenge_manager.import_from(challenges)
        _LOG.info("Imported %s challenges from %s", len(imported), source)
        return [challenge.id for challenge in imported]
