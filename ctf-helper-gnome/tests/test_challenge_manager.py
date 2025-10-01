from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_modules():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    challenge_module = importlib.import_module("ctf_helper.manager.challenge_manager")
    export_module = importlib.import_module("ctf_helper.manager.export_import")
    db_module = importlib.import_module("ctf_helper.db")
    return challenge_module.ChallengeManager, export_module.ExportImportManager, db_module.Database


class ChallengeManagerExportTest(unittest.TestCase):
    def test_create_and_export(self) -> None:
        ChallengeManager, ExportImportManager, Database = load_modules()

        with tempfile.TemporaryDirectory() as temp_dir:
            tmp_path = Path(temp_dir)
            database = Database(tmp_path / "db.sqlite3")
            manager = ChallengeManager(database=database)
            manager.db.initialise()

            challenge = manager.create_challenge(
                title="Test",
                project="Practice",
                category="Crypto",
                difficulty="easy",
                status="Not Started",
                description="Decode this",
            )
            manager.set_flag(challenge.id, "flag{test}")
            manager.save_note(challenge.id, "Remember to rotate by 13")

            export = ExportImportManager(manager)
            archive = tmp_path / "workspace.ctfpack"
            export.export_to_path(archive)
            self.assertTrue(archive.exists())

            with zipfile.ZipFile(archive, "r") as zp:
                manifest = json.loads(zp.read("manifest.json"))
            self.assertIn("challenges", manifest)


if __name__ == "__main__":
    unittest.main()
