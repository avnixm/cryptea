from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ResourcesTemplateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.prev_data = os.environ.get("XDG_DATA_HOME")
        os.environ["XDG_DATA_HOME"] = self.tmpdir.name
        for module in ("ctf_helper.resources", "ctf_helper.data_paths", "ctf_helper.logger"):
            sys.modules.pop(module, None)
        resources_module = importlib.import_module("ctf_helper.resources")
        self.Resources = resources_module.Resources

    def tearDown(self) -> None:
        if self.prev_data is None:
            os.environ.pop("XDG_DATA_HOME", None)
        else:
            os.environ["XDG_DATA_HOME"] = self.prev_data

    def test_template_index_contains_builtins(self) -> None:
        resources = self.Resources()
        index = resources.template_index()
        self.assertIn("warmup-crypto", index)
        self.assertEqual(index["warmup-crypto"]["category"], "Crypto")

    def test_ensure_templates_extracted_idempotent(self) -> None:
        resources = self.Resources()
        created = resources.ensure_templates_extracted()
        templates_root = Path(self.tmpdir.name) / "ctf-helper" / "templates"
        expected_files = {"warmup-crypto.json", "pcap-inspection.json"}
        self.assertTrue(expected_files.issubset({path.name for path in created}))
        for template_file in expected_files:
            payload = json.loads((templates_root / template_file).read_text())
            self.assertIn("name", payload)

        # second call should not recreate files
        self.assertEqual(resources.ensure_templates_extracted(), [])


if __name__ == "__main__":
    unittest.main()
