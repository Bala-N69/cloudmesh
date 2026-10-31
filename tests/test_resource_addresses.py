import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]


class TestResourceAddresses(unittest.TestCase):
    def test_invalid_addresses_rejected_even_for_clean_resources(self):
        for address in [None, False, 0, [], {}, "", " \t\n"]:
            with self.subTest(address=address):
                with self.assertRaisesRegex(ValueError, "Resource address must be a nonempty string"):
                    scan_plan({"resource_changes": [{"address": address, "change": {"after": {}}}]})

    def test_valid_and_missing_addresses_preserved(self):
        for metadata, expected in [({}, "unknown resource"),
                                   ({"address": 'module.app["café"].bucket'}, 'module.app["café"].bucket')]:
            findings = scan_plan({"resource_changes": [{**metadata, "change": {"actions": ["delete"]}}]})
            self.assertEqual(findings, [("HIGH", expected, "Resource will be deleted.")])

    def test_invalid_address_never_produces_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            plan.write_text(json.dumps({"resource_changes": [
                {"address": "valid", "change": {"actions": ["delete"]}},
                {"address": [], "change": {"actions": ["delete"]}}]}))
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [{"path": "plan.json", "kind": "terraform"}]}))
            for module, source in [("cli", plan), ("batch", manifest)]:
                for output in ["text", "json", "markdown", "sarif"]:
                    with self.subTest(module=module, output=output):
                        result = subprocess.run([sys.executable, "-m", "cloudmesh_sentinel." + module,
                            str(source), "--format", output], cwd=ROOT,
                            capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("Resource address must be a nonempty string", result.stderr)
