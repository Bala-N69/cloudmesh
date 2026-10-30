import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import terminal_text

ROOT = Path(__file__).resolve().parents[1]


class TestTerminalReports(unittest.TestCase):
    def test_controls_are_visible_not_executed(self):
        for character in ["\x1b", "\x00", "\r", "\n", "\t", "\x7f", "\x9b",
                          "\u202e", "\u2066", "\u2028", "\u2029", "\ud800"]:
            with self.subTest(character=repr(character)):
                rendered = terminal_text("before" + character + "after")
                self.assertNotIn(character, rendered)
                self.assertEqual(rendered, "before" + character.encode("unicode_escape").decode("ascii") + "after")

    def test_ordinary_names_unchanged(self):
        text = 'module.app["web"].bucket/café-東京'
        self.assertEqual(terminal_text(text), text)

    def test_single_batch_text_and_machine_reports(self):
        address = "bucket.\x1b[2J\rspoof\n[HIGH] hidden\u202e"
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            plan.write_text(json.dumps({"resource_changes": [{"address": address,
                "type": "google_storage_bucket", "change": {"actions": ["delete"], "after": None}}]}))
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [{"path": "plan.json", "kind": "terraform"}]}))
            for module, source in [("cli", plan), ("batch", manifest)]:
                for output in ["text", "json", "sarif"]:
                    with self.subTest(module=module, output=output):
                        result = subprocess.run([sys.executable, "-m", "cloudmesh_sentinel." + module,
                            str(source), "--format", output, "--fail-on", "high"], cwd=ROOT,
                            capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 1, result.stderr)
                        if output == "text":
                            self.assertIn(terminal_text(address), result.stdout)
                            self.assertNotIn("\x1b", result.stdout)
                            self.assertNotIn("\u202e", result.stdout)
                            self.assertEqual(result.stdout.count("\n[HIGH]"), 1)
                        else:
                            document = json.loads(result.stdout)
                            if output == "sarif":
                                actual = document["runs"][0]["results"][0]["properties"]["resource"]
                            else:
                                findings = document["findings"] if module == "cli" else document["files"][0]["findings"]
                                actual = findings[0]["address"]
                            self.assertEqual(actual, address)
