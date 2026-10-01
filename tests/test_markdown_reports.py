import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import markdown_report

ROOT = Path(__file__).resolve().parents[1]


class TestMarkdownReports(unittest.TestCase):
    def run_report(self, path, threshold="none"):
        return subprocess.run(
            [sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"), str(path),
             "--format", "markdown", "--fail-on", threshold],
            capture_output=True, text=True, timeout=10)

    def test_demo_report_and_thresholds(self):
        for threshold, status, gate in [("none", 0, "Informational"),
                                        ("medium", 1, "FAIL"), ("high", 1, "FAIL")]:
            with self.subTest(threshold=threshold):
                result = self.run_report(ROOT / "examples/demo-plan.json", threshold)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn("Gate: " + gate, result.stdout)
                self.assertIn("| 3 | 3 | 0 |", result.stdout)
                self.assertEqual(result.stdout.count("| HIGH | google"), 3)

    def test_safe_report(self):
        result = self.run_report(ROOT / "examples/safe-plan.json", "medium")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Gate: PASS", result.stdout)
        self.assertIn("| 0 | 0 | 0 |", result.stdout)
        self.assertIn("No findings matched", result.stdout)
        self.assertIn("not proof of security", result.stdout)

    def test_order_and_medium_gate(self):
        findings = [("MEDIUM", "z", "review"), ("HIGH", "b", "fix"), ("HIGH", "a", "fix")]
        original = list(findings)
        report = markdown_report(findings, "high")
        self.assertLess(report.index("| HIGH | a"), report.index("| HIGH | b"))
        self.assertLess(report.index("| HIGH | b"), report.index("| MEDIUM | z"))
        self.assertEqual(findings, original)
        self.assertIn("Gate: PASS", markdown_report(findings[:1], "high"))
        self.assertIn("Gate: FAIL", markdown_report(findings[:1], "medium"))

    def test_untrusted_address_cannot_add_rows_or_markup(self):
        address = 'resource|\n# heading <script> @team [click](https://example.invalid) `code`'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps({"resource_changes": [{"address": address,
                "change": {"actions": ["delete"], "after": None}}]}), encoding="utf-8")
            result = self.run_report(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("&#124;", result.stdout)
        for unsafe in ["<script>", "@team", "[click]", "`code`", "\n# heading"]:
            self.assertNotIn(unsafe, result.stdout)
        rows = [line for line in result.stdout.splitlines() if line.startswith("| HIGH |")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count("|"), 4)

    def test_invalid_input_has_no_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            for document in ['{', '{"resource_changes": [], "resource_changes": []}',
                             '{"value": NaN}']:
                path.write_text(document, encoding="utf-8")
                result = self.run_report(path)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
