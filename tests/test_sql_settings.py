import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]


def plan(after):
    return {"resource_changes": [{"type": "google_sql_database_instance", "address": "sql.example",
        "change": {"actions": ["create"], "after": after}}]}


class TestSqlSettings(unittest.TestCase):
    def test_invalid_blocks_rejected(self):
        for field in ["settings", "backup_configuration", "ip_configuration"]:
            for value in [False, 0, "", {}, "invalid", [None], [[]], [{}, False]]:
                after = {field: value} if field == "settings" else {"settings": [{field: value}]}
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, field + " must be a list of objects"):
                        scan_plan(plan(after))

    def test_missing_null_and_empty_blocks_supported(self):
        for after in [{}, {"settings": None}, {"settings": []}, {"settings": [{}]},
                      {"settings": [{"backup_configuration": None, "ip_configuration": None}]},
                      {"settings": [{"backup_configuration": [], "ip_configuration": []}]}]:
            self.assertEqual(scan_plan(plan(after)), [])

    def test_existing_findings_preserved(self):
        findings = scan_plan(plan({"settings": [{"backup_configuration": [{"enabled": False}],
            "ip_configuration": [{"ipv4_enabled": True}]}]}))
        self.assertEqual([item[0] for item in findings], ["MEDIUM", "HIGH"])

    def test_cli_and_batch_no_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps(plan({"settings": False})))
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [{"path": "bad.json", "kind": "terraform"}]}))
            for module, source in [("cli", path), ("batch", manifest)]:
                for output in ["text", "json", "markdown", "sarif"]:
                    with self.subTest(module=module, output=output):
                        result = subprocess.run([sys.executable, "-m", "cloudmesh_sentinel." + module,
                            str(source), "--format", output], cwd=ROOT, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("Cloud SQL settings must be a list of objects", result.stderr)
