import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]


def plan(field, value):
    block = "ip_configuration" if field == "ipv4_enabled" else "backup_configuration"
    return {"resource_changes": [{"type": "google_sql_database_instance", "address": "sql.example",
        "change": {"actions": ["create"], "after": {"settings": [{block: [{field: value}]}]}}}]}


class TestSqlFlags(unittest.TestCase):
    def test_invalid_boolean_values(self):
        for field in ["ipv4_enabled", "enabled"]:
            for value in ["true", "false", 0, 1, [], {}]:
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, field + " must be a boolean"):
                        scan_plan(plan(field, value))

    def test_valid_values_preserve_findings(self):
        for field, risky, severity in [("ipv4_enabled", True, "HIGH"), ("enabled", False, "MEDIUM")]:
            for value in [True, False, None]:
                with self.subTest(field=field, value=value):
                    findings = scan_plan(plan(field, value))
                    self.assertEqual(len(findings), int(value is risky))
                    if findings:
                        self.assertEqual(findings[0][0], severity)

    def test_invalid_later_block_is_not_hidden(self):
        document = plan("ipv4_enabled", False)
        settings = document["resource_changes"][0]["change"]["after"]["settings"]
        settings.append({"backup_configuration": [{"enabled": True}, {"enabled": "false"}]})
        with self.assertRaisesRegex(ValueError, "enabled must be a boolean"):
            scan_plan(document)

    def test_cli_and_batch_fail_without_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [{"path": "bad.json", "kind": "terraform"}]}))
            for field in ["ipv4_enabled", "enabled"]:
                document = plan(field, "true")
                document["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
                path.write_text(json.dumps(document))
                for command in [["-m", "cloudmesh_sentinel.cli", str(path)],
                                ["-m", "cloudmesh_sentinel.batch", str(manifest)]]:
                    for output in ["text", "json", "markdown"]:
                        result = subprocess.run([sys.executable, *command, "--format", output],
                            cwd=ROOT, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn(field + " must be a boolean", result.stderr)
