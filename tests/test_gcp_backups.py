import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = "google_sql_database_instance.example"
WARNING = ("MEDIUM", ADDRESS,
           "Cloud SQL automated backups are explicitly disabled; review recovery coverage.")


def plan(settings, actions=None):
    return {"resource_changes": [{"type": "google_sql_database_instance",
        "address": ADDRESS, "change": {"actions": actions or ["update"],
        "after": {"settings": settings}}}]}


class TestCloudSqlBackups(unittest.TestCase):
    def test_explicitly_disabled_backups(self):
        for action in [["create"], ["update"], ["no-op"]]:
            with self.subTest(action=action):
                self.assertEqual(scan_plan(plan([
                    {"backup_configuration": [{"enabled": False}]}], action)), [WARNING])

    def test_missing_unknown_and_enabled_values(self):
        settings_cases = [None, [], [{}], [{"backup_configuration": None}],
                          [{"backup_configuration": []}]]
        settings_cases.append([{"backup_configuration": [{}]}])
        for settings in settings_cases:
            with self.subTest(settings=settings):
                self.assertEqual(scan_plan(plan(settings)), [])

    def test_no_warning_for_other_values(self):
        for value in [True, None, 0, "false"]:
            with self.subTest(value=value):
                self.assertEqual(scan_plan(plan([
                    {"backup_configuration": [{"enabled": value}]}])), [])

    def test_deleted_instance_only_reports_deletion(self):
        document = plan([], ["delete"])
        change = document["resource_changes"][0]["change"]
        change["before"] = {"settings": [{"backup_configuration": [{"enabled": False}]}]}
        change["after"] = None
        self.assertEqual(scan_plan(document), [("HIGH", ADDRESS, "Resource will be deleted.")])

    def test_replacement_and_public_ip_findings_remain(self):
        result = scan_plan(plan([{"backup_configuration": [{"enabled": False}],
            "ip_configuration": [{"ipv4_enabled": True}]}], ["delete", "create"]))
        self.assertIn(WARNING, result)
        self.assertIn(("HIGH", ADDRESS, "Resource will be replaced."), result)
        self.assertIn(("HIGH", ADDRESS, "Cloud SQL instance permits a public IPv4 address."), result)
        self.assertEqual(len(result), 3)

    def test_cli_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan([
                {"backup_configuration": [{"enabled": False}]}])), encoding="utf-8")
            for threshold, expected in [("none", 0), ("high", 0), ("medium", 1)]:
                with self.subTest(threshold=threshold):
                    result = subprocess.run([sys.executable,
                        str(ROOT / "cloudmesh_sentinel/cli.py"), str(path),
                        "--format", "json", "--fail-on", threshold],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["summary"],
                                     {"total": 1, "MEDIUM": 1, "HIGH": 0})
