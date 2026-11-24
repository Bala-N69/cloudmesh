"""Review explicitly disabled Cloud SQL API-level deletion protection."""
import unittest

from cloudmesh_sentinel.cli import scan_plan


ADDRESS = "google_sql_database_instance.example"


def plan(settings):
    return {"resource_changes": [{"type": "google_sql_database_instance",
            "address": ADDRESS, "change": {"actions": ["update"],
            "after": {"settings": settings}}}]}


class SqlDeletionProtectionTests(unittest.TestCase):
    def test_explicit_false_reports_once(self):
        findings = scan_plan(plan([{"deletion_protection_enabled": False},
                                   {"deletion_protection_enabled": False}]))
        self.assertEqual(findings, [("MEDIUM", ADDRESS,
            "Cloud SQL instance deletion protection is explicitly disabled; review deletion risk.")])

    def test_unknown_and_enabled_do_not_report(self):
        for settings in ([], [{}], [{"deletion_protection_enabled": None}],
                         [{"deletion_protection_enabled": True}]):
            with self.subTest(settings=settings):
                self.assertEqual(scan_plan(plan(settings)), [])

    def test_bad_values_are_rejected(self):
        for value in ("false", 0, [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "deletion_protection_enabled"):
                    scan_plan(plan([{"deletion_protection_enabled": value}]))

    def test_other_sql_findings_remain_independent(self):
        findings = scan_plan(plan([{"deletion_protection_enabled": False,
                                   "backup_configuration": [{"enabled": False}]}]))
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(severity == "MEDIUM" for severity, _, _ in findings))
