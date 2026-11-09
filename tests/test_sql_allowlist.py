import unittest

from cloudmesh_sentinel.cli import scan_plan


def findings(*groups):
    configs = [{"authorized_networks": [{"value": value} for value in group]}
               for group in groups]
    return scan_plan({"resource_changes": [{"type": "google_sql_database_instance",
        "change": {"after": {"settings": [{"ip_configuration": configs}]}}}]})


class SqlAllowlistTests(unittest.TestCase):
    def test_full_coverage_reported_once(self):
        result = findings(["128.0.0.0/1", "0.0.0.0/1", "0.0.0.0/2"], ["0.0.0.0/0"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "HIGH")

    def test_independent_configs_and_partial_coverage(self):
        self.assertEqual(findings(["0.0.0.0/1", "::/0", None], ["128.0.0.0/1"]), [])
        self.assertEqual(findings(["0.0.0.0/1", "128.0.0.0/2"]), [])

    def test_invalid_later_value_is_not_hidden(self):
        for value in ["bad", False, 0, {}]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "authorized_networks.value"):
                findings(["0.0.0.0/0"], [value])
