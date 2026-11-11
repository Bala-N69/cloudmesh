import unittest

from cloudmesh_sentinel.cli import scan_plan


def scan(*groups):
    configurations = [{"cidr_blocks": [{"cidr_block": value} for value in group]}
                      for group in groups]
    return scan_plan({"resource_changes": [{"type": "google_container_cluster",
        "address": "google_container_cluster.demo", "change": {"after": {
            "master_authorized_networks_config": configurations}}}]})


class GkeAllowlistTests(unittest.TestCase):
    def test_split_full_coverage_reports_once(self):
        result = scan(["0.0.0.0/1", "128.0.0.0/1"], ["0.0.0.0/0"])
        self.assertEqual(result, [("HIGH", "google_container_cluster.demo",
                                  "GKE control plane allows access from 0.0.0.0/0.")])

    def test_partial_or_separate_configs_do_not_report(self):
        self.assertEqual(scan(["0.0.0.0/1"], ["128.0.0.0/1"]), [])
        self.assertEqual(scan(["::/0", "0.0.0.0/1", None]), [])

    def test_invalid_later_range_is_not_hidden(self):
        for value in [False, 0, {}, "invalid"]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "GKE cidr_block"):
                scan(["0.0.0.0/0"], [value])

    def test_invalid_blocks_rejected(self):
        for value in [False, {}, [None]]:
            plan = {"resource_changes": [{"type": "google_container_cluster", "change": {
                "after": {"master_authorized_networks_config": value}}}]}
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "GKE master_authorized"):
                scan_plan(plan)
