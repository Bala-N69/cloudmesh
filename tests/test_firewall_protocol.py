import unittest

from cloudmesh_sentinel.cli import scan_plan


def scan(rule):
    return scan_plan({"resource_changes": [{"type": "google_compute_firewall",
        "address": "google_compute_firewall.demo", "change": {"after": {
            "source_ranges": ["0.0.0.0/0"], "allow": [rule]}}}]})


class FirewallProtocolTests(unittest.TestCase):
    def test_invalid_supplied_protocols(self):
        for value in [None, False, 6, "", "  ", [], {}]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "allow.protocol"):
                scan({"protocol": value, "ports": ["22"]})

    def test_valid_protocols_and_omitted_legacy_default(self):
        self.assertEqual(scan({"ports": ["22"]})[0][0], "HIGH")
        self.assertEqual(scan({"protocol": "TCP", "ports": ["22"]})[0][0], "HIGH")
        self.assertEqual(scan({"protocol": "udp", "ports": ["53"]})[0][0], "MEDIUM")
