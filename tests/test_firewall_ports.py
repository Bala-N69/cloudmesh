import unittest

from cloudmesh_sentinel.cli import scan_plan


def scan(ports):
    return scan_plan({"resource_changes": [{"type": "google_compute_firewall",
        "address": "google_compute_firewall.test", "change": {"after": {
            "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ports}]}}}]})


class FirewallPortTests(unittest.TestCase):
    def test_admin_port_in_valid_range(self):
        self.assertEqual(scan(["20-23"])[0][0], "HIGH")
        self.assertEqual(scan(["443"])[0][0], "MEDIUM")

    def test_bad_ports_are_not_ignored(self):
        for value in ["22-", "-22", "3389-22", "0", "65536", "22-3389-443", "ssh", "٢٢", "99999999999999999999"]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "invalid TCP port"):
                scan(["22", value])
