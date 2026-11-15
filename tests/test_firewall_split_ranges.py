import unittest

from cloudmesh_sentinel.cli import scan_plan


def scan(ranges):
    return scan_plan({"resource_changes": [{"type": "google_compute_firewall",
        "address": "google_compute_firewall.demo", "change": {"after": {
            "source_ranges": ranges, "allow": [{"protocol": "tcp", "ports": ["22"]}]}}}]})


class FirewallSplitRangesTests(unittest.TestCase):
    def test_ipv4_halves_cover_everywhere_once(self):
        self.assertEqual(scan(["0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/2"]),
                         [("HIGH", "google_compute_firewall.demo", "Firewall allows traffic from 0.0.0.0/0.")])

    def test_ipv6_halves_cover_everywhere_once(self):
        self.assertEqual(scan(["::/1", "8000::/1"]),
                         [("HIGH", "google_compute_firewall.demo", "Firewall allows traffic from ::/0.")])

    def test_partial_and_mixed_families_are_not_public(self):
        self.assertEqual(scan(["0.0.0.0/1", "8000::/1"]), [])

    def test_explicit_and_split_ranges_are_deduplicated(self):
        self.assertEqual(len(scan(["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"])), 1)
