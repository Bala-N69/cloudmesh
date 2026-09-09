import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]


def firewall(after, actions=None):
    return {"resource_changes": [{"address": "google_compute_firewall.test",
            "type": "google_compute_firewall",
            "change": {"actions": actions or ["create"], "after": after}}]}


class TestGcpFirewall(unittest.TestCase):
    def test_public_rule_matrix(self):
        for protocol, ports, severity in [
            ("tcp", ["20-25"], "HIGH"), ("6", ["3380-3390"], "HIGH"),
            ("tcp", [], "HIGH"), ("all", [], "HIGH"),
            ("tcp", ["443"], "MEDIUM"), ("udp", ["22"], "MEDIUM"),
            ("icmp", [], "MEDIUM"), ("tcp", ["23-3370"], "MEDIUM"),
        ]:
            for source in ["0.0.0.0/0", "::/0"]:
                with self.subTest(protocol=protocol, ports=ports, source=source):
                    result = scan_plan(firewall({"source_ranges": [source],
                        "allow": [{"protocol": protocol, "ports": ports}]}))
                    self.assertEqual(result, [(severity, "google_compute_firewall.test",
                                              f"Firewall allows traffic from {source}.")])

    def test_inactive_and_nonpublic_rules(self):
        base = {"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "all"}]}
        for patch in [{"disabled": True}, {"direction": "EGRESS"}, {"allow": []},
                      {"source_ranges": ["10.0.0.0/8"]}, {"source_ranges": None}]:
            with self.subTest(patch=patch):
                self.assertEqual(scan_plan(firewall({**base, **patch})), [])

    def test_equivalent_ipv6_ranges_are_deduplicated(self):
        result = scan_plan(firewall({"source_ranges": ["::/0", "0:0:0:0:0:0:0:0/0"],
                                     "allow": [{"protocol": "all"}]}))
        self.assertEqual(len(result), 1)

    def test_deleted_firewall_only_reports_deletion(self):
        self.assertEqual(scan_plan(firewall(None, ["delete"])),
                         [("HIGH", "google_compute_firewall.test", "Resource will be deleted.")])


class TestCliReports(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"),
                               *map(str, args)], capture_output=True, text=True, timeout=10)

    def test_risky_fixture_json_and_gate(self):
        result = self.run_cli(ROOT / "examples/gcp-network-risk-plan.json", "--format", "json", "--fail-on", "high")
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["summary"], {"total": 3, "MEDIUM": 0, "HIGH": 3})
        self.assertEqual({f["address"] for f in report["findings"]}, {
            "google_compute_firewall.ipv6_ssh", "google_compute_firewall.admin_range",
            "google_compute_firewall.all_tcp"})
        self.assertEqual(result.stderr, "")

    def test_safe_fixture_passes_strict_gate(self):
        result = self.run_cli(ROOT / "examples/safe-plan.json", "--format", "json", "--fail-on", "medium")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["findings"], [])

    def test_default_remains_informational(self):
        result = self.run_cli(ROOT / "examples/demo-plan.json")
        self.assertEqual(result.returncode, 0)
        self.assertIn("CloudMesh Sentinel: 3 finding(s)", result.stdout)

    def test_medium_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(firewall({"source_ranges": ["::/0"],
                "allow": [{"protocol": "tcp", "ports": ["443"]}]})))
            for threshold, expected in [("none", 0), ("high", 0), ("medium", 1)]:
                with self.subTest(threshold=threshold):
                    self.assertEqual(self.run_cli(path, "--fail-on", threshold).returncode, expected)

    def test_invalid_inputs_fail_without_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            for data in ["{", "[]", '{"resource_changes": null}', '{"resource_changes": [null]}']:
                with self.subTest(data=data):
                    path.write_text(data)
                    result = self.run_cli(path, "--format", "json")
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("unable to scan plan", result.stderr)
            result = self.run_cli(Path(directory) / "missing.json")
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
