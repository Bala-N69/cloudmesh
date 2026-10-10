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

    def test_disabled_requires_boolean(self):
        for patch in [{}, {"direction": "EGRESS"}, {"allow": []}]:
            for value in ["false", "true", 0, 1, [], {}, [False]]:
                with self.subTest(patch=patch, value=value):
                    after = {"source_ranges": ["0.0.0.0/0"],
                             "allow": [{"protocol": "all"}], "disabled": value, **patch}
                    with self.assertRaisesRegex(ValueError, "disabled must be a boolean"):
                        scan_plan(firewall(after))

    def test_disabled_boolean_and_null_behavior(self):
        for value, count in [(True, 0), (False, 1), (None, 1)]:
            with self.subTest(value=value):
                result = scan_plan(firewall({"source_ranges": ["::/0"],
                    "allow": [{"protocol": "all"}], "disabled": value}))
                self.assertEqual(len(result), count)

    def test_invalid_disabled_cli_rejects_without_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(firewall({"source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "all"}], "disabled": "false"},
                ["delete", "create"])), encoding="utf-8")
            for output_format in ["text", "json", "markdown"]:
                with self.subTest(output_format=output_format):
                    result = subprocess.run([sys.executable,
                        str(ROOT / "cloudmesh_sentinel/cli.py"), str(path),
                        "--format", output_format], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("disabled must be a boolean", result.stderr)

    def test_deleted_firewall_only_reports_deletion(self):
        self.assertEqual(scan_plan(firewall(None, ["delete"])),
                         [("HIGH", "google_compute_firewall.test", "Resource will be deleted.")])


class TestComputeExternalAccess(unittest.TestCase):
    def plan(self, interfaces, actions=None):
        return {"resource_changes": [{"address": "google_compute_instance.test",
            "type": "google_compute_instance", "change": {
                "actions": actions or ["create"],
                "after": {"network_interface": interfaces}}}]}

    def test_external_access_once_per_instance(self):
        for interfaces in [
            [{"access_config": [{}]}],
            [{"ipv6_access_config": [{}]}],
            [{"ipv6_access_config": [{"external_ipv6": "2001:db8::1"}]}],
            [{"access_config": [{}], "ipv6_access_config": [{}]}],
            [{}, {"ipv6_access_config": [{}]}, {"access_config": [{}]}],
        ]:
            with self.subTest(interfaces=interfaces):
                self.assertEqual(scan_plan(self.plan(interfaces)), [
                    ("HIGH", "google_compute_instance.test",
                     "Compute instance has a public IP address.")])

    def test_private_and_unknown_interfaces(self):
        for interfaces in [None, [], [{}],
                           [{"access_config": [], "ipv6_access_config": []}],
                           [{"access_config": None, "ipv6_access_config": None}],
                           [{"ipv6_address": "fd20::1"}]]:
            with self.subTest(interfaces=interfaces):
                self.assertEqual(scan_plan(self.plan(interfaces)), [])

    def test_deleted_instance_does_not_report_old_external_access(self):
        plan = self.plan(None, ["delete"])
        change = plan["resource_changes"][0]["change"]
        change["before"] = {"network_interface": [{"ipv6_access_config": [{}]}]}
        change["after"] = None
        self.assertEqual(scan_plan(plan), [("HIGH", "google_compute_instance.test",
                                           "Resource will be deleted.")])

    def test_ipv6_cli_severity_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(self.plan([{"ipv6_access_config": [{}]}])))
            result = subprocess.run([sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"),
                str(path), "--format", "json", "--fail-on", "high"],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout)["summary"],
                             {"total": 1, "MEDIUM": 0, "HIGH": 1})


class TestProjectPublicIam(unittest.TestCase):
    def test_public_principals_and_private_bindings(self):
        for resource_type, field in [("google_project_iam_member", "member"),
                                     ("google_project_iam_binding", "members")]:
            for member in ["allUsers", "allAuthenticatedUsers", "domain:example.invalid", None]:
                with self.subTest(resource_type=resource_type, member=member):
                    after = {"role": "roles/viewer", field: [member] if field == "members" and member else member}
                    plan = {"resource_changes": [{"address": "project_access",
                        "type": resource_type, "change": {"actions": ["create"], "after": after}}]}
                    expected = [("HIGH", "project_access", "Project IAM change includes a public principal.")]
                    self.assertEqual(scan_plan(plan), expected if member in {"allUsers", "allAuthenticatedUsers"} else [])

    def test_removed_public_binding_only_reports_deletion(self):
        plan = {"resource_changes": [{"address": "project_access", "type": "google_project_iam_binding",
            "change": {"actions": ["delete"], "before": {"members": ["allUsers"]}, "after": None}}]}
        self.assertEqual(scan_plan(plan), [("HIGH", "project_access", "Resource will be deleted.")])


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

    def test_duplicate_json_keys_are_rejected(self):
        documents = [
            '{"resource_changes": [{"change": {"actions": ["delete"]}}], "resource_changes": []}',
            '{"resource_changes": [], "resource_changes": []}',
            '{"resource_changes": [{"change": {"actions": ["delete"], "actions": []}}]}',
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            for document in documents:
                path.write_text(document, encoding="utf-8")
                for output_format in ["text", "json"]:
                    with self.subTest(document=document, output_format=output_format):
                        result = self.run_cli(path, "--format", output_format)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("Duplicate JSON key", result.stderr)

    def test_nonfinite_json_constants_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            for constant in ["NaN", "Infinity", "-Infinity"]:
                path.write_text('{"resource_changes": [], "metadata": {"value": ' + constant + '}}',
                                encoding="utf-8")
                for output_format in ["text", "json"]:
                    with self.subTest(constant=constant, output_format=output_format):
                        result = self.run_cli(path, "--format", output_format)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("Invalid JSON numeric constant", result.stderr)

    def test_numeric_values_and_constant_strings_remain_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps({"resource_changes": [], "metadata": {
                "values": [0, -5, 1.25, "NaN", "Infinity", "-Infinity"]}}), encoding="utf-8")
            result = self.run_cli(path, "--format", "json")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["findings"], [])


if __name__ == "__main__":
    unittest.main()
