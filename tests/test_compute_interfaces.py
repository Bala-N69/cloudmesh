import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]


def plan(after):
    return {"resource_changes": [{"type": "google_compute_instance", "address": "vm.example",
        "change": {"actions": ["create"], "after": after}}]}


class TestComputeInterfaces(unittest.TestCase):
    def test_invalid_block_shapes(self):
        for field in ["network_interface", "access_config", "ipv6_access_config"]:
            for value in [False, 0, "", {}, "invalid", [None], [[]], [{}, False]]:
                after = {field: value} if field == "network_interface" else {"network_interface": [{field: value}]}
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, field + " must be a list of objects"):
                        scan_plan(plan(after))

    def test_absent_and_unknown_configuration(self):
        for after in [{}, {"network_interface": None}, {"network_interface": []},
                      {"network_interface": [{}]},
                      {"network_interface": [{"access_config": None, "ipv6_access_config": []}]}]:
            self.assertEqual(scan_plan(plan(after)), [])

    def test_both_address_families_and_multiple_interfaces(self):
        for interfaces in [
            [{"access_config": [{}]}], [{"ipv6_access_config": [{}]}],
            [{}, {"access_config": [{}], "ipv6_access_config": [{}]}],
            [{"access_config": [{}]}, {"access_config": [{}]}],
        ]:
            self.assertEqual(scan_plan(plan({"network_interface": interfaces})),
                [("HIGH", "vm.example", "Compute instance has a public IP address.")])

    def test_public_interface_does_not_skip_later_validation(self):
        with self.assertRaisesRegex(ValueError, "ipv6_access_config"):
            scan_plan(plan({"network_interface": [
                {"access_config": [{}]}, {"ipv6_access_config": False}]}))

    def test_invalid_input_has_no_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps(plan({"network_interface": False})))
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [{"path": "bad.json", "kind": "terraform"}]}))
            for module, source in [("cli", path), ("batch", manifest)]:
                for output in ["text", "json", "markdown", "sarif"]:
                    with self.subTest(module=module, output=output):
                        result = subprocess.run([sys.executable, "-m", "cloudmesh_sentinel." + module,
                            str(source), "--format", output], cwd=ROOT, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("Compute network_interface must be a list of objects", result.stderr)
