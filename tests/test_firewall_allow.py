import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]


def plan(after):
    return {"resource_changes": [{"type": "google_compute_firewall",
        "address": "firewall.example", "change": {"actions": ["create"], "after": after}}]}


class TestFirewallAllow(unittest.TestCase):
    def test_rejects_malformed_rules_even_when_inactive(self):
        for value in [False, 0, "", {}, "tcp", [None], [False], [[]], [{}, "tcp"]]:
            for extra in [{}, {"disabled": True}, {"direction": "EGRESS"}]:
                with self.subTest(value=value, extra=extra):
                    with self.assertRaisesRegex(ValueError, "Firewall allow must be a list of objects"):
                        scan_plan(plan({"allow": value, **extra}))

    def test_empty_and_unknown_rules_remain_supported(self):
        for after in [{}, {"allow": None}, {"allow": []}]:
            self.assertEqual(scan_plan(plan(after)), [])

    def test_valid_rules_keep_severity_and_inactive_behavior(self):
        for rule, severity in [({"protocol": "tcp", "ports": ["22"]}, "HIGH"),
                               ({"protocol": "tcp", "ports": ["443"]}, "MEDIUM")]:
            after = {"allow": [rule], "source_ranges": ["0.0.0.0/0"]}
            self.assertEqual(scan_plan(plan(after)), [(severity, "firewall.example",
                "Firewall allows traffic from 0.0.0.0/0.")])
            for extra in [{"disabled": True}, {"direction": "EGRESS"}]:
                self.assertEqual(scan_plan(plan({**after, **extra})), [])

    def test_cli_and_batch_fail_without_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps(plan({"allow": {}})))
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [{"path": "bad.json", "kind": "terraform"}]}))
            for module, source in [("cli", path), ("batch", manifest)]:
                for output in ["text", "json", "markdown"]:
                    with self.subTest(module=module, output=output):
                        result = subprocess.run([sys.executable, "-m", "cloudmesh_sentinel." + module,
                            str(source), "--format", output], cwd=ROOT, capture_output=True,
                            text=True, timeout=10)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("Firewall allow must be a list of objects", result.stderr)
