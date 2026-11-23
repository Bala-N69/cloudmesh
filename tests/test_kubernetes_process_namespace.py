"""Check pod process-namespace sharing without conflating it with host PID access."""
import json
from pathlib import Path
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes


ROOT = Path(__file__).resolve().parents[1]


class KubernetesProcessNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / "examples/kubernetes-safe.json").read_text())
        self.spec = self.document["spec"]["template"]["spec"]

    def test_enabled_adds_medium_finding(self):
        self.spec["shareProcessNamespace"] = True
        findings = scan_kubernetes(self.document)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "MEDIUM")
        self.assertIn("shares a process namespace", findings[0][2])

    def test_disabled_or_absent_is_clean(self):
        self.assertEqual(scan_kubernetes(self.document), [])
        self.spec["shareProcessNamespace"] = False
        self.assertEqual(scan_kubernetes(self.document), [])

    def test_malformed_values_are_rejected(self):
        for value in ("true", 1, [], {}):
            with self.subTest(value=value):
                self.spec["shareProcessNamespace"] = value
                with self.assertRaisesRegex(ValueError, "shareProcessNamespace"):
                    scan_kubernetes(self.document)
