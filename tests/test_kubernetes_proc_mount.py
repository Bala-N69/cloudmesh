"""Exercise unmasked procMount detection across Kubernetes container types."""
import copy
import json
from pathlib import Path
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes


ROOT = Path(__file__).resolve().parents[1]


class KubernetesProcMountTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / "examples/kubernetes-safe.json").read_text())
        self.spec = self.document["spec"]["template"]["spec"]

    def test_unmasked_is_high_for_each_container_type(self):
        for group in ("containers", "initContainers", "ephemeralContainers"):
            with self.subTest(group=group):
                document = copy.deepcopy(self.document)
                spec = document["spec"]["template"]["spec"]
                if group != "containers":
                    spec[group] = [copy.deepcopy(spec["containers"][0])]
                spec[group][0]["securityContext"]["procMount"] = "Unmasked"
                findings = scan_kubernetes(document)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0][0], "HIGH")
                self.assertIn(f"/{group}/", findings[0][1])

    def test_default_is_clean_and_invalid_values_fail(self):
        self.spec["containers"][0]["securityContext"]["procMount"] = "Default"
        self.assertEqual(scan_kubernetes(self.document), [])
        for value in ("unmasked", "Unknown", True, [], {}):
            with self.subTest(value=value):
                self.spec["containers"][0]["securityContext"]["procMount"] = value
                with self.assertRaisesRegex(ValueError, "procMount"):
                    scan_kubernetes(self.document)
