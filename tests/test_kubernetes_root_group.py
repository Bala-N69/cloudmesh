"""Review explicit root group IDs without guessing image defaults."""
import copy
import json
from pathlib import Path
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes


ROOT = Path(__file__).resolve().parents[1]


class KubernetesRootGroupTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / "examples/kubernetes-safe.json").read_text())
        self.spec = self.document["spec"]["template"]["spec"]

    def test_pod_root_group_inherited_and_overridden(self):
        self.spec["securityContext"]["runAsGroup"] = 0
        self.assertEqual(scan_kubernetes(self.document)[0][0], "MEDIUM")
        self.spec["containers"][0]["securityContext"]["runAsGroup"] = 1000
        self.assertEqual(scan_kubernetes(self.document), [])

    def test_each_container_group(self):
        for group in ("containers", "initContainers", "ephemeralContainers"):
            with self.subTest(group=group):
                document = copy.deepcopy(self.document)
                spec = document["spec"]["template"]["spec"]
                if group != "containers":
                    spec[group] = [copy.deepcopy(spec["containers"][0])]
                spec[group][0]["securityContext"]["runAsGroup"] = 0
                findings = scan_kubernetes(document)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0][0], "MEDIUM")
                self.assertIn(f"/{group}/", findings[0][1])

    def test_missing_and_nonzero_are_clean(self):
        self.assertEqual(scan_kubernetes(self.document), [])
        self.spec["containers"][0]["securityContext"]["runAsGroup"] = 1000
        self.assertEqual(scan_kubernetes(self.document), [])

    def test_invalid_values_rejected_at_both_scopes(self):
        for context in (self.spec["securityContext"], self.spec["containers"][0]["securityContext"]):
            for value in ("0", True, -1, 1.5, [], {}):
                with self.subTest(value=value, context=context):
                    context["runAsGroup"] = value
                    with self.assertRaisesRegex(ValueError, "runAsGroup"):
                        scan_kubernetes(self.document)
                    context.pop("runAsGroup")
