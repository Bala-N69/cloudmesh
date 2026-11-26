"""Null container identities must not mask inherited Pod root identities."""
import json
from pathlib import Path
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes


ROOT = Path(__file__).resolve().parents[1]


class KubernetesNullIdentityTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / "examples/kubernetes-safe.json").read_text())
        self.spec = self.document["spec"]["template"]["spec"]
        self.container = self.spec["containers"][0]["securityContext"]

    def test_null_container_values_inherit_root_user_and_group(self):
        self.spec["securityContext"].update(runAsUser=0, runAsGroup=0)
        self.container.update(runAsUser=None, runAsGroup=None)
        findings = scan_kubernetes(self.document)
        self.assertEqual([severity for severity, _, _ in findings], ["HIGH", "MEDIUM"])
        self.assertIn("root UID 0", findings[0][2])
        self.assertIn("root GID 0", findings[1][2])

    def test_nonroot_container_values_override_pod_root_values(self):
        self.spec["securityContext"].update(runAsUser=0, runAsGroup=0)
        self.container.update(runAsUser=1000, runAsGroup=1000)
        self.assertEqual(scan_kubernetes(self.document), [])
