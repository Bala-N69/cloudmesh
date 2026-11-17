import json
from pathlib import Path
import subprocess
import sys
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes


ROOT = Path(__file__).resolve().parents[1]


def workload(ports, group="containers"):
    return {"kind": "Pod", "metadata": {"name": "test"}, "spec": {
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "main", "securityContext": {"allowPrivilegeEscalation": False,
                       "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                       "capabilities": {"drop": ["ALL"]}}}],
        **({group: [{"name": "extra", "ports": ports,
                    "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": True,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}}}]}
           if group != "containers" else {})}}


class KubernetesHostPortTests(unittest.TestCase):
    def test_hostport_in_all_container_groups(self):
        for group in ("containers", "initContainers", "ephemeralContainers"):
            document = workload([{"hostPort": 8080}, {"hostPort": 9090}], group)
            if group == "containers":
                document["spec"]["containers"][0]["ports"] = [{"hostPort": 8080}, {"hostPort": 9090}]
            with self.subTest(group=group):
                findings = scan_kubernetes(document)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0][0], "HIGH")
                self.assertIn("/" + group + "/", findings[0][1])

    def test_zero_missing_and_null_are_not_bindings(self):
        for ports in (None, [], [{}], [{"hostPort": 0}], [{"hostPort": None}]):
            with self.subTest(ports=ports):
                document = workload(ports)
                document["spec"]["containers"][0]["ports"] = ports
                self.assertEqual(scan_kubernetes(document), [])

    def test_bad_shapes_rejected_even_after_hostport_found(self):
        for ports in (False, {}, [None], [{"hostPort": True}], [{"hostPort": -1}],
                      [{"hostPort": 65536}], [{"hostPort": "8080"}],
                      [{"hostPort": 80}, {"hostPort": False}]):
            document = workload(ports)
            document["spec"]["containers"][0]["ports"] = ports
            with self.subTest(ports=ports), self.assertRaisesRegex(ValueError, "ports|hostPort"):
                scan_kubernetes(document)

    def test_example_reports_one_high_and_fails_gate(self):
        path = ROOT / "examples/kubernetes-hostport-risky.json"
        self.assertEqual(len(scan_kubernetes(json.loads(path.read_text()))), 1)
        result = subprocess.run([sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"),
                                 str(path), "--input-kind", "kubernetes", "--fail-on", "high"],
                                cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Container binds a hostPort", result.stdout)
