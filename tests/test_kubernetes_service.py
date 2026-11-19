import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes


ROOT = Path(__file__).resolve().parents[1]


def service(spec, name="web"):
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": "lab"}, "spec": spec}


class KubernetesServiceTests(unittest.TestCase):
    def test_exposure_types_and_distinct_findings(self):
        expected = [
            ({"type": "LoadBalancer"}, "LoadBalancer"),
            ({"type": "NodePort", "ports": [{"nodePort": 30080}]}, "node port"),
            ({"externalIPs": ["203.0.113.10", "2001:db8::10"]}, "externalIPs"),
        ]
        for spec, message in expected:
            with self.subTest(spec=spec):
                findings = scan_kubernetes(service(spec))
                self.assertTrue(any(message in finding[2] for finding in findings))
                self.assertTrue(all(level == "HIGH" for level, _, _ in findings))
        combined = scan_kubernetes(service({"type": "LoadBalancer", "externalIPs": ["203.0.113.10"],
                                            "ports": [{"nodePort": 30080}]}))
        self.assertEqual(len(combined), 3)

    def test_internal_services_and_lists(self):
        self.assertEqual(scan_kubernetes(service({"type": "ClusterIP", "ports": [{"port": 80}]})), [])
        self.assertEqual(scan_kubernetes(service({"type": "ExternalName", "externalName": "example.invalid"})), [])
        document = {"kind": "List", "items": [service({"type": "ClusterIP"}, "internal"),
                                               service({"type": "NodePort"}, "edge")]}
        self.assertEqual(len(scan_kubernetes(document)), 1)
        self.assertEqual(scan_kubernetes(document)[0][1], "Service/lab/edge")

    def test_invalid_supplied_values(self):
        invalid = [{"type": False}, {"type": []}, {"type": "Unknown"},
                   {"externalIPs": "203.0.113.10"}, {"externalIPs": ["invalid"]},
                   {"ports": {}}, {"ports": [None]}, {"ports": [{"nodePort": True}]},
                   {"ports": [{"nodePort": -1}]}, {"ports": [{"nodePort": 65536}]}]
        for spec in invalid:
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                scan_kubernetes(service(spec))

    def test_invalid_later_service_cannot_emit_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "services.json"
            path.write_text(json.dumps({"kind": "List", "items": [
                service({"type": "LoadBalancer"}), service({"externalIPs": ["invalid"]})]}))
            result = subprocess.run([sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"),
                                     str(path), "--input-kind", "kubernetes", "--format", "json"],
                                    cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")

    def test_example_reports_and_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.json"
            path.write_text(json.dumps(service({"type": "LoadBalancer",
                                                "ports": [{"port": 80, "nodePort": 30080}]}, "edge")))
            self.assertEqual(len(scan_kubernetes(json.loads(path.read_text()))), 2)
            result = subprocess.run([sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"),
                                     str(path), "--input-kind", "kubernetes", "--fail-on", "high"],
                                    cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("Service/lab/edge", result.stdout)
