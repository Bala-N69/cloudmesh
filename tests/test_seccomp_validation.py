import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes

ROOT = Path(__file__).resolve().parents[1]


class TestSeccompValidation(unittest.TestCase):
    def setUp(self):
        self.workload = json.loads((ROOT / "examples/kubernetes-safe.json").read_text())

    def test_invalid_profiles_in_every_scope(self):
        invalid = [[], False, 0, "RuntimeDefault", {"type": []},
                   {"type": {}}, {"type": True}, {"type": 1}]
        for scope in ["pod", "containers", "initContainers", "ephemeralContainers"]:
            for profile in invalid:
                with self.subTest(scope=scope, profile=profile):
                    workload = copy.deepcopy(self.workload)
                    spec = workload["spec"]["template"]["spec"]
                    if scope == "pod":
                        context = spec["securityContext"]
                        spec["containers"][0]["securityContext"]["seccompProfile"] = {
                            "type": "RuntimeDefault"}
                    else:
                        if scope != "containers":
                            spec[scope] = [copy.deepcopy(spec["containers"][0])]
                        context = spec[scope][0]["securityContext"]
                    context["seccompProfile"] = profile
                    with self.assertRaisesRegex(ValueError, "seccompProfile"):
                        scan_kubernetes(workload)

    def test_valid_shapes_keep_existing_findings(self):
        context = self.workload["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        for profile, count in [(None, 1), ({}, 1), ({"type": None}, 1),
                               ({"type": "Unconfined"}, 1), ({"type": "unknown"}, 1),
                               ({"type": "RuntimeDefault"}, 0),
                               ({"type": "Localhost", "localhostProfile": "example.json"}, 0)]:
            with self.subTest(profile=profile):
                context["seccompProfile"] = profile
                findings = scan_kubernetes(self.workload)
                self.assertEqual(len(findings), count)
                if count:
                    self.assertEqual(findings[0][0], "MEDIUM")
                    self.assertIn("seccomp", findings[0][2])

    def test_cli_rejects_without_partial_report(self):
        spec = self.workload["spec"]["template"]["spec"]
        spec["hostNetwork"] = True
        spec["securityContext"]["seccompProfile"] = {"type": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workload.json"
            path.write_text(json.dumps(self.workload), encoding="utf-8")
            for output_format in ["text", "json", "markdown"]:
                result = subprocess.run([sys.executable,
                    str(ROOT / "cloudmesh_sentinel/cli.py"), str(path),
                    "--input-kind", "kubernetes", "--format", output_format],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("seccompProfile.type must be a string", result.stderr)
