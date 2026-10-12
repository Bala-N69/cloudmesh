"""Reject local seccomp profiles that previously produced clean reports."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes

ROOT = Path(__file__).resolve().parents[1]


class TestLocalSeccomp(unittest.TestCase):
    def workload(self, profile, scope="pod"):
        document = json.loads((ROOT / "examples/kubernetes-safe.json").read_text())
        spec = document["spec"]["template"]["spec"]
        if scope == "pod":
            context = spec["securityContext"]
        else:
            if scope != "containers":
                spec[scope] = [copy.deepcopy(spec["containers"][0])]
            context = spec[scope][0]["securityContext"]
        context["seccompProfile"] = profile
        return document

    def test_invalid_local_paths_in_all_scopes(self):
        profiles = [{"type": "Localhost"}] + [
            {"type": "Localhost", "localhostProfile": path}
            for path in [None, "", " ", False, 1, [], {}, "/profile.json",
                         "../profile.json", "profiles/../../profile.json", ".", "./", "a\x00b"]]
        profiles += [{"type": kind, "localhostProfile": "profile.json"}
                     for kind in [None, "RuntimeDefault", "Unconfined"]]
        for scope in ["pod", "containers", "initContainers", "ephemeralContainers"]:
            for profile in profiles:
                with self.subTest(scope=scope, profile=profile):
                    with self.assertRaisesRegex(ValueError, "localhostProfile"):
                        scan_kubernetes(self.workload(profile, scope))

    def test_valid_local_profiles_and_inheritance(self):
        for scope in ["pod", "containers", "initContainers", "ephemeralContainers"]:
            for path in ["profile.json", "profiles/allow.json", "./profiles/allow.json"]:
                with self.subTest(scope=scope, path=path):
                    self.assertEqual(scan_kubernetes(self.workload(
                        {"type": "Localhost", "localhostProfile": path}, scope)), [])

    def test_single_and_batch_cli_fail_without_partial_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            bad = folder / "bad.json"
            bad.write_text(json.dumps(self.workload({"type": "Localhost"})))
            manifest = folder / "batch.json"
            manifest.write_text(json.dumps({"inputs": [
                {"path": str(ROOT / "examples/kubernetes-safe.json"), "kind": "kubernetes"},
                {"path": "bad.json", "kind": "kubernetes"}]}))
            for output in ["text", "json", "markdown"]:
                for args in [
                    ["-m", "cloudmesh_sentinel.cli", str(bad), "--input-kind", "kubernetes"],
                    ["-m", "cloudmesh_sentinel.batch", str(manifest)]]:
                    with self.subTest(output=output, command=args[1]):
                        result = subprocess.run([sys.executable, *args, "--format", output],
                            cwd=ROOT, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("localhostProfile", result.stderr)
                        self.assertNotIn("Traceback", result.stderr)
