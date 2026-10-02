"""Opt-in runtime checks for a locally built image; never pull or build images."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


IMAGE = os.environ.get("CLOUDMESH_DOCKER_TEST_IMAGE")


@unittest.skipUnless(IMAGE, "Set CLOUDMESH_DOCKER_TEST_IMAGE to test a built image")
class TestContainer(unittest.TestCase):
    def run_container(self, *args, entrypoint=None, plan_path=None):
        command = ["docker", "run", "--rm", "--pull=never", "--network=none",
                   "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"]
        if entrypoint:
            command += ["--entrypoint", entrypoint]
        if plan_path is not None:
            command += ["--mount", f"type=bind,source={plan_path},target=/input/plan.json,readonly"]
        return subprocess.run(command + [IMAGE, *args], text=True,
                              capture_output=True, timeout=60)

    def test_default_prints_help(self):
        result = self.run_container()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--fail-on", result.stdout)

    def test_safe_plan_passes(self):
        result = self.run_container("examples/safe-plan.json", "--format", "json",
                                    "--fail-on", "medium")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], [])

    def test_risky_plan_fails_gate(self):
        result = self.run_container("examples/demo-plan.json", "--format", "json",
                                    "--fail-on", "high")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["summary"]["HIGH"], 3)

    def test_nonroot_identity(self):
        result = self.run_container("-c", "import os; print(os.getuid(), os.getgid())",
                                    entrypoint="python")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "10001 10001")

    def test_workload_and_identity_examples(self):
        for fixture, kind, status in [("kubernetes-safe.json", "kubernetes", 0),
                                      ("kubernetes-risky.json", "kubernetes", 1),
                                      ("gcp-identity-risk-plan.json", "terraform", 1)]:
            with self.subTest(fixture=fixture):
                result = self.run_container("examples/" + fixture, "--input-kind", kind,
                                            "--format", "json", "--fail-on", "medium")
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(bool(json.loads(result.stdout)["findings"]), bool(status))

    def test_external_plan_input(self):
        for content, expected_status in [(' {"resource_changes": []}', 0), ('{invalid', 2)]:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                plan = Path(directory) / "plan.json"
                plan.write_text(content, encoding="utf-8")
                # Only synthetic test data: permit the container's numeric UID to read it.
                plan.chmod(0o644)
                result = self.run_container("/input/plan.json", "--format", "json",
                                            "--fail-on", "medium", plan_path=plan)
                self.assertEqual(result.returncode, expected_status, result.stderr)
                if expected_status == 0:
                    self.assertEqual(json.loads(result.stdout)["findings"], [])
                else:
                    self.assertEqual(result.stdout, "")
                    self.assertIn("unable to scan plan", result.stderr)
                self.assertEqual(plan.read_text(encoding="utf-8"), content)

    def test_external_plan_mount_is_readonly(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            content = '{"resource_changes": []}'
            plan.write_text(content, encoding="utf-8")
            # A disposable, world-writable fixture proves the mount itself blocks writes.
            plan.chmod(0o666)
            probe = (
                "import errno, sys\n"
                "try:\n"
                "    open('/input/plan.json', 'w').close()\n"
                "except OSError as error:\n"
                "    sys.exit(0 if error.errno == errno.EROFS else 1)\n"
                "sys.exit(1)\n"
            )
            result = self.run_container("-c", probe, entrypoint="python", plan_path=plan)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(plan.read_text(encoding="utf-8"), content)
