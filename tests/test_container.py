"""Opt-in runtime checks for a locally built image; never pull or build images."""
import json
import os
import subprocess
import unittest


IMAGE = os.environ.get("CLOUDMESH_DOCKER_TEST_IMAGE")


@unittest.skipUnless(IMAGE, "Set CLOUDMESH_DOCKER_TEST_IMAGE to test a built image")
class TestContainer(unittest.TestCase):
    def run_container(self, *args, entrypoint=None):
        command = ["docker", "run", "--rm", "--pull=never", "--network=none",
                   "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"]
        if entrypoint:
            command += ["--entrypoint", entrypoint]
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
