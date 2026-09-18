"""Exercise shell guardrails with controlled output, without a cluster or kubectl.

The fixture combines base resources with the dev replica count. It is not a
Kustomize renderer: the existing Kubernetes CI job covers actual rendering.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate-kubernetes.sh"


class TestKubernetesValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        resources = sorted((ROOT / "kubernetes/base").glob("*.yaml"))
        cls.manifest = "\n---\n".join(
            path.read_text() for path in resources if path.name != "kustomization.yaml"
        ).replace("replicas: 2", "replicas: 1")

    def validate(self, manifest, render_status=0):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "manifest.yaml"
            fixture.write_text(manifest)
            scratch = Path(directory) / "validator-temp"
            scratch.mkdir()
            environment = dict(os.environ, CLOUDMESH_TEST_MANIFEST=str(fixture),
                               CLOUDMESH_TEST_RENDER_STATUS=str(render_status),
                               TMPDIR=str(scratch))
            # Exported function substitutes only the renderer; the real shell
            # script, normalization and guardrail checks run unchanged.
            result = subprocess.run(
                ["bash", "-c", 'kubectl() { test -f "$TMPDIR/"* || return 88; '
                 'cat "$CLOUDMESH_TEST_MANIFEST"; '
                 'if [ "$CLOUDMESH_TEST_RENDER_STATUS" != 0 ]; then echo "test renderer error" >&2; fi; '
                 'return "$CLOUDMESH_TEST_RENDER_STATUS"; }; '
                 'export -f kubectl; bash "$1"', "validator-test", str(SCRIPT)],
                env=environment, cwd=directory, text=True, capture_output=True,
                timeout=15,
            )
            # Assert before TemporaryDirectory removes the enclosing folder,
            # otherwise the test harness would hide a leaked manifest.
            self.assertEqual(list(scratch.iterdir()), [], "Validator leaked temporary files")
            self.assertTrue(fixture.is_file(), "Validator removed an unrelated file")
            return result

    def test_expected_manifest_passes(self):
        result = self.validate(self.manifest)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_relative_invocation_ignores_cdpath(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "manifest.yaml"
            fixture.write_text(self.manifest)
            result = subprocess.run(
                ["bash", "-c",
                 'kubectl() { [ "$#" -eq 2 ] && [ "$1" = kustomize ] && '
                 '[ "$2" = "$CLOUDMESH_TEST_OVERLAY" ] || return 89; '
                 'cat "$CLOUDMESH_TEST_MANIFEST"; }; export -f kubectl; '
                 'bash scripts/validate-kubernetes.sh'],
                cwd=ROOT, env={**os.environ, "CDPATH": str(ROOT),
                    "TMPDIR": directory, "CLOUDMESH_TEST_MANIFEST": str(fixture),
                    "CLOUDMESH_TEST_OVERLAY": str(ROOT / "kubernetes/overlays/dev")},
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "Kubernetes manifest security checks passed.\n")
            self.assertEqual(list(Path(directory).iterdir()), [fixture])

    def test_help_without_external_tools(self):
        for flag in ["--help", "-h"]:
            with self.subTest(flag=flag):
                result = subprocess.run(
                    ["/bin/bash", str(SCRIPT), flag],
                    env={**os.environ, "PATH": "/nonexistent"},
                    capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode, 0)
                self.assertIn("Usage:", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_unexpected_arguments_fail_before_dependencies(self):
        for args in [["--hel"], ["prod"], ["--help", "prod"]]:
            with self.subTest(args=args):
                result = subprocess.run(
                    ["/bin/bash", str(SCRIPT), *args],
                    env={**os.environ, "PATH": "/nonexistent"},
                    capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("unexpected arguments", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_temporary_file_failure_stops_before_rendering(self):
        result = subprocess.run(
            ["bash", "-c",
             'mktemp() { echo "test temporary-file error" >&2; return 7; }; '
             'kubectl() { echo "renderer should not run" >&2; return 99; }; '
             'export -f mktemp kubectl; bash "$1"', "validator-test", str(SCRIPT)],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not create a temporary manifest", result.stderr)
        self.assertIn("test temporary-file error", result.stderr)
        self.assertNotIn("renderer should not run", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_renderer_failure_cannot_pass_with_valid_output(self):
        result = self.validate(self.manifest, render_status=9)
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not render", result.stderr)
        self.assertIn("test renderer error", result.stderr)
        self.assertNotIn("checks passed", result.stdout)

    def test_empty_renderer_output_is_reported(self):
        for output in ["", "\n \t\n"]:
            with self.subTest(output=output):
                result = self.validate(output)
                self.assertEqual(result.returncode, 1)
                self.assertIn("rendered no content", result.stderr)
                self.assertNotIn("missing kind:", result.stderr)

    def test_whitespace_is_not_significant(self):
        padded = "\n".join("  " + line + "  " for line in self.manifest.splitlines())
        result = self.validate(padded)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_health_endpoint_settings_are_required(self):
        for expected, changed in [
            ("path: /healthz", "path: /"),
            ("containerPort: 8080", "containerPort: 8081"),
            ("name: http", "name: web"),
            ("port: http", "port: missing"),
            ("path: /healthz", "path: /healthz-other"),
        ]:
            with self.subTest(changed=changed):
                result = self.validate(self.manifest.replace(expected, changed))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("missing " + expected, result.stderr)

    def test_image_as_first_container_field(self):
        # Kustomize sorts container keys, putting image at the list item's
        # start ("- image:"), unlike our source manifest's "- name:".
        rendered = self.manifest.replace(
            '- name: web\n          image: nginxinc/nginx-unprivileged:1.27-alpine',
            '- image: nginxinc/nginx-unprivileged:1.27-alpine\n          name: web')
        self.assertNotEqual(rendered, self.manifest)
        result = self.validate(rendered)
        self.assertEqual(result.returncode, 0, result.stderr)
        invalid = rendered.replace('1.27-alpine', '1.27-alpine-unapproved')
        result = self.validate(invalid)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing image:', result.stderr)

    def test_partial_values_are_rejected(self):
        for expected, changed in [
            ("replicas: 1", "replicas: 10"),
            ("kind: Service", "kind: ServiceAccount"),
            ("serviceAccountName: cloudmesh-demo", "serviceAccountName: cloudmesh-demo-admin"),
            ("image: nginxinc/nginx-unprivileged:1.27-alpine",
             "image: nginxinc/nginx-unprivileged:1.27-alpine-unapproved"),
            ("terminationGracePeriodSeconds: 30", "terminationGracePeriodSeconds: 300"),
        ]:
            with self.subTest(changed=changed):
                result = self.validate(self.manifest.replace(expected, changed))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("missing " + expected, result.stderr)

    def test_commented_setting_does_not_pass(self):
        result = self.validate(self.manifest.replace("replicas: 1", "# replicas: 1"))
        self.assertNotEqual(result.returncode, 0)

    def test_commented_header_does_not_pass(self):
        result = self.validate(self.manifest.replace(
            'add_header X-Frame-Options "DENY" always;',
            '# add_header X-Frame-Options "DENY" always;'))
        self.assertNotEqual(result.returncode, 0)

    def test_egress_still_rejected(self):
        result = self.validate(self.manifest + "\negress: []\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected egress:", result.stderr)


if __name__ == "__main__":
    unittest.main()
