import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import sarif_report

ROOT = Path(__file__).resolve().parents[1]
FINDINGS = [("HIGH", "resource.example", "Example risk.")]


class TestPortableSarifPaths(unittest.TestCase):
    def test_portable_paths_and_fingerprints_across_checkouts(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = []
            for name in ["checkout-one", "checkout-two"]:
                root = Path(directory) / name
                root.mkdir()
                reports.append(sarif_report([(str(root / "plan #1.json"), "terraform", FINDINGS)], source_root=root))
            self.assertEqual(reports[0], reports[1])
            output = json.dumps(reports[0])
            self.assertNotIn(directory, output)
            self.assertIn("plan%20%231.json", output)

    def test_rejects_outside_paths_even_without_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            for source in [root / ".." / "outside.json", Path(directory) / "repo-other" / "plan.json"]:
                with self.assertRaisesRegex(ValueError, "outside the source root"):
                    sarif_report([(str(source), "terraform", [])], source_root=root)
            (root / "link.json").symlink_to(Path(directory) / "outside.json")
            with self.assertRaisesRegex(ValueError, "outside the source root"):
                sarif_report([(str(root / "link.json"), "terraform", FINDINGS)], source_root=root)

    def test_root_must_be_directory(self):
        with self.assertRaisesRegex(ValueError, "existing directory"):
            sarif_report([], source_root=ROOT / "README.md")

    def test_single_and_batch_cli(self):
        for module, source in [("cli", "demo-plan.json"), ("batch", "batch-demo.json")]:
            command = [sys.executable, "-m", "cloudmesh_sentinel." + module,
                       str(ROOT / "examples" / source), "--format", "sarif", "--fail-on", "high"]
            result = subprocess.run([*command, "--source-root", str(ROOT)], cwd=ROOT,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertNotIn(str(ROOT), result.stdout)
            for finding in json.loads(result.stdout)["runs"][0]["results"]:
                self.assertTrue(finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("examples/"))
            result = subprocess.run([*command, "--source-root", str(ROOT / "tests")], cwd=ROOT,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("outside the source root", result.stderr)

    def test_option_requires_sarif(self):
        for module, source in [("cli", "demo-plan.json"), ("batch", "batch-demo.json")]:
            result = subprocess.run([sys.executable, "-m", "cloudmesh_sentinel." + module,
                "examples/" + source, "--source-root", "."], cwd=ROOT,
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("requires --format sarif", result.stderr)
