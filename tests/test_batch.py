import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.batch import load_inputs

ROOT = Path(__file__).resolve().parents[1]


class TestBatch(unittest.TestCase):
    def run_batch(self, manifest, *args, cwd=None):
        environment = dict(os.environ, PYTHONPATH=str(ROOT))
        return subprocess.run([sys.executable, "-m", "cloudmesh_sentinel.batch", str(manifest), *args],
                              cwd=cwd or ROOT, env=environment, capture_output=True, text=True, timeout=10)

    def test_mixed_report_sources_counts_and_gate(self):
        result = self.run_batch(ROOT / "examples/batch-demo.json", "--format", "json", "--fail-on", "high")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["summary"], {"files": 3, "total": 14, "HIGH": 10, "MEDIUM": 4})
        self.assertEqual(report["gate"], "fail")
        self.assertEqual([f["source"] for f in report["files"]],
                         ["gcp-identity-risk-plan.json", "kubernetes-risky.json", "kubernetes-safe.json"])
        self.assertEqual(report["files"][2]["findings"], [])

    def test_safe_batch_all_formats_from_another_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            for output in ["text", "json", "markdown"]:
                with self.subTest(output=output):
                    result = self.run_batch(ROOT / "examples/batch-safe.json", "--format", output,
                                            "--fail-on", "medium", cwd=directory)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(result.stdout)

    def test_default_is_informational(self):
        result = self.run_batch(ROOT / "examples/batch-demo.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("3 file(s), 14 finding(s)", result.stdout)

    def test_invalid_manifest_shapes(self):
        invalid = [{}, {"inputs": []}, {"inputs": None}, {"inputs": [None]},
                   {"inputs": [{"path": "x", "kind": "yaml"}]},
                   {"inputs": [{"path": "", "kind": "terraform"}]},
                   {"inputs": [{"path": "x", "kind": "terraform", "typo": True}]}]
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "batch.json"
            for document in invalid:
                with self.subTest(document=document):
                    manifest.write_text(json.dumps(document))
                    result = self.run_batch(manifest, "--format", "json")
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")

    def test_invalid_second_file_cannot_produce_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            manifest = folder / "batch.json"
            manifest.write_text(json.dumps({"inputs": [
                {"path": str(ROOT / "examples/demo-plan.json"), "kind": "terraform"},
                {"path": "invalid.json", "kind": "terraform"}]}))
            for content in [None, "{", '{"resource_changes":[],"resource_changes":[]}', '{"x":NaN}']:
                with self.subTest(content=content):
                    if content is not None:
                        (folder / "invalid.json").write_text(content)
                    result = self.run_batch(manifest, "--format", "markdown", "--fail-on", "high")
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("invalid.json", result.stderr)

    def test_duplicate_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [
                {"path": "a.json", "kind": "terraform"},
                {"path": "./a.json", "kind": "kubernetes"}]}))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_inputs(manifest)

    def test_markdown_source_is_escaped(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            name = "plan|@team.json"
            (folder / name).write_text('{"resource_changes": []}')
            manifest = folder / "batch.json"
            manifest.write_text(json.dumps({"inputs": [{"path": name, "kind": "terraform"}]}))
            result = self.run_batch(manifest, "--format", "markdown")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(name, result.stdout)
            self.assertIn("&#124;", result.stdout)
            self.assertNotIn("@team", result.stdout)
