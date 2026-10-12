import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import parse_finite_float, scan_plan
from cloudmesh_sentinel.batch import load_inputs

ROOT = Path(__file__).resolve().parents[1]


class TestNumericOverflow(unittest.TestCase):
    def test_finite_numbers_remain_supported(self):
        for value in ["0.0", "-1.25", "1e308", "1e-999"]:
            self.assertEqual(parse_finite_float(value), float(value))

    def test_overflow_rejected(self):
        for value in ["1e999", "-1e999"]:
            with self.assertRaisesRegex(ValueError, "finite floating-point range"):
                parse_finite_float(value)

    def test_embedded_iam_policy_overflow(self):
        for kind in ["google_project_iam_policy", "google_storage_bucket_iam_policy"]:
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "finite floating-point range"):
                scan_plan({"resource_changes": [{"type": kind, "change": {
                    "after": {"policy_data": '{"bindings": [], "extra": 1e999}'}}}]})

    def test_batch_manifest_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "batch.json"
            path.write_text('{"inputs": [{"path": 1e999, "kind": "terraform"}]}')
            with self.assertRaisesRegex(ValueError, "finite floating-point range"):
                load_inputs(path)

    def test_cli_rejects_overflow_without_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "input.json"
            manifest = root / "batch.json"
            for kind, document in [("terraform", {"resource_changes": []}),
                    ("kubernetes", json.loads((ROOT / "examples/kubernetes-safe.json").read_text()))]:
                manifest.write_text(json.dumps({"inputs": [{"path": "input.json", "kind": kind}]}))
                for number in ["1e999", "-1e999"]:
                    path.write_text(json.dumps(document)[:-1] + ', "extra": ' + number + '}')
                    for command in [[str(ROOT / "cloudmesh_sentinel/cli.py"), str(path),
                                     "--input-kind", kind],
                                    ["-m", "cloudmesh_sentinel.batch", str(manifest)]]:
                        for output in ["text", "json", "markdown"]:
                            with self.subTest(kind=kind, number=number, command=command, output=output):
                                result = subprocess.run([sys.executable, *command, "--format", output],
                                    cwd=ROOT, capture_output=True, text=True, timeout=10)
                                self.assertEqual(result.returncode, 2)
                                self.assertEqual(result.stdout, "")
                                self.assertIn("finite floating-point range", result.stderr)
