import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]
FIELD = "uniform_bucket_level_access"


def plan(after, actions=None):
    return {"resource_changes": [{"type": "google_storage_bucket", "address": "bucket.example",
        "change": {"actions": actions or ["create"], "after": after}}]}


class TestStorageFlags(unittest.TestCase):
    def test_invalid_boolean_values(self):
        for value in ["false", "true", 0, 1, [], {}]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, FIELD + " must be a boolean"):
                scan_plan(plan({FIELD: value}))

    def test_valid_and_unknown_values(self):
        for after in [{}, {FIELD: None}, {FIELD: True}]:
            self.assertEqual(scan_plan(plan(after)), [])
        self.assertEqual(scan_plan(plan({FIELD: False})), [("MEDIUM", "bucket.example",
            "Cloud Storage bucket does not use uniform bucket-level access.")])

    def test_deletion_and_replacement_preserved(self):
        self.assertEqual(scan_plan(plan(None, ["delete"])),
                         [("HIGH", "bucket.example", "Resource will be deleted.")])
        findings = scan_plan(plan({FIELD: False}, ["delete", "create"]))
        self.assertEqual([finding[0] for finding in findings], ["HIGH", "MEDIUM"])

    def test_cli_and_batch_reject_without_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps(plan({FIELD: "false"}, ["delete", "create"])))
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [{"path": "bad.json", "kind": "terraform"}]}))
            for command in [["-m", "cloudmesh_sentinel.cli", str(path)],
                            ["-m", "cloudmesh_sentinel.batch", str(manifest)]]:
                for output in ["text", "json", "markdown"]:
                    with self.subTest(command=command, output=output):
                        result = subprocess.run([sys.executable, *command, "--format", output],
                            cwd=ROOT, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn(FIELD + " must be a boolean", result.stderr)
