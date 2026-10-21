import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]
KINDS = ["google_project_iam_member", "google_project_iam_binding",
         "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"]


def plan(kind, after, actions=None):
    return {"resource_changes": [{"type": kind, "address": "synthetic.access",
        "change": {"actions": actions or ["create"], "after": after}}]}


class TestIamMembers(unittest.TestCase):
    def test_invalid_members_in_all_supported_resources(self):
        for kind in KINDS:
            for field, values in [("member", [False, 1, [], {}]),
                                  ("members", ["allUsers", False, 1, {}, [None], [1]])]:
                for value in values:
                    with self.subTest(kind=kind, field=field, value=value):
                        with self.assertRaisesRegex(ValueError, "IAM member"):
                            scan_plan(plan(kind, {field: value}))

    def test_public_members_and_duplicates_still_flag(self):
        for kind in KINDS:
            for principal in ["allUsers", "allAuthenticatedUsers"]:
                for after in [{"member": principal}, {"members": [principal, principal]},
                              {"member": principal, "members": [principal]}]:
                    with self.subTest(kind=kind, after=after):
                        result = scan_plan(plan(kind, after))
                        self.assertEqual(len(result), 1)
                        self.assertEqual(result[0][0], "HIGH")

    def test_absent_null_private_and_deletion(self):
        for kind in KINDS:
            for after in [{}, {"member": None, "members": None}, {"members": []},
                          {"member": "serviceAccount:synthetic", "role": "roles/viewer"}]:
                self.assertEqual(scan_plan(plan(kind, after)), [])
            self.assertEqual(scan_plan(plan(kind, None, ["delete"])),
                [("HIGH", "synthetic.access", "Resource will be deleted.")])

    def test_privileged_service_account_still_flagged(self):
        for kind in KINDS[:2]:
            findings = scan_plan(plan(kind, {"members": ["serviceAccount:synthetic"],
                                           "role": "roles/editor"}))
            self.assertEqual(len(findings), 1)
            self.assertIn("privileged", findings[0][2])

    def test_cli_and_batch_fail_without_partial_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps(plan(KINDS[1], {"members": "allUsers"},
                                           ["delete", "create"])), encoding="utf-8")
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [
                {"path": "bad.json", "kind": "terraform"}]}), encoding="utf-8")
            for command in [["-m", "cloudmesh_sentinel.cli", str(path)],
                            ["-m", "cloudmesh_sentinel.batch", str(manifest)]]:
                for output in ["text", "json", "markdown"]:
                    result = subprocess.run([sys.executable, *command, "--format", output],
                        cwd=ROOT, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("IAM members must be a list of strings", result.stderr)
