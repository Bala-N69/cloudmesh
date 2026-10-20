import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]


def plan(after, actions=None, kind="google_compute_instance"):
    return {"resource_changes": [{"address": "synthetic.resource", "type": kind,
        "change": {"actions": actions or ["create"], "after": after}}]}


class TestPlanState(unittest.TestCase):
    def test_invalid_planned_state_is_rejected(self):
        for kind in ["google_compute_instance", "google_storage_bucket", "unknown_resource"]:
            for after in [False, True, 0, 1, "", "state", [], [{}]]:
                with self.subTest(kind=kind, after=after):
                    with self.assertRaisesRegex(ValueError, "change.after must be an object or null"):
                        scan_plan(plan(after, kind=kind))

    def test_missing_null_and_empty_remain_compatible(self):
        for after in [None, {}]:
            self.assertEqual(scan_plan(plan(after)), [])
        document = plan(None)
        del document["resource_changes"][0]["change"]["after"]
        self.assertEqual(scan_plan(document), [])

    def test_deleted_and_public_instances_keep_findings(self):
        self.assertEqual(scan_plan(plan(None, ["delete"])),
                         [("HIGH", "synthetic.resource", "Resource will be deleted.")])
        findings = scan_plan(plan({"network_interface": [{"access_config": [{}]}]}))
        self.assertEqual(findings, [("HIGH", "synthetic.resource",
                                    "Compute instance has a public IP address.")])

    def test_single_and_batch_fail_without_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            document = plan(None, ["delete"])
            document["resource_changes"] += plan(False)["resource_changes"]
            path.write_text(json.dumps(document), encoding="utf-8")
            manifest = Path(directory) / "batch.json"
            manifest.write_text(json.dumps({"inputs": [
                {"path": str(ROOT / "examples/safe-plan.json"), "kind": "terraform"},
                {"path": "bad.json", "kind": "terraform"}]}), encoding="utf-8")
            for command in [["-m", "cloudmesh_sentinel.cli", str(path)],
                            ["-m", "cloudmesh_sentinel.batch", str(manifest)]]:
                for output in ["text", "json", "markdown"]:
                    with self.subTest(command=command, output=output):
                        result = subprocess.run([sys.executable, *command, "--format", output],
                            cwd=ROOT, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("change.after must be an object or null", result.stderr)
