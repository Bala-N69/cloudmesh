import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_plan

ROOT = Path(__file__).resolve().parents[1]


def plan(actions):
    return {"resource_changes": [{"address": "synthetic.resource",
        "type": "synthetic", "change": {"actions": actions, "after": None}}]}


class TestPlanActions(unittest.TestCase):
    def test_malformed_actions_are_rejected(self):
        for actions in ["delete", "create", "delete,create", None, False, 0,
                        {}, [None], [1], ["delete", False]]:
            with self.subTest(actions=actions), self.assertRaisesRegex(ValueError, "change.actions"):
                scan_plan(plan(actions))

    def test_supported_action_lists_preserve_findings(self):
        for actions, message in [(["delete"], "Resource will be deleted."),
                (["delete", "create"], "Resource will be replaced."),
                (["create", "delete"], "Resource will be replaced."),
                (["create"], None), (["update"], None), (["no-op"], None), ([], None)]:
            with self.subTest(actions=actions):
                expected = [("HIGH", "synthetic.resource", message)] if message else []
                self.assertEqual(scan_plan(plan(actions)), expected)

    def test_missing_actions_remain_compatible(self):
        document = plan([])
        del document["resource_changes"][0]["change"]["actions"]
        self.assertEqual(scan_plan(document), [])

    def test_single_and_batch_reject_without_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            document = plan(["delete"])
            document["resource_changes"] += plan("delete")["resource_changes"]
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
                        self.assertIn("change.actions must be a list of strings", result.stderr)
