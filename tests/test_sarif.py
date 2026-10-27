import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import sarif_report

ROOT = Path(__file__).resolve().parents[1]


class TestSarif(unittest.TestCase):
    def run_scan(self, arguments):
        return subprocess.run([sys.executable, *arguments], cwd=ROOT,
                              capture_output=True, text=True, timeout=10)

    def test_rules_severity_locations_and_identity(self):
        findings = [("HIGH", "bucket.one", "Public access."),
                    ("MEDIUM", "bucket.two", "Missing hardening."),
                    ("HIGH", "bucket.three", "Public access.")]
        report = sarif_report([("plans/test #1.json", "terraform", findings)], "high")
        self.assertEqual(report["version"], "2.1.0")
        run = report["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        self.assertEqual([r["level"] for r in run["results"]], ["error", "warning", "error"])
        self.assertEqual(run["properties"]["gate"], "fail")
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            self.assertIn(result["ruleId"], ids)
            location = result["locations"][0]["physicalLocation"]
            self.assertEqual(location["artifactLocation"]["uri"], "plans/test%20%231.json")
            self.assertNotIn("region", location)
        self.assertEqual(report, sarif_report([("plans/test #1.json", "terraform", findings)], "high"))
        fingerprints = [r["partialFingerprints"]["cloudmeshFinding/v1"] for r in run["results"]]
        self.assertEqual(len(set(fingerprints)), 3)

    def test_fingerprints_independent_of_order_and_distinguish_files(self):
        finding = ("HIGH", "pod/app", "Unsafe setting.")
        inputs = [("a.json", "kubernetes", [finding]), ("b.json", "kubernetes", [finding])]
        results = sarif_report(inputs)["runs"][0]["results"]
        reverse = sarif_report(list(reversed(inputs)))["runs"][0]["results"]
        self.assertEqual(results, list(reversed(reverse)))
        self.assertNotEqual(results[0]["partialFingerprints"], results[1]["partialFingerprints"])

    def test_empty_scan_and_absolute_uri(self):
        run = sarif_report([("safe.json", "terraform", [])], "medium")["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["properties"], {"filesScanned": 1, "failOn": "medium", "gate": "pass"})
        source = str(ROOT / "examples/demo-plan.json")
        result = sarif_report([(source, "terraform", [("HIGH", "resource", "Risk.")])])["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], Path(source).as_uri())

    def test_medium_only_threshold_and_duplicate_occurrences(self):
        finding = ("MEDIUM", "bucket", "Review hardening.")
        inputs = [("a.json", "terraform", [finding, finding])]
        for threshold, gate in [("none", "informational"), ("high", "pass"), ("medium", "fail")]:
            run = sarif_report(inputs, threshold)["runs"][0]
            self.assertEqual(run["properties"]["gate"], gate)
            self.assertEqual(len(run["results"]), 2)
            self.assertEqual(run["results"][0], run["results"][1])

    def test_single_scan_entry_points_and_gates(self):
        for entry in [["cloudmesh_sentinel/cli.py"], ["-m", "cloudmesh_sentinel.cli"]]:
            for fixture, kind, threshold, expected in [
                ("demo-plan.json", "terraform", "high", 1),
                ("safe-plan.json", "terraform", "medium", 0),
                ("kubernetes-risky.json", "kubernetes", "none", 0),
                ("kubernetes-safe.json", "kubernetes", "medium", 0)]:
                with self.subTest(entry=entry, fixture=fixture):
                    result = self.run_scan([*entry, "examples/" + fixture,
                        "--input-kind", kind, "--format", "sarif", "--fail-on", threshold])
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(json.loads(result.stdout)["version"], "2.1.0")

    def test_batch_counts_and_manifest_relative_paths(self):
        result = self.run_scan(["-m", "cloudmesh_sentinel.batch", "examples/batch-demo.json",
                                "--format", "sarif", "--fail-on", "high"])
        self.assertEqual(result.returncode, 1, result.stderr)
        run = json.loads(result.stdout)["runs"][0]
        normal = self.run_scan(["-m", "cloudmesh_sentinel.batch", "examples/batch-demo.json", "--format", "json"])
        self.assertEqual(len(run["results"]), json.loads(normal.stdout)["summary"]["total"])
        self.assertEqual(run["properties"]["filesScanned"], 3)
        for finding in run["results"]:
            self.assertTrue(finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("examples/"))

    def test_invalid_input_never_produces_partial_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.json"
            bad.write_text('{"resource_changes": false}')
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(json.dumps({"inputs": [
                {"path": str(ROOT / "examples/demo-plan.json"), "kind": "terraform"},
                {"path": "bad.json", "kind": "terraform"}]}))
            for module, source in [("cli", bad), ("batch", manifest)]:
                result = self.run_scan(["-m", "cloudmesh_sentinel." + module, str(source), "--format", "sarif"])
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("unable to scan", result.stderr)
