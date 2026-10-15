import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.compare import compare_reports, load_report, render

ROOT = Path(__file__).resolve().parents[1]
HIGH = {"severity": "HIGH", "address": "resource", "message": "risk"}
MEDIUM = {"severity": "MEDIUM", "address": "resource", "message": "review"}


def report(findings):
    return {"schema_version": 1, "findings": findings, "summary": {
        "total": len(findings), "HIGH": sum(f["severity"] == "HIGH" for f in findings),
        "MEDIUM": sum(f["severity"] == "MEDIUM" for f in findings)}}


def batch(findings, source="workload.json", kind="kubernetes"):
    result = report(findings)
    result["report_type"] = "batch"
    result["files"] = [{"source": source, "kind": kind, "findings": result.pop("findings")}]
    result["summary"]["files"] = 1
    return result


class TestCompare(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.before = Path(self.directory.name) / "before.json"
        self.after = Path(self.directory.name) / "after.json"

    def save(self, before, after):
        self.before.write_text(json.dumps(before), encoding="utf-8")
        self.after.write_text(json.dumps(after), encoding="utf-8")

    def test_new_resolved_unchanged_and_duplicates(self):
        self.save(report([HIGH, HIGH]), report([HIGH, MEDIUM]))
        result = compare_reports(self.before, self.after)
        self.assertEqual(result["summary"], {"new": 1, "resolved": 1, "unchanged": 1, "current_total": 2})
        self.assertEqual(result["new"][0]["severity"], "MEDIUM")
        self.assertEqual(result["resolved"][0]["severity"], "HIGH")

    def test_large_batch_summary_matches_independent_counts(self):
        before_files, after_files = [], []
        for index in range(250):
            source = f"workload-{index:03d}.json"
            old = [HIGH, HIGH, MEDIUM] if index % 2 else []
            current = [HIGH, MEDIUM, MEDIUM] if index % 3 else []
            before_files.append({"source": source, "kind": "kubernetes", "findings": old})
            after_files.append({"source": source, "kind": "kubernetes", "findings": current})
        def document(files):
            result = report([finding for entry in files for finding in entry["findings"]])
            result.pop("findings")
            result.update(report_type="batch", files=files)
            result["summary"]["files"] = len(files)
            return result
        self.save(document(before_files), document(list(reversed(after_files))))
        result = compare_reports(self.before, self.after, "high")
        self.assertEqual(result["gate"], "fail")
        self.assertEqual(len(result["files"]), 250)
        for entry in result["files"]:
            for group in ("new", "resolved", "unchanged"):
                self.assertEqual(entry["summary"][group],
                    sum(item["source"] == entry["source"] for item in result[group]))
            for level in ("HIGH", "MEDIUM"):
                self.assertEqual(entry["current_severity"][level], sum(
                    item["source"] == entry["source"] and item["severity"] == level
                    for group in ("new", "unchanged") for item in result[group]))
        for key, count in result["summary"].items():
            self.assertEqual(sum(entry["summary"][key] for entry in result["files"]), count)
            self.assertEqual(sum(entry[key] for entry in result["by_severity"].values()), count)

    def test_severity_summary_counts_duplicate_occurrences(self):
        self.save(report([HIGH, HIGH]), report([HIGH, MEDIUM]))
        result = compare_reports(self.before, self.after, "high")
        self.assertEqual(result["by_severity"], {
            "HIGH": {"new": 0, "resolved": 1, "unchanged": 1, "current_total": 1},
            "MEDIUM": {"new": 1, "resolved": 0, "unchanged": 0, "current_total": 1}})
        self.assertEqual(result["files"][0]["summary"], result["summary"])
        self.assertEqual(result["gate"], "fail")

    def test_file_summary_includes_clean_files_and_is_sorted(self):
        before = batch([HIGH], "z.json")
        before["files"].append({"source": "a.json", "kind": "terraform", "findings": []})
        before["summary"]["files"] = 2
        after = copy.deepcopy(before)
        after["files"][0]["findings"] = [MEDIUM]
        after["summary"].update(HIGH=0, MEDIUM=1)
        self.save(before, after)
        result = compare_reports(self.before, self.after)
        self.assertEqual([entry["source"] for entry in result["files"]], ["a.json", "z.json"])
        self.assertEqual(result["files"][0]["summary"],
                         {"new": 0, "resolved": 0, "unchanged": 0, "current_total": 0})
        self.assertEqual(result["files"][1]["current_severity"], {"HIGH": 0, "MEDIUM": 1})
        for key, total in result["summary"].items():
            self.assertEqual(sum(entry["summary"][key] for entry in result["files"]), total)

    def test_summary_sources_are_escaped(self):
        self.save(batch([], "<img>|\n\x1b[31m"), batch([HIGH], "<img>|\n\x1b[31m"))
        result = compare_reports(self.before, self.after)
        self.assertIn("Severity summary", render(result, "markdown"))
        self.assertIn("File summary", render(result, "markdown"))
        self.assertNotIn("<img>", render(result, "markdown"))
        self.assertNotIn("\x1b", render(result, "text"))

    def test_empty_summary_and_resolved_only_gate(self):
        for before in [[], [HIGH]]:
            self.save(report(before), report([]))
            result = compare_reports(self.before, self.after, "medium")
            self.assertEqual(result["gate"], "pass")
            self.assertEqual(result["files"][0]["current_severity"], {"HIGH": 0, "MEDIUM": 0})

    def test_gate_counts_unchanged_risks(self):
        for findings, threshold, gate in [([HIGH], "high", "fail"), ([MEDIUM], "high", "pass"),
                ([MEDIUM], "medium", "fail"), ([HIGH], "none", "informational"), ([], "medium", "pass")]:
            self.save(report(findings), report(findings))
            with self.subTest(findings=findings, threshold=threshold):
                self.assertEqual(compare_reports(self.before, self.after, threshold)["gate"], gate)

    def test_severity_change_is_new_and_resolved(self):
        self.save(report([HIGH]), report([{**HIGH, "severity": "MEDIUM"}]))
        result = compare_reports(self.before, self.after)
        self.assertEqual((len(result["new"]), len(result["resolved"])), (1, 1))

    def test_batch_scopes_and_order(self):
        before = batch([HIGH])
        before["files"].append({"source": "plan.json", "kind": "terraform", "findings": []})
        before["summary"]["files"] = 2
        after = copy.deepcopy(before)
        after["files"].reverse()
        self.save(before, after)
        self.assertEqual(compare_reports(self.before, self.after)["summary"]["unchanged"], 1)
        for after in [batch([HIGH], "renamed.json"), batch([HIGH], kind="terraform"), report([HIGH])]:
            self.save(batch([HIGH]), after)
            with self.assertRaisesRegex(ValueError, "matching"):
                compare_reports(self.before, self.after)

    def test_invalid_reports_fail_closed(self):
        invalid = [[], {}, {**report([]), "schema_version": True},
                   {**report([]), "schema_version": 2}, {**report([]), "report_type": "comparison"},
                   {**report([]), "findings": None}, report([{"severity": "LOW", "address": "x", "message": "x"}]),
                   {**report([]), "summary": {"total": False, "HIGH": 0, "MEDIUM": 0}},
                   {**report([HIGH]), "summary": report([])["summary"]},
                   {**report([]), "findings": [None]}]
        duplicate = batch([])
        duplicate["files"] *= 2
        invalid.append(duplicate)
        for value in invalid:
            with self.subTest(value=value):
                self.save(value, report([]))
                with self.assertRaises((ValueError, TypeError)):
                    load_report(self.before)

    def test_markdown_escapes_and_text_quotes_untrusted_content(self):
        self.save(report([]), report([{**HIGH, "address": "<script>|\n\x1b[31m"}]))
        result = compare_reports(self.before, self.after)
        self.assertNotIn("<script>", render(result, "markdown"))
        self.assertNotIn("\x1b", render(result, "text"))

    def test_cli_formats_exit_codes_and_no_partial_report(self):
        for output in ["text", "json", "markdown"]:
            for findings, expected in [([], 0), ([HIGH], 1)]:
                self.save(report(findings), report(findings))
                result = self.run_cli(output)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertTrue(result.stdout)
            for invalid in ['{', '{"schema_version": 1, "schema_version": 1}',
                            '{"extra": 1e999}', '{"extra": NaN}']:
                self.after.write_text(invalid)
                result = self.run_cli(output)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)

    def run_cli(self, output):
        return subprocess.run([sys.executable, "-m", "cloudmesh_sentinel.compare",
            str(self.before), str(self.after), "--format", output, "--fail-on", "high"],
            cwd=ROOT, capture_output=True, text=True, timeout=10)

    def test_real_scanner_reports_single_and_batch(self):
        for module, args in [("cli", ["examples/demo-plan.json"]),
                             ("cli", ["examples/kubernetes-safe.json", "--input-kind", "kubernetes"]),
                             ("batch", ["examples/batch-demo.json"])]:
            result = subprocess.run([sys.executable, "-m", "cloudmesh_sentinel." + module,
                *args, "--format", "json"], cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(result.stdout)
            self.save(document, document)
            comparison = compare_reports(self.before, self.after)
            self.assertEqual(comparison["summary"]["new"], 0)
            self.assertEqual(comparison["summary"]["unchanged"], document["summary"]["total"])
