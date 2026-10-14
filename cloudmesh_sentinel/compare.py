"""Compare two saved Sentinel JSON reports without suppressing current findings."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from .cli import (SEVERITY_RANK, markdown_cell, parse_finite_float,
                  reject_duplicate_keys, reject_nonfinite_constant)


def load_report(path):
    with path.open(encoding="utf-8") as stream:
        document = json.load(stream, object_pairs_hook=reject_duplicate_keys,
                             parse_constant=reject_nonfinite_constant,
                             parse_float=parse_finite_float)
    if not isinstance(document, dict) or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("Expected a Sentinel schema version 1 report")
    report_type = document.get("report_type", "single")
    if report_type == "single":
        if "files" in document:
            raise ValueError("Single report cannot contain files")
        files = [{"source": "", "kind": "", "findings": document.get("findings")}]
    elif report_type == "batch":
        files = document.get("files")
        if not isinstance(files, list) or not files or "findings" in document:
            raise ValueError("Batch report requires a nonempty files list")
    else:
        raise ValueError("Unsupported report type")
    scope, findings = {}, Counter()
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("Expected report file object")
        source, kind = entry.get("source"), entry.get("kind")
        if report_type == "batch" and (not isinstance(source, str) or not source.strip()
                                       or kind not in ("terraform", "kubernetes")):
            raise ValueError("Invalid batch source or kind")
        if source in scope:
            raise ValueError("Duplicate batch source")
        scope[source] = kind
        entries = entry.get("findings")
        if not isinstance(entries, list):
            raise ValueError("Expected findings list")
        for finding in entries:
            if not isinstance(finding, dict):
                raise ValueError("Expected finding object")
            values = [finding.get(field) for field in ("severity", "address", "message")]
            if not all(isinstance(value, str) and value for value in values):
                raise ValueError("Finding fields must be nonempty strings")
            if values[0] not in SEVERITY_RANK:
                raise ValueError("Unsupported finding severity")
            findings[(source, kind, *values)] += 1
    expected = {"total": sum(findings.values()), **{
        level: sum(count for key, count in findings.items() if key[2] == level)
        for level in SEVERITY_RANK}}
    if report_type == "batch":
        expected["files"] = len(files)
    summary = document.get("summary")
    if not isinstance(summary, dict) or set(summary) != set(expected) or any(
            type(summary[key]) is not int or summary[key] != value
            for key, value in expected.items()):
        raise ValueError("Report summary does not match findings")
    return report_type, scope, findings


def expand(findings):
    return [{"source": source, "kind": kind, "severity": severity,
             "address": address, "message": message}
            for (source, kind, severity, address, message), count in sorted(
                findings.items(), key=lambda item: (-SEVERITY_RANK[item[0][2]], item[0]))
            for _ in range(count)]


def compare_reports(before, after, threshold="none"):
    if threshold not in ("none", "medium", "high"):
        raise ValueError("Unsupported severity threshold")
    before_type, before_scope, old = load_report(before)
    after_type, after_scope, current = load_report(after)
    if before_type != after_type or before_scope != after_scope:
        raise ValueError("Reports must have matching types and batch source/kind sets")
    groups = {"new": expand(current - old), "resolved": expand(old - current),
              "unchanged": expand(old & current)}
    blocked = threshold != "none" and any(
        SEVERITY_RANK[key[2]] >= SEVERITY_RANK[threshold.upper()] for key in current)
    by_severity = {level: {group: sum(item["severity"] == level for item in entries)
                          for group, entries in groups.items()}
                   for level in ("HIGH", "MEDIUM")}
    for counts in by_severity.values():
        counts["current_total"] = counts["new"] + counts["unchanged"]
    files = []
    for source, kind in sorted(after_scope.items()):
        file_groups = {group: [item for item in entries if item["source"] == source]
                       for group, entries in groups.items()}
        counts = {group: len(entries) for group, entries in file_groups.items()}
        counts["current_total"] = counts["new"] + counts["unchanged"]
        files.append({"source": source, "kind": kind, "summary": counts,
                      "current_severity": {level: sum(item["severity"] == level
                          for group in ("new", "unchanged") for item in file_groups[group])
                          for level in ("HIGH", "MEDIUM")}})
    return {"schema_version": 1, "report_type": "comparison", "fail_on": threshold,
            "by_severity": by_severity, "files": files,
            "gate": "informational" if threshold == "none" else ("fail" if blocked else "pass"),
            "summary": {**{group: len(items) for group, items in groups.items()},
                        "current_total": sum(current.values())}, **groups}


def render(result, output):
    if output == "json":
        return json.dumps(result, indent=2)
    lines = ["# CloudMesh Sentinel comparison" if output == "markdown" else "CloudMesh Sentinel comparison",
             "", f"Gate: {result['gate']} (all current findings; threshold: {result['fail_on']})", "",
             ", ".join(f"{key}: {value}" for key, value in result["summary"].items())]
    lines += ["", "## Severity summary" if output == "markdown" else "Severity summary"]
    if output == "markdown":
        lines += ["", "| Severity | New | Resolved | Unchanged | Current |",
                  "| --- | --- | --- | --- | --- |"]
    for level, counts in result["by_severity"].items():
        values = [str(counts[key]) for key in ("new", "resolved", "unchanged", "current_total")]
        lines.append("| " + " | ".join([level, *values]) + " |" if output == "markdown"
                     else f"{level}: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
    lines += ["", "## File summary" if output == "markdown" else "File summary"]
    if output == "markdown":
        lines += ["", "| Source | Kind | New | Resolved | Unchanged | Current HIGH | Current MEDIUM |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
    for entry in result["files"]:
        source = entry["source"] or "(single report)"
        values = [source, entry["kind"], *[str(entry["summary"][key])
                  for key in ("new", "resolved", "unchanged")],
                  str(entry["current_severity"]["HIGH"]), str(entry["current_severity"]["MEDIUM"])]
        if output == "markdown":
            lines.append("| " + " | ".join(markdown_cell(value) for value in values) + " |")
        else:
            lines.append(f"{source!r} ({entry['kind']!r}): {entry['summary']}; current severity: {entry['current_severity']}")
    for group in ("new", "resolved", "unchanged"):
        lines += ["", f"## {group.title()}" if output == "markdown" else group.title()]
        if output == "markdown":
            lines += ["", "| Source | Kind | Severity | Resource | Finding |", "| --- | --- | --- | --- | --- |"]
        for finding in result[group]:
            values = [finding[key] for key in ("source", "kind", "severity", "address", "message")]
            if output == "markdown":
                lines.append("| " + " | ".join(markdown_cell(value) for value in values) + " |")
            else:
                lines.append(" | ".join(repr(value) for value in values))
    lines += ["", "Resolved means absent from the current report, not proof of remediation."]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Compare saved Sentinel JSON reports.")
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument("--fail-on", choices=("none", "medium", "high"), default="none")
    args = parser.parse_args()
    try:
        result = compare_reports(args.before, args.after, args.fail_on)
    except (OSError, ValueError, TypeError) as error:
        print(f"CloudMesh Sentinel: unable to compare reports: {error}", file=sys.stderr)
        return 2
    print(render(result, args.format))
    return int(result["gate"] == "fail")


if __name__ == "__main__":
    sys.exit(main())
