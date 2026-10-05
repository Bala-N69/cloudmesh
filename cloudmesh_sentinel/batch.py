"""Scan an explicit manifest of Terraform and Kubernetes JSON files offline."""
import argparse
import json
from pathlib import Path
import sys

from .cli import (SEVERITY_RANK, markdown_cell, markdown_report,
                  reject_duplicate_keys, reject_nonfinite_constant, scan_file)


def load_inputs(manifest):
    with manifest.open(encoding="utf-8") as stream:
        document = json.load(stream, object_pairs_hook=reject_duplicate_keys,
                             parse_constant=reject_nonfinite_constant)
    if not isinstance(document, dict) or set(document) != {"inputs"}:
        raise ValueError("Batch manifest must contain only an inputs list")
    entries = document["inputs"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Batch inputs must be a nonempty list")
    result, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "kind"}:
            raise ValueError("Each batch input requires exactly path and kind")
        source, kind = entry["path"], entry["kind"]
        if not isinstance(source, str) or not source.strip():
            raise ValueError("Batch path must be a nonempty string")
        if kind not in ("terraform", "kubernetes"):
            raise ValueError("Batch kind must be terraform or kubernetes")
        path = (manifest.parent / source).resolve()
        if path in seen:
            raise ValueError("Batch manifest contains a duplicate input path")
        seen.add(path)
        result.append((source, kind, path))
    return result


def scan_batch(manifest):
    reports = []
    for source, kind, path in load_inputs(manifest):
        try:
            findings = scan_file(path, kind)
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
            raise ValueError(f"Input {source!r} could not be scanned: {error}") from error
        reports.append((source, kind, findings))
    return reports


def main():
    parser = argparse.ArgumentParser(description="Scan an explicit batch of GCP plans and Kubernetes JSON.")
    parser.add_argument("manifest", type=Path, help="JSON manifest listing input paths and kinds")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument("--fail-on", choices=("none", "medium", "high"), default="none")
    args = parser.parse_args()
    try:
        reports = scan_batch(args.manifest)
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
        print(f"CloudMesh Sentinel: unable to scan batch: {error}", file=sys.stderr)
        return 2

    all_findings = [finding for _, _, findings in reports for finding in findings]
    blocked = args.fail_on != "none" and any(
        SEVERITY_RANK[level] >= SEVERITY_RANK[args.fail_on.upper()]
        for level, _, _ in all_findings)
    summary = {"files": len(reports), "total": len(all_findings), **{
        level: sum(severity == level for severity, _, _ in all_findings) for level in SEVERITY_RANK}}
    if args.format == "json":
        print(json.dumps({"schema_version": 1, "report_type": "batch", "summary": summary,
            "fail_on": args.fail_on, "gate": "informational" if args.fail_on == "none" else ("fail" if blocked else "pass"),
            "files": [{"source": source, "kind": kind, "findings": [
                {"severity": level, "address": address, "message": message}
                for level, address, message in findings]} for source, kind, findings in reports]}, indent=2))
    elif args.format == "markdown":
        print("# CloudMesh Sentinel batch report\n")
        print(f"Files scanned: {len(reports)}\n")
        gate = "Informational" if args.fail_on == "none" else ("FAIL" if blocked else "PASS")
        print(f"Gate: {gate} (threshold: {args.fail_on})\n")
        print("| Total | HIGH | MEDIUM |\n| --- | --- | --- |")
        print(f"| {summary['total']} | {summary['HIGH']} | {summary['MEDIUM']} |")
        for source, kind, findings in reports:
            print(f"\n## {markdown_cell(source)} ({kind})\n")
            section = markdown_report(findings, args.fail_on)
            print(section.replace("# CloudMesh Sentinel report\n", "", 1)
                  .replace("## Findings", "### Findings").lstrip())
    else:
        print(f"CloudMesh Sentinel: {len(reports)} file(s), {len(all_findings)} finding(s)\n")
        print("Gate: " + ("informational" if args.fail_on == "none" else ("FAIL" if blocked else "PASS")))
        for source, kind, findings in reports:
            print(f"\nSource: {source!r} ({kind}) — {len(findings)} finding(s)")
            for level, address, message in findings:
                print(f"[{level}] {address}\n  {message}")
    return int(blocked)


if __name__ == "__main__":
    sys.exit(main())
