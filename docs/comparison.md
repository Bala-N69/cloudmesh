# Compare infrastructure risk reports

Compare two Sentinel schema-version-1 JSON reports offline, without dependencies
or credentials. Single GCP/Kubernetes reports and mixed batch reports are supported.
The command never modifies either input or suppresses existing scanner findings.

## Runnable synthetic demo

From the repository root, use a fresh directory to avoid overwriting reports:

```bash
report_dir=$(mktemp -d)
python3 -m cloudmesh_sentinel.cli examples/demo-plan.json --format json > "$report_dir/before.json"
python3 -m cloudmesh_sentinel.cli examples/safe-plan.json --format json > "$report_dir/after.json"
python3 -m cloudmesh_sentinel.compare "$report_dir/before.json" "$report_dir/after.json" --format markdown --fail-on high
```

Expect three resolved findings and exit 0. These are different synthetic fixtures,
not evidence of real remediation. Reverse the paths for three new HIGH findings
and exit 1. Compare the risky report with itself for three unchanged HIGH findings
and exit 1. Temporary reports remain for inspection.

## Matching and limits

Findings match by exact severity, address, and message; duplicate occurrences
are counted. Batch matching also includes literal source path and kind. Both
batch reports must have identical source/kind sets, including clean files;
dropping, renaming, or changing a file's kind fails with exit 2. Order may differ.

Single reports do not record source path or kind. Ensure you compare the same
workload/scope and scanner version. Message, severity, or address changes appear
as resolved plus new findings. A resolved finding is absent from the later
report, not proof of remediation. Reports and their provenance are not
authenticated: compare trusted reports and review the configuration changes.

## Formats and gates

Use `--format text` (default), `json`, or `markdown`. JSON has schema version 1,
`report_type: comparison`, lists `new`, `resolved`, `unchanged`, and summary counts
including `current_total`. Finding objects include source, kind, severity,
address, and message; source/kind are empty strings for single reports.
Comparison reports cannot be used as scan reports for further comparisons.

- Exit 0: informational mode (`--fail-on none`), or below the chosen threshold.
- Exit 1: any current finding meets `--fail-on high` or `--fail-on medium`.
- Exit 2: unreadable, malformed, inconsistent, or incompatible input; no stdout.

Gates count **all current findings**, not just new ones. Original report gate
fields are ignored. Summaries must match findings. Unsupported versions and
severities, duplicate keys, nonfinite literals, and numeric overflow are rejected.
Existing scanner and CI gates remain intact.

Markdown escapes untrusted punctuation; text quotes finding fields to avoid raw
terminal control characters. Escaping is not redaction: reports can contain
sensitive resource names. Output order is deterministic.

## Docker

After rebuilding the image, mount a folder of trusted reports read-only:

```bash
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --mount "type=bind,source=$report_dir,target=/reports,readonly" \
  --entrypoint python cloudmesh-sentinel:local -m cloudmesh_sentinel.compare \
  /reports/before.json /reports/after.json --format markdown --fail-on high
```

The non-root container user must be able to read those files. No image upload,
cloud deployment, or GitHub configuration change is required.
