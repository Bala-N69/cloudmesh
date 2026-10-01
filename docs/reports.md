# Reviewing scan reports

Sentinel supports `text` (default), `json`, and `markdown`. All formats use the
same findings and severity thresholds. Markdown is intended for human review;
JSON remains the structured interface for other tools.

## Local review

```bash
python3 cloudmesh_sentinel/cli.py examples/safe-plan.json --format markdown --fail-on medium
python3 cloudmesh_sentinel/cli.py examples/demo-plan.json --format markdown --fail-on high
```

The safe fixture prints PASS and exits 0. The demo prints FAIL with three HIGH
findings and exits 1. With no threshold, the gate reads Informational and
findings do not change the exit status. PASS only means the configured threshold
was not reached; it can still include MEDIUM findings when the threshold is HIGH.

## Save a report and preserve its exit code

```bash
status=0
python3 cloudmesh_sentinel/cli.py examples/demo-plan.json --format markdown --fail-on high > /tmp/cloudmesh-report.md || status=$?
cat /tmp/cloudmesh-report.md
# In a CI shell script, return the scanner's original status:
exit "$status"
```

Run that block in a script: `exit` ends the current shell. Redirection replaces
the destination file, including with an empty file when input is invalid.
Exit 2 means the input could not be scanned, not that a security finding exists.

## Containers and CI

After building the image using the [Docker guide](docker.md):

```bash
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges cloudmesh-sentinel:local examples/demo-plan.json --format markdown
```

The existing scanner CI job renders only the committed synthetic demo into its
GitHub Actions job summary. Its expected failure threshold is checked before
the summary is appended. The report is not a PR comment or an uploaded artifact.

Reports sort HIGH before MEDIUM, then resource and message, without changing
the order of existing text/JSON output. Newlines in cell values become spaces;
punctuation is represented as HTML numeric entities so input cannot create new
table columns, headings, links, or raw HTML. These entities display as ordinary
characters in rendered Markdown. Escaping is not secret redaction: inspect
resource names before sharing a report. A report only covers implemented rules.
