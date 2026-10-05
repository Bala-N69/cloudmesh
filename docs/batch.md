# Scan a batch of infrastructure files

Run commands from the repository root. No additional Python packages, cloud
account, or cluster are needed. Single-file commands remain unchanged.

## Manifest

Create a JSON manifest containing an explicit list of files and their input kinds:

```json
{
  "inputs": [
    {"path": "gcp-identity-risk-plan.json", "kind": "terraform"},
    {"path": "kubernetes-risky.json", "kind": "kubernetes"}
  ]
}
```

Paths resolve relative to the manifest's directory, even when running from a
different directory. Absolute paths and parent-directory paths are also accepted;
the manifest is a trusted local file list, not a sandbox. Only explicitly listed
files are read; there is no recursive discovery, glob expansion, or auto-detection.
Review a manifest before using it on your machine. Empty lists, unknown fields,
invalid kinds, and duplicate resolved paths (including symlink aliases) are
rejected. Distinct hard links are not deduplicated.

## Reports and exit codes

```bash
python3 -m cloudmesh_sentinel.batch examples/batch-demo.json --format markdown --fail-on high
python3 -m cloudmesh_sentinel.batch examples/batch-safe.json --format json --fail-on medium
```

- Exit 0: scan completed below the threshold, or informational mode (`--fail-on none`).
- Exit 1: at least one finding meets the configured threshold; the complete report is printed.
- Exit 2: invalid manifest or input; stderr identifies the error and stdout remains empty.

Files appear in manifest order. The summary counts all files, including those
with zero findings. Findings remain grouped by source and input kind, so equal
resource names in different files remain distinguishable. The mixed demo has
three files and 14 findings (10 HIGH, four MEDIUM). A problem in a later file
discards the partial results; input errors take precedence over policy failures.

JSON uses `schema_version: 1` and `report_type: "batch"`, with `summary`, `gate`,
`fail_on`, and a `files` array. Each file includes `source`, `kind`, and `findings`.
This is a separate report structure from single-file JSON. Markdown escapes
source labels and finding cells, but does not redact sensitive names or paths.
The scanner reads files without modifying them; redirecting output can overwrite
your chosen output file, so never redirect onto an input or manifest.

## Docker

Build the image using the [Docker guide](docker.md), then override its default
single-file entry point for a batch scan:

```bash
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --entrypoint python cloudmesh-sentinel:local -m cloudmesh_sentinel.batch \
  examples/batch-safe.json --format json --fail-on medium
```

For external inputs, mount a dedicated directory containing only the manifest
and synthetic inputs read-only. Manifest paths must resolve inside the container;
host absolute paths are not automatically translated.

## CI

The scanner workflow checks the safe batch and expects exit 1 from the mixed
synthetic batch. Its Markdown report is appended to the job summary. The Docker
job runs both batch examples in the built image. This does not publish real
infrastructure data or create cloud resources. Existing scanner limitations
still apply; a clean batch is not a complete security assessment.
