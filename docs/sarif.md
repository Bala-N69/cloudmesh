# SARIF security reports

Export completed Terraform and Kubernetes scans as SARIF 2.1.0 for security
report viewers and code-scanning integrations. No new dependencies are needed.

```bash
# Informational export; risky inputs return 0 unless a threshold is set.
python3 cloudmesh_sentinel/cli.py examples/demo-plan.json --format sarif > /tmp/cloudmesh.sarif

# Mixed GCP/Kubernetes export. This demo intentionally exits 1.
python3 -m cloudmesh_sentinel.batch examples/batch-demo.json --format sarif --fail-on high > /tmp/cloudmesh-batch.sarif

# Safe Kubernetes example returns 0.
python3 cloudmesh_sentinel/cli.py examples/kubernetes-safe.json --input-kind kubernetes --format sarif --fail-on medium
```

## Report contract

- HIGH maps to SARIF `error`; MEDIUM maps to `warning`.
- Findings retain resource address, input kind, severity, and input-file URI.
  Reserved filename characters are percent-encoded.
- Relative single-input paths are relative to the invocation directory. Batch
  paths are joined to the manifest directory first. Absolute paths become file
  URIs. Use repository-relative inputs from the repository root for portability.
- Locations reference input JSON, **not** original Terraform HCL or Kubernetes
  YAML. No line numbers are guessed. File-only location support varies by viewer.
- Rule IDs combine the input kind and a digest of the exact finding message.
  Identical messages share a rule; changed messages change the rule ID.
- `cloudmeshFinding/v1` fingerprints include path, kind, severity, address, and
  message, independently of scan order. Changing these fields changes identity.
  Duplicate findings are preserved. This custom fingerprint does not promise
  GitHub alert deduplication.
- Run properties include files scanned, threshold, and gate outcome. Completed
  scans have `executionSuccessful: true` even when the policy gate fails.

Exit codes remain **0** (below threshold/informational), **1** (policy failure),
and **2** (invalid input/usage). Policy failures still print reports; invalid
single or batch inputs print no partial report. Shell redirection may create
an empty destination file on errors, so always check the exit code.

## Privacy and integration limits

Export stays offline: no uploads, settings changes, or new workflow permissions.
Raw input is not embedded, but paths and resource names may be sensitive. An
absolute path can reveal local directory names. Review before sharing and use
synthetic examples for demonstrations.

Consult the consumer's requirements, such as
[GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
GitHub uses a supported subset and its own fingerprint handling. Upload and alert
rendering have not been integration-tested here. Generated-file locations do
not provide annotations against original infrastructure source.

Use `--format json` for CloudMesh before/after comparisons: SARIF is export-only,
not comparison input. Existing text, JSON, and Markdown remain unchanged.
The Docker scanner accepts the same flag; see [Docker usage](docker.md).
