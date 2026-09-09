# GCP Terraform plan lab

This lab scans synthetic Terraform plan JSON locally. Python's standard
library is sufficient: no GCP project, Terraform installation, credentials,
deployment, or billing account is required for these examples.

## Run the scenarios

From the repository root:

```bash
python3 cloudmesh_sentinel/cli.py examples/gcp-network-risk-plan.json --format json
python3 cloudmesh_sentinel/cli.py examples/safe-plan.json --format json --fail-on medium
```

The network-risk fixture produces three HIGH findings: IPv6 SSH open to all
sources, an IPv4 TCP range including RDP (3389), and public unrestricted TCP.
The safe fixture produces zero findings under the implemented checks.

To exercise the failure gate:

```bash
python3 cloudmesh_sentinel/cli.py examples/gcp-network-risk-plan.json --fail-on high
```

This deliberately exits 1. In GitHub Actions the safe example must exit 0
and the risky example must exit exactly 1; a scanner error must fail the job.
The automated tests check JSON contents and both severity thresholds as well.

## Output contract

- `--format text` is the existing default human-readable report.
- `--format json` emits schema version 1, a summary with `total`, `MEDIUM`,
  and `HIGH` counts, and findings with `severity`, `address`, and `message`.
- `--fail-on none` (default) keeps completed scans informational.
- `--fail-on high` rejects HIGH findings; `--fail-on medium` rejects both levels.
- Exit 0 means below the selected threshold, exit 1 means policy failure,
  and exit 2 means an input or argument error. Input errors go to stderr.

## Firewall coverage and limits

The scanner detects explicit all-source ranges (`0.0.0.0/0` and `::/0`)
on enabled ingress allow rules. TCP ports 22 and 3389, inclusive ranges
containing them, unrestricted TCP, and the `all` protocol are HIGH.
Other public ingress allow rules are MEDIUM. Numeric TCP protocol `6` is
supported. Disabled, egress, and deny-only rules do not generate this finding;
deletions still generate the separate deletion warning.

This checks configuration, not effective network reachability. It does not
resolve rule priority, targets, hierarchical firewall policies, or unknown
Terraform values. Missing source ranges are not inferred as public; unresolved
values need manual review. Existing minimal fixtures without a protocol are
treated as TCP for compatibility. Inputs are assumed to be Terraform-shaped
JSON; this is not a complete Terraform schema validator.

The other scanner rules cover public compute addresses, storage IAM, broad
service-account roles, Cloud SQL public IPv4, GKE control-plane exposure, and
resource deletion/replacement. These are a limited set of heuristics, not a
compliance assessment. Keep real plans and secrets out of the repository.

Reference: [Google provider firewall resource](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall).
