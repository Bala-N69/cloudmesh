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

Project IAM member and binding resources are also flagged HIGH when their
planned `after` values include `allUsers` or `allAuthenticatedUsers`, regardless
of role. The latter is not limited to your organization. This flags a risky
configuration attempt; it does not assert that Google accepts the binding or
that organization policies permit access. Unknown members are not inferred.
Deleting a public
binding produces the existing deletion warning, not a new public-access warning.

References: [Google provider firewall resource](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall)
and [Google IAM principals](https://docs.cloud.google.com/iam/docs/principals-overview).

## Full IAM policies and service-account keys

```bash
python3 cloudmesh_sentinel/cli.py examples/gcp-identity-risk-plan.json --format markdown --fail-on high
```

This synthetic example emits four HIGH findings and exits 1:

- Public members in `google_project_iam_policy.policy_data`.
- Owner/Editor granted to a service account in the project policy.
- Public members in `google_storage_bucket_iam_policy.policy_data`.
- A `google_service_account_key` create action.

The scanner parses the JSON string in the planned `after.policy_data` and
checks bindings. Each policy emits at most one public and one privileged-role
finding. Conditions are not evaluated; a conditional grant still warrants
review. Malformed policy JSON, duplicate keys, or invalid binding shapes cause
exit 2 without a report. Missing/null policy data is unknown and not inferred.
Deletion-only changes receive the existing deletion finding. Key replacement
emits both replacement and key-creation findings; no-op keys are not flagged.
The key check covers generated and uploaded keys and does not read key material.
These are review policies, not proof of effective access or provider acceptance.

Reference: [Google service account key resource](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_service_account_key).
