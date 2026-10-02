# CloudMesh Sentinel

Find risky infrastructure settings before deployment.

CloudMesh Sentinel is a lightweight Python CLI for reviewing GCP Terraform plans
and Kubernetes workload JSON. It highlights public access, excessive permissions,
and container security gaps so you can investigate them before applying changes.

Use the included examples to learn what risky configurations look like, generate
reports for code reviews, or add severity-based checks to a CI pipeline.
The scanner runs locally with Python 3.10+ and the standard library—no cloud
account, credentials, Terraform installation, or running cluster is needed to
try the examples. CI tests the project with Python 3.12.

## Quick start

```bash
git clone https://github.com/Bala-N69/cloudmesh.git
cd cloudmesh

# Find three HIGH findings in a synthetic Terraform plan.
python3 cloudmesh_sentinel/cli.py examples/demo-plan.json

# Inspect a Kubernetes workload with unsafe settings.
python3 cloudmesh_sentinel/cli.py examples/kubernetes-risky.json --input-kind kubernetes

# Compare it with a workload that passes the implemented checks.
python3 cloudmesh_sentinel/cli.py examples/kubernetes-safe.json --input-kind kubernetes
```

The two risky examples print findings; the safe example prints `0 finding(s)`.
Scans are informational by default. Add `--fail-on high` to exit with a failure
when HIGH findings are present, or `--format markdown` for a report you can review
alongside a pull request.

Continue with the [GCP plan lab](terraform/README.md),
[Kubernetes scanning guide](kubernetes/README.md#kubernetes-json-scanning),
[reporting examples](docs/reports.md), or [Docker guide](docs/docker.md).
CloudMesh is a practical DevSecOps learning and review tool; its checks cover
specific patterns, and a clean report is not a complete security assessment.

## What it detects

- Public IPv4/IPv6 ingress firewall rules, including SSH/RDP port ranges and unrestricted TCP
- Compute instances with public IP addresses
- Cloud SQL instances that permit public IPv4 addresses
- Public Google Cloud Storage IAM access
- Cloud Storage buckets without uniform bucket-level access
- Service accounts assigned broad project roles such as Owner or Editor
- Project IAM member/binding changes that include public principals
- Public principals and broad service-account roles inside full GCP IAM policies
- Creation or replacement of GCP service-account keys
- Kubernetes container privilege settings, host access, and hardening gaps
- GKE control planes that allow access from any IPv4 address
- Resources scheduled for deletion
- Resources scheduled for replacement

## Run it locally

```bash
python3 cloudmesh_sentinel/cli.py examples/demo-plan.json
```

Example output:

```text
CloudMesh Sentinel: 3 finding(s)

[HIGH] google_compute_firewall.allow_ssh
  Firewall allows traffic from 0.0.0.0/0.

[HIGH] google_storage_bucket_iam_member.public_read
  Cloud Storage access is public.

[HIGH] google_compute_instance.web
  Resource will be replaced.
```

## Docker packaging

The scanner can also be packaged as a non-root container with only its source
and synthetic examples. See the [Docker guide](docs/docker.md) for build/run
commands, read-only input mounts, and opt-in container tests. A Docker engine
is required for local container checks; no cloud account is needed. GitHub
Actions builds the image and runs its seven integration tests in a separate job,
including external read-only plan inputs and malformed-input handling.

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

## Try a safe plan

The repository also includes a plan with internal HTTPS access and uniform
Cloud Storage access. It should return zero findings:

```bash
python3 cloudmesh_sentinel/cli.py examples/safe-plan.json
```

## GCP plan reports and CI gates

Inspect three GCP network risks without credentials or a cloud project:

```bash
python3 cloudmesh_sentinel/cli.py examples/gcp-network-risk-plan.json --format json
python3 cloudmesh_sentinel/cli.py examples/safe-plan.json --fail-on medium
```

Use `--fail-on high` to reject HIGH findings or `--fail-on medium` to reject
MEDIUM and HIGH findings. Exit codes are 0 for a completed scan below the
threshold, 1 for a policy failure, and 2 for input/usage errors. The default
remains informational, even when findings are present. JSON reports include
a schema version, severity counts, resource addresses, and messages.

Duplicate JSON keys are rejected at any nesting level with exit code 2 and no
success report, preventing later values from silently hiding earlier changes.
Repeated field names in separate objects remain valid.
Unquoted `NaN`, `Infinity`, and `-Infinity` literals are also rejected with exit
code 2 and no success report, including in nested fields. Ordinary JSON numbers
and quoted strings such as `"Infinity"` remain accepted.

See the [GCP plan lab](terraform/README.md) for examples and detection limits.
Zero findings means no implemented rule matched; it is not proof of security.

## Markdown reports

Create a readable risk report for a pull request or review:

```bash
python3 cloudmesh_sentinel/cli.py examples/demo-plan.json --format markdown > /tmp/cloudmesh-report.md
```

Reports contain HIGH/MEDIUM totals, a gate result, and findings sorted by
severity and resource. Add `--fail-on high` or `--fail-on medium` to enforce
the same exit codes as text/JSON output. The report is still printed when the
gate fails; invalid input exits 2 without printing a report. The default is
informational. Resource and finding text is escaped to preserve table layout
and prevent it from introducing Markdown links or HTML.

GitHub Actions adds a report for the synthetic demo to the scanner job summary.
It deliberately expects exit 1 from that risky demo; unexpected exit codes fail
the step. It does not automatically publish reports from real infrastructure.
Review reports before sharing: resource names may be sensitive even when the
raw plan is omitted. See [reporting examples](docs/reports.md).

## Kubernetes lab

Sentinel now checks individual Kubernetes workloads from JSON:

```bash
python3 cloudmesh_sentinel/cli.py examples/kubernetes-safe.json --input-kind kubernetes --fail-on medium
python3 cloudmesh_sentinel/cli.py examples/kubernetes-risky.json --input-kind kubernetes --format markdown --fail-on high
```

It checks regular, init, and ephemeral containers separately, including pod-level
security settings inherited by each container. All three report formats and
severity gates are supported. See [Kubernetes JSON scanning](kubernetes/README.md#kubernetes-json-scanning)
for supported workloads, rules, and limits. The existing Kustomize lab validation
continues to check its specific baseline; the JSON scanner is a separate mode.

CloudMesh also includes a local-first Kubernetes baseline in
[`kubernetes/`](kubernetes/). It uses Kustomize to separate reusable manifests
from a development overlay and demonstrates namespace isolation, least-
privilege container settings, NetworkPolicy, and resource limits, including
bounded ephemeral storage for its writable runtime volumes.

Rendering the manifests is local and free:

```bash
kubectl kustomize kubernetes/overlays/dev
```

To also check the lab's key security defaults, run:

```bash
bash scripts/validate-kubernetes.sh
```

See the [Kubernetes lab guide](kubernetes/README.md) for details.

GitHub Actions also compiles the Python source, runs the scanner tests, verifies
the risky demo plan reports its expected high-risk findings, confirms the safe
plan returns zero findings, validates the rendered Kubernetes security defaults,
and performs CodeQL analysis on the Python code before changes are merged.

## Project structure

```text
cloudmesh/
├── cloudmesh_sentinel/   # Scanner source code
├── examples/             # Sample Terraform-plan inputs
├── kubernetes/           # Secure local Kubernetes lab
├── scripts/              # Local validation helpers
├── tests/                # Automated security-rule tests
├── .github/workflows/    # Continuous integration checks
└── README.md
```

## Roadmap

- Expand checks for GCP, AWS, and Azure Terraform resources

## Security note

This project contains only sample infrastructure data. Never commit cloud credentials, Terraform state files, or secret configuration values.
