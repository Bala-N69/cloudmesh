# CloudMesh Sentinel

A lightweight Python CLI that scans Terraform plan JSON files for high-risk infrastructure changes before deployment.

CloudMesh Sentinel is designed for cloud and DevSecOps workflows where catching risky changes early matters—before they reach GCP, AWS, Azure, or any real environment.

## What it detects

- Public firewall rules, including public SSH or RDP access
- Compute instances with public IP addresses
- Cloud SQL instances that permit public IPv4 addresses
- Public Google Cloud Storage IAM access
- Cloud Storage buckets without uniform bucket-level access
- Service accounts assigned broad project roles such as Owner or Editor
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

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

## Kubernetes lab

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
the demo plan reports its expected high-risk findings, validates the rendered
Kubernetes security defaults, and performs CodeQL analysis on the Python code
before changes are merged.

## Project structure

```text
cloudmesh/
├── cloudmesh_sentinel/   # Scanner source code
├── examples/             # Safe sample Terraform-plan input
├── kubernetes/           # Secure local Kubernetes lab
├── scripts/              # Local validation helpers
├── tests/                # Automated security-rule tests
├── .github/workflows/    # Continuous integration checks
└── README.md
```

## Roadmap

- Support Markdown and JSON risk reports
- Add configurable policy severity levels
- Expand checks for GCP, AWS, and Azure Terraform resources

## Security note

This project contains only sample infrastructure data. Never commit cloud credentials, Terraform state files, or secret configuration values.
