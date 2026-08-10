# cloudmesh
Cloud engineering lab focused on GCP, Terraform, Kubernetes, CI/CD automation, and DevSecOps practices.
# CloudMesh Sentinel

A lightweight Python CLI that scans Terraform plan JSON files for high-risk infrastructure changes before deployment.

CloudMesh Sentinel is designed for cloud and DevSecOps workflows where catching risky changes early matters—before they reach GCP, AWS, Azure, or any real environment.

## What it detects

- Public firewall rules, including public SSH or RDP access
- Public Google Cloud Storage IAM access
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

## Project structure

```text
cloudmesh/
├── cloudmesh_sentinel/   # Scanner source code
├── examples/             # Safe sample Terraform-plan input
├── tests/                # Automated security-rule tests
└── README.md
```

## Roadmap

- Add GitHub Actions to run tests automatically
- Support Markdown and JSON risk reports
- Add configurable policy severity levels
- Expand checks for GCP, AWS, and Azure Terraform resources

## Security note

This project contains only sample infrastructure data. Never commit cloud credentials, Terraform state files, or secret configuration values.