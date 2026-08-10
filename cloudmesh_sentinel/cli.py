import argparse
import json
from pathlib import Path

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
ADMIN_PORTS = {"22", "3389"}


def scan_plan(plan: dict) -> list[tuple[str, str, str]]:
    findings = []

    for resource in plan.get("resource_changes", []):
        address = resource.get("address", "unknown resource")
        resource_type = resource.get("type", "")
        change = resource.get("change", {})
        actions = change.get("actions", [])
        after = change.get("after") or {}

        if actions == ["delete"]:
            findings.append(("HIGH", address, "Resource will be deleted."))

        if "delete" in actions and "create" in actions:
            findings.append(("HIGH", address, "Resource will be replaced."))

        if resource_type == "google_compute_firewall":
            is_public = "0.0.0.0/0" in after.get("source_ranges", [])
            allows_admin = any(
                ADMIN_PORTS.intersection(rule.get("ports", []))
                for rule in after.get("allow", [])
            )

            if is_public:
                severity = "HIGH" if allows_admin else "MEDIUM"
                findings.append(
                    (severity, address, "Firewall allows traffic from 0.0.0.0/0.")
                )

        if resource_type.startswith("google_storage_bucket_iam_"):
            if after.get("member") in PUBLIC_MEMBERS:
                findings.append(
                    ("HIGH", address, "Cloud Storage access is public.")
                )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan a Terraform plan JSON file for infrastructure risks."
    )
    parser.add_argument("plan", type=Path, help="Path to Terraform plan JSON")
    args = parser.parse_args()

    with args.plan.open(encoding="utf-8") as file:
        findings = scan_plan(json.load(file))

    print(f"CloudMesh Sentinel: {len(findings)} finding(s)\n")

    for severity, address, message in findings:
        print(f"[{severity}] {address}")
        print(f"  {message}\n")


if __name__ == "__main__":
    main()