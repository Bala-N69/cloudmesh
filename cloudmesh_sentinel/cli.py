import argparse
import json
from pathlib import Path

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
ADMIN_PORTS = {"22", "3389"}
PRIVILEGED_PROJECT_ROLES = {"roles/owner", "roles/editor"}


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

        if resource_type == "google_compute_instance":
            has_public_ip = any(
                interface.get("access_config")
                for interface in after.get("network_interface", [])
            )
            if has_public_ip:
                findings.append(
                    ("HIGH", address, "Compute instance has a public IP address.")
                )

        if resource_type.startswith("google_storage_bucket_iam_"):
            members = {after.get("member"), *(after.get("members") or [])}
            if PUBLIC_MEMBERS.intersection(members):
                findings.append(
                    ("HIGH", address, "Cloud Storage access is public.")
                )

        if resource_type in {
            "google_project_iam_member",
            "google_project_iam_binding",
        }:
            members = {after.get("member"), *(after.get("members") or [])}
            role = after.get("role")
            has_service_account = any(
                isinstance(member, str) and member.startswith("serviceAccount:")
                for member in members
            )

            if role in PRIVILEGED_PROJECT_ROLES and has_service_account:
                findings.append(
                    (
                        "HIGH",
                        address,
                        "Service account receives a privileged project IAM role.",
                    )
                )

        if resource_type == "google_storage_bucket":
            if after.get("uniform_bucket_level_access") is False:
                findings.append(
                    (
                        "MEDIUM",
                        address,
                        "Cloud Storage bucket does not use uniform bucket-level access.",
                    )
                )

        if resource_type == "google_sql_database_instance":
            settings = after.get("settings") or []
            ip_configuration = settings[0].get("ip_configuration", []) if settings else []
            if ip_configuration and ip_configuration[0].get("ipv4_enabled") is True:
                findings.append(
                    ("HIGH", address, "Cloud SQL instance permits a public IPv4 address.")
                )

        if resource_type == "google_container_cluster":
            master_networks = after.get("master_authorized_networks_config") or []
            allows_anywhere = any(
                cidr.get("cidr_block") == "0.0.0.0/0"
                for configuration in master_networks
                for cidr in configuration.get("cidr_blocks", [])
            )
            if allows_anywhere:
                findings.append(
                    (
                        "HIGH",
                        address,
                        "GKE control plane allows access from 0.0.0.0/0.",
                    )
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
