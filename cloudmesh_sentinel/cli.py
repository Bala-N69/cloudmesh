import argparse
import json
import sys
from ipaddress import ip_network
from pathlib import Path

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
ADMIN_PORTS = {"22", "3389"}
PRIVILEGED_PROJECT_ROLES = {"roles/owner", "roles/editor"}
SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2}


def public_firewall_findings(after: dict, address: str) -> list[tuple[str, str, str]]:
    """Inspect explicit public ingress ranges; unknown sources are not inferred."""
    rules = after.get("allow") or []
    if after.get("disabled") or after.get("direction") == "EGRESS" or not rules:
        return []
    public_ranges = set()
    for source in after.get("source_ranges") or []:
        try:
            network = ip_network(source, strict=False)
        except (ValueError, TypeError):
            continue
        if network.prefixlen == 0:
            public_ranges.add(str(network))

    allows_admin = False
    for rule in rules:
        # Older synthetic examples omit protocol; preserve their TCP behavior.
        protocol = str(rule.get("protocol", "tcp")).lower()
        if protocol == "all":
            allows_admin = True
        elif protocol in {"tcp", "6"}:
            ports = rule.get("ports") or []
            if not ports:
                allows_admin = True
            for value in ports:
                bounds = str(value).split("-")
                try:
                    start = int(bounds[0])
                    end = int(bounds[-1])
                except ValueError:
                    continue
                if len(bounds) <= 2 and any(start <= int(port) <= end for port in ADMIN_PORTS):
                    allows_admin = True
    severity = "HIGH" if allows_admin else "MEDIUM"
    return [(severity, address, f"Firewall allows traffic from {source}.")
            for source in sorted(public_ranges)]


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
            findings.extend(public_firewall_findings(after, address))

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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a Terraform plan JSON file for infrastructure risks."
    )
    parser.add_argument("plan", type=Path, help="Path to Terraform plan JSON")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on", choices=("none", "medium", "high"), default="none",
                        help="Exit 1 for findings at or above this severity (default: none)")
    args = parser.parse_args()

    try:
        with args.plan.open(encoding="utf-8") as file:
            plan = json.load(file)
        if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes", []), list):
            raise ValueError("Expected a plan object with a resource_changes list")
        findings = scan_plan(plan)
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
        print(f"CloudMesh Sentinel: unable to scan plan: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps({
            "schema_version": 1,
            "summary": {"total": len(findings), **{
                level: sum(severity == level for severity, _, _ in findings)
                for level in SEVERITY_RANK}},
            "findings": [{"severity": severity, "address": address, "message": message}
                         for severity, address, message in findings],
        }, indent=2))
    else:
        print(f"CloudMesh Sentinel: {len(findings)} finding(s)\n")
        for severity, address, message in findings:
            print(f"[{severity}] {address}")
            print(f"  {message}\n")

    return int(args.fail_on != "none" and any(
        SEVERITY_RANK[severity] >= SEVERITY_RANK[args.fail_on.upper()]
        for severity, _, _ in findings))


if __name__ == "__main__":
    sys.exit(main())
