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

        if resource_type == "google_service_account_key" and "create" in actions:
            findings.append(("HIGH", address, "Service account key will be created; review long-lived credential usage."))

        if resource_type in {"google_project_iam_policy", "google_storage_bucket_iam_policy"}:
            policy_data = after.get("policy_data")
            if policy_data is not None:
                policy = json.loads(policy_data, object_pairs_hook=reject_duplicate_keys,
                                    parse_constant=reject_nonfinite_constant)
                if not isinstance(policy, dict) or not isinstance(policy.get("bindings", []), list):
                    raise ValueError("Expected IAM policy object with bindings list")
                public = privileged = False
                for binding in policy.get("bindings", []):
                    if not isinstance(binding, dict) or not isinstance(binding.get("members", []), list):
                        raise ValueError("Expected IAM binding object with members list")
                    members = binding.get("members", [])
                    if not all(isinstance(member, str) for member in members):
                        raise ValueError("Expected IAM members to be strings")
                    public |= bool(PUBLIC_MEMBERS.intersection(members))
                    privileged |= (binding.get("role") in PRIVILEGED_PROJECT_ROLES and
                                   any(member.startswith("serviceAccount:") for member in members))
                if public:
                    findings.append(("HIGH", address, "IAM policy includes a public principal."))
                if privileged and resource_type == "google_project_iam_policy":
                    findings.append(("HIGH", address, "Service account receives a privileged project IAM role."))

        if actions == ["delete"]:
            findings.append(("HIGH", address, "Resource will be deleted."))

        if "delete" in actions and "create" in actions:
            findings.append(("HIGH", address, "Resource will be replaced."))

        if resource_type == "google_compute_firewall":
            findings.extend(public_firewall_findings(after, address))

        if resource_type == "google_compute_instance":
            has_public_ip = any(
                interface.get("access_config")
                or interface.get("ipv6_access_config")
                for interface in after.get("network_interface") or []
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
            if PUBLIC_MEMBERS.intersection(members):
                findings.append(
                    ("HIGH", address, "Project IAM change includes a public principal.")
                )
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
            if any(
                backup.get("enabled") is False
                for setting in settings
                for backup in setting.get("backup_configuration") or []
            ):
                findings.append(
                    ("MEDIUM", address, "Cloud SQL automated backups are explicitly disabled; review recovery coverage.")
                )
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


def security_context(resource):
    context = resource.get("securityContext")
    if context is None:
        return {}
    if not isinstance(context, dict):
        raise ValueError("securityContext must be an object")
    return context


def validate_boolean_fields(context, fields):
    for field in fields:
        value = context.get(field)
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"{field} must be a boolean")


def validate_user_id(context):
    value = context.get("runAsUser")
    if value is not None and (type(value) is not int or value < 0):
        raise ValueError("runAsUser must be a non-negative integer")


def scan_kubernetes(document):
    """Inspect Linux workload JSON without contacting a cluster."""
    findings = []
    supported = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}

    def inspect(resource):
        if not isinstance(resource, dict):
            raise ValueError("Expected Kubernetes resource object")
        kind = resource.get("kind")
        if kind == "List":
            items = resource.get("items")
            if not isinstance(items, list) or not items:
                raise ValueError("Kubernetes List must contain resources")
            for item in items:
                inspect(item)
            return
        if kind not in supported:
            raise ValueError("Unsupported Kubernetes kind; supply supported workloads only")
        metadata = resource.get("metadata") or {}
        name = metadata.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("Kubernetes resource requires metadata.name")
        address = f"{kind}/{metadata.get('namespace', 'default')}/{name}"
        spec = resource.get("spec")
        if kind == "CronJob":
            spec = spec["jobTemplate"]["spec"]["template"]["spec"]
        elif kind != "Pod":
            spec = spec["template"]["spec"]
        if not isinstance(spec, dict):
            raise ValueError("Expected workload pod spec")
        if (spec.get("os") or {}).get("name", "linux") != "linux":
            raise ValueError("Kubernetes checks currently support Linux workloads only")

        def add(severity, target, message):
            findings.append((severity, target, message))

        validate_boolean_fields(spec, ["hostNetwork", "hostPID", "hostIPC",
                                       "automountServiceAccountToken"])
        for field in ["hostNetwork", "hostPID", "hostIPC"]:
            if spec.get(field) is True:
                add("HIGH", address, f"Pod enables {field}.")
        for volume in spec.get("volumes") or []:
            if "hostPath" in volume:
                add("HIGH", address, "Pod mounts a hostPath volume.")
        if spec.get("automountServiceAccountToken") is not False:
            add("MEDIUM", address, "Pod does not explicitly disable service-account token mounting.")
        pod_security = security_context(spec)
        validate_boolean_fields(pod_security, ["runAsNonRoot"])
        validate_user_id(pod_security)
        containers = spec.get("containers")
        if not isinstance(containers, list) or not containers:
            raise ValueError("Pod spec requires a nonempty containers list")
        for group in ["containers", "initContainers", "ephemeralContainers"]:
            entries = spec.get(group, [])
            if not isinstance(entries, list):
                raise ValueError("Expected container list")
            for container in entries:
                name = container.get("name")
                if not isinstance(name, str) or not name:
                    raise ValueError("Container requires a name")
                target = f"{address}/{group}/{name}"
                security = security_context(container)
                validate_boolean_fields(security, ["privileged", "allowPrivilegeEscalation",
                                                    "runAsNonRoot", "readOnlyRootFilesystem"])
                validate_user_id(security)
                if security.get("privileged") is True:
                    add("HIGH", target, "Container is privileged.")
                if security.get("allowPrivilegeEscalation") is not False:
                    add("HIGH", target, "Container does not explicitly disable privilege escalation.")
                if security.get("runAsNonRoot", pod_security.get("runAsNonRoot")) is not True:
                    add("HIGH", target, "Container does not enforce runAsNonRoot.")
                if security.get("runAsUser", pod_security.get("runAsUser")) == 0:
                    add("HIGH", target, "Container explicitly selects root UID 0.")
                if security.get("readOnlyRootFilesystem") is not True:
                    add("MEDIUM", target, "Container root filesystem is not explicitly read-only.")
                capabilities = security.get("capabilities")
                if capabilities is None:
                    capabilities = {}
                elif not isinstance(capabilities, dict):
                    raise ValueError("Container capabilities must be an object")
                for field in ["drop", "add"]:
                    values = capabilities.get(field)
                    if values is not None and (
                            not isinstance(values, list) or
                            not all(isinstance(value, str) for value in values)):
                        raise ValueError(f"Container capabilities.{field} must be a list of strings")
                if "ALL" not in (capabilities.get("drop") or []):
                    add("MEDIUM", target, "Container does not drop ALL Linux capabilities.")
                if capabilities.get("add"):
                    add("MEDIUM", target, "Container adds Linux capabilities; review necessity.")
                seccomp = security.get("seccompProfile", pod_security.get("seccompProfile")) or {}
                if seccomp.get("type") not in {"RuntimeDefault", "Localhost"}:
                    add("MEDIUM", target, "Container has no restricted seccomp profile.")

    inspect(document)
    return findings


def reject_duplicate_keys(pairs):
    """Reject ambiguous JSON objects at every nesting level."""
    result = {}
    for key, value in pairs:
        if key in result:
            # Do not echo arbitrary input keys or values into CI logs.
            raise ValueError("Duplicate JSON key; each object must have unique keys")
        result[key] = value
    return result


def reject_nonfinite_constant(value):
    """Reject Python's JSON extensions for non-finite numeric literals."""
    raise ValueError("Invalid JSON numeric constant; NaN and Infinity are not permitted")


def markdown_cell(value: str) -> str:
    """Encode punctuation so plan content cannot introduce Markdown or HTML."""
    return "".join(
        character if character.isalnum() or character == " " else f"&#{ord(character)};"
        for character in " ".join(str(value).split())
    )


def markdown_report(findings, threshold: str) -> str:
    counts = {level: sum(severity == level for severity, _, _ in findings)
              for level in SEVERITY_RANK}
    blocked = threshold != "none" and any(
        SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold.upper()]
        for severity, _, _ in findings)
    gate = "Informational (no failure threshold)" if threshold == "none" else (
        f"{'FAIL' if blocked else 'PASS'} (threshold: {threshold.upper()})")
    lines = ["# CloudMesh Sentinel report", "", f"Gate: {gate}", "",
             "| Total | HIGH | MEDIUM |", "| --- | --- | --- |",
             f"| {len(findings)} | {counts['HIGH']} | {counts['MEDIUM']} |", ""]
    if findings:
        lines += ["## Findings", "", "| Severity | Resource | Finding |",
                  "| --- | --- | --- |"]
        # Sort a copy: preserve the original order of text/JSON reports.
        for severity, address, message in sorted(
                findings, key=lambda item: (-SEVERITY_RANK[item[0]], item[1], item[2])):
            lines.append(f"| {severity} | {markdown_cell(address)} | {markdown_cell(message)} |")
    else:
        lines.append("No findings matched the implemented rules.")
    lines += ["", "This report covers implemented checks only; zero findings is not proof of security."]
    return "\n".join(lines)


def scan_file(path: Path, input_kind: str):
    """Load and scan one file with the same strict parser used by every CLI."""
    with path.open(encoding="utf-8") as file:
        plan = json.load(file, object_pairs_hook=reject_duplicate_keys,
                         parse_constant=reject_nonfinite_constant)
    if input_kind == "kubernetes":
        return scan_kubernetes(plan)
    if input_kind != "terraform":
        raise ValueError("Unsupported input kind")
    if isinstance(plan, dict) and "kind" in plan and "resource_changes" not in plan:
        raise ValueError("Kubernetes documents require --input-kind kubernetes")
    if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes", []), list):
        raise ValueError("Expected a plan object with a resource_changes list")
    return scan_plan(plan)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Terraform plan or Kubernetes workload JSON for infrastructure risks."
    )
    parser.add_argument("plan", type=Path, help="Path to Terraform plan or Kubernetes workload JSON")
    parser.add_argument("--input-kind", choices=("terraform", "kubernetes"), default="terraform",
                        help="Input format (default: terraform); Kubernetes requires workload JSON")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument("--fail-on", choices=("none", "medium", "high"), default="none",
                        help="Exit 1 for findings at or above this severity (default: none)")
    args = parser.parse_args()

    try:
        findings = scan_file(args.plan, args.input_kind)
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
    elif args.format == "markdown":
        print(markdown_report(findings, args.fail_on))
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
