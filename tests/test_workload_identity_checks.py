import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloudmesh_sentinel.cli import scan_kubernetes, scan_plan

ROOT = Path(__file__).resolve().parents[1]


class TestWorkloads(unittest.TestCase):
    def setUp(self):
        self.workload = json.loads((ROOT / "examples/kubernetes-safe.json").read_text())
        self.spec = self.workload["spec"]["template"]["spec"]

    def test_safe_fixture_and_all_supported_kinds(self):
        for kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"]:
            resource = {"kind": kind, "metadata": {"name": "demo"}}
            if kind == "Pod":
                resource["spec"] = self.spec
            elif kind == "CronJob":
                resource["spec"] = {"jobTemplate": {"spec": {"template": {"spec": self.spec}}}}
            else:
                resource["spec"] = {"template": {"spec": self.spec}}
            with self.subTest(kind=kind):
                self.assertEqual(scan_kubernetes(resource), [])

    def test_unsafe_sidecar_is_not_masked(self):
        self.spec["containers"].append({"name": "unsafe", "securityContext": {"privileged": True}})
        findings = scan_kubernetes(self.workload)
        self.assertTrue(any("privileged" in message for _, _, message in findings))
        self.assertTrue(all(address.endswith("/containers/unsafe") for _, address, _ in findings))

    def test_container_override_beats_pod_inheritance(self):
        security = self.spec["containers"][0]["securityContext"]
        security.update(runAsNonRoot=False, runAsUser=0, seccompProfile={"type": "Unconfined"})
        findings = scan_kubernetes(self.workload)
        self.assertEqual(len(findings), 3)
        self.assertEqual(sum(level == "HIGH" for level, _, _ in findings), 2)

    def test_init_and_ephemeral_containers_are_checked(self):
        for group in ["initContainers", "ephemeralContainers"]:
            workload = copy.deepcopy(self.workload)
            workload["spec"]["template"]["spec"][group] = [{"name": "unsafe"}]
            findings = scan_kubernetes(workload)
            self.assertTrue(findings)
            self.assertTrue(all(f"/{group}/unsafe" in address for _, address, _ in findings))

    def test_host_access_and_token_mount(self):
        self.spec.update(hostNetwork=True, hostPID=True, hostIPC=True,
                         automountServiceAccountToken=True, volumes=[{"hostPath": {"path": "/example"}}])
        findings = scan_kubernetes(self.workload)
        self.assertEqual(len(findings), 5)
        self.assertEqual(sum(level == "HIGH" for level, _, _ in findings), 4)

    def test_list_and_unsupported_inputs(self):
        self.assertEqual(scan_kubernetes({"kind": "List", "items": [self.workload]}), [])
        for invalid in [{}, {"kind": "Service"}, {"kind": "List", "items": []},
                        {"kind": "Pod", "metadata": {"name": "empty"}, "spec": {"containers": []}}]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                scan_kubernetes(invalid)

    def test_capabilities_require_string_lists(self):
        for field in ["drop", "add"]:
            for invalid in ["ALL", "NOT_ALL", {"ALL": True}, [1], [False], [None]]:
                with self.subTest(field=field, invalid=invalid):
                    workload = copy.deepcopy(self.workload)
                    caps = workload["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]
                    caps[field] = invalid
                    with self.assertRaisesRegex(ValueError, "capabilities.*list of strings"):
                        scan_kubernetes(workload)

    def test_capability_lists_preserve_findings(self):
        caps = self.spec["containers"][0]["securityContext"]["capabilities"]
        for drop in [None, [], ["NOT_ALL"]]:
            caps["drop"] = drop
            self.assertTrue(any("does not drop ALL" in message
                                for _, _, message in scan_kubernetes(self.workload)))
        caps.update(drop=["ALL"], add=["NET_ADMIN"])
        findings = scan_kubernetes(self.workload)
        self.assertEqual(len(findings), 1)
        self.assertIn("adds Linux capabilities", findings[0][2])

    def test_user_ids_require_nonnegative_integers(self):
        for scope in ["pod", "containers", "initContainers", "ephemeralContainers"]:
            for value in [False, True, "0", -1, 0.0, [], {}]:
                with self.subTest(scope=scope, value=value):
                    workload = copy.deepcopy(self.workload)
                    spec = workload["spec"]["template"]["spec"]
                    if scope == "pod":
                        context = spec["securityContext"]
                    else:
                        if scope != "containers":
                            spec[scope] = [copy.deepcopy(spec["containers"][0])]
                        context = spec[scope][0]["securityContext"]
                    context["runAsUser"] = value
                    with self.assertRaisesRegex(ValueError, "runAsUser.*non-negative integer"):
                        scan_kubernetes(workload)

    def test_valid_user_id_override_and_root_detection(self):
        self.spec["securityContext"]["runAsUser"] = 0
        self.assertTrue(any("root UID 0" in message for _, _, message in scan_kubernetes(self.workload)))
        self.spec["containers"][0]["securityContext"]["runAsUser"] = 101
        self.assertEqual(scan_kubernetes(self.workload), [])


class TestGcpIdentity(unittest.TestCase):
    def plan(self, resource_type, after, actions=None):
        return {"resource_changes": [{"type": resource_type, "address": "synthetic",
                "change": {"actions": actions or ["create"], "after": after}}]}

    def test_policy_variants_and_deduplication(self):
        for kind in ["google_project_iam_policy", "google_storage_bucket_iam_policy"]:
            for member in ["allUsers", "allAuthenticatedUsers"]:
                binding = {"role": "roles/viewer", "members": [member]}
                findings = scan_plan(self.plan(kind, {"policy_data": json.dumps({"bindings": [binding, binding]})}))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0][0], "HIGH")

    def test_privileged_service_account_and_private_policy(self):
        for role, count in [("roles/editor", 1), ("roles/owner", 1), ("roles/viewer", 0)]:
            policy = {"bindings": [{"role": role, "members": ["serviceAccount:synthetic"]}]}
            self.assertEqual(len(scan_plan(self.plan("google_project_iam_policy",
                             {"policy_data": json.dumps(policy)}))), count)

    def test_keys_only_flag_creation(self):
        for actions, count in [(["create"], 1), (["no-op"], 0), (["delete"], 1), (["delete", "create"], 2)]:
            findings = scan_plan(self.plan("google_service_account_key", None, actions))
            self.assertEqual(len(findings), count)
            self.assertEqual(any("key will be created" in message for _, _, message in findings), "create" in actions)

    def test_unknown_policy_and_deleted_policy(self):
        self.assertEqual(scan_plan(self.plan("google_project_iam_policy", {"policy_data": None})), [])
        self.assertEqual(len(scan_plan(self.plan("google_project_iam_policy", None, ["delete"]))), 1)

    def test_malformed_nested_policy(self):
        for policy in ['{', '[]', '{"bindings": null}', '{"bindings": [], "bindings": []}',
                       '{"bindings": [{"members": "allUsers"}]}']:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                scan_plan(self.plan("google_project_iam_policy", {"policy_data": policy}))


class TestCombinedCli(unittest.TestCase):
    def test_kubernetes_requires_explicit_input_mode(self):
        result = subprocess.run([sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"),
            str(ROOT / "examples/kubernetes-risky.json")], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--input-kind kubernetes", result.stderr)

    def test_formats_and_gates(self):
        for fixture, kind, status in [("kubernetes-safe.json", "kubernetes", 0),
                                      ("kubernetes-risky.json", "kubernetes", 1),
                                      ("gcp-identity-risk-plan.json", "terraform", 1)]:
            for output in ["text", "json", "markdown"]:
                result = subprocess.run([sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"),
                    str(ROOT / "examples" / fixture), "--input-kind", kind, "--format", output,
                    "--fail-on", "medium"], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertTrue(result.stdout)

    def test_invalid_kubernetes_input_emits_no_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            for document in [{"kind": "ConfigMap"}, {"kind": "Deployment", "metadata": {"name": "broken"}}, []]:
                path.write_text(json.dumps(document))
                result = subprocess.run([sys.executable, str(ROOT / "cloudmesh_sentinel/cli.py"), str(path),
                    "--input-kind", "kubernetes", "--format", "json"], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
