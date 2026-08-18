import unittest

from cloudmesh_sentinel.cli import scan_plan


class TestTerraformRiskScanner(unittest.TestCase):
    def test_flags_public_ssh_firewall_as_high_risk(self):
        plan = {
            "resource_changes": [
                {
                    "address": "google_compute_firewall.allow_ssh",
                    "type": "google_compute_firewall",
                    "change": {
                        "actions": ["create"],
                        "after": {
                            "source_ranges": ["0.0.0.0/0"],
                            "allow": [{"ports": ["22"]}],
                        },
                    },
                }
            ]
        }

        findings = scan_plan(plan)

        self.assertIn(
            ("HIGH", "google_compute_firewall.allow_ssh",
             "Firewall allows traffic from 0.0.0.0/0."),
            findings,
        )

    def test_flags_public_storage_access_as_high_risk(self):
        plan = {
            "resource_changes": [
                {
                    "address": "google_storage_bucket_iam_member.public_read",
                    "type": "google_storage_bucket_iam_member",
                    "change": {
                        "actions": ["create"],
                        "after": {"member": "allUsers"},
                    },
                }
            ]
        }

        findings = scan_plan(plan)

        self.assertEqual(findings[0][0], "HIGH")
        self.assertIn("Storage access is public", findings[0][2])

    def test_flags_compute_instance_with_public_ip(self):
        plan = {
            "resource_changes": [
                {
                    "address": "google_compute_instance.web",
                    "type": "google_compute_instance",
                    "change": {
                        "actions": ["create"],
                        "after": {
                            "network_interface": [{"access_config": [{}]}],
                        },
                    },
                }
            ]
        }

        self.assertIn(
            ("HIGH", "google_compute_instance.web", "Compute instance has a public IP address."),
            scan_plan(plan),
        )

    def test_flags_cloud_sql_with_public_ipv4(self):
        plan = {
            "resource_changes": [
                {
                    "address": "google_sql_database_instance.app",
                    "type": "google_sql_database_instance",
                    "change": {
                        "actions": ["create"],
                        "after": {
                            "settings": [{"ip_configuration": [{"ipv4_enabled": True}]}],
                        },
                    },
                }
            ]
        }

        self.assertIn(
            (
                "HIGH",
                "google_sql_database_instance.app",
                "Cloud SQL instance permits a public IPv4 address.",
            ),
            scan_plan(plan),
        )

    def test_flags_storage_bucket_without_uniform_access(self):
        plan = {
            "resource_changes": [
                {
                    "address": "google_storage_bucket.logs",
                    "type": "google_storage_bucket",
                    "change": {
                        "actions": ["create"],
                        "after": {"uniform_bucket_level_access": False},
                    },
                }
            ]
        }

        self.assertIn(
            (
                "MEDIUM",
                "google_storage_bucket.logs",
                "Cloud Storage bucket does not use uniform bucket-level access.",
            ),
            scan_plan(plan),
        )

    def test_flags_resource_replacement_as_high_risk(self):
        plan = {
            "resource_changes": [
                {
                    "address": "google_compute_instance.web",
                    "type": "google_compute_instance",
                    "change": {
                        "actions": ["delete", "create"],
                        "after": {},
                    },
                }
            ]
        }

        findings = scan_plan(plan)

        self.assertEqual(findings[0][0], "HIGH")
        self.assertIn("replaced", findings[0][2])

    def test_safe_plan_has_no_findings(self):
        plan = {
            "resource_changes": [
                {
                    "address": "google_compute_firewall.allow_https",
                    "type": "google_compute_firewall",
                    "change": {
                        "actions": ["create"],
                        "after": {
                            "source_ranges": ["10.0.0.0/8"],
                            "allow": [{"ports": ["443"]}],
                        },
                    },
                }
            ]
        }

        self.assertEqual(scan_plan(plan), [])


if __name__ == "__main__":
    unittest.main()
