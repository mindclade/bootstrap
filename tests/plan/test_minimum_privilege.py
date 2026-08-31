# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
"""Adversarial tests for Ring-0 OpenTofu plan classification."""

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ACTIVE_SIGNING_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErp5ckXjgHSqIb2af/45Lat+pw0HK
mRlf0R6uyEmYOcJ9OUMWh7B4DftTdqcSXXK0cFf0RwQvPW9WBhTWPqEAWQ==
-----END PUBLIC KEY-----
"""


def runfiles_directory():
    runfiles = os.environ.get("RUNFILES_DIR") or os.environ.get("TEST_SRCDIR")
    return Path(runfiles) if runfiles else None


def local_repository_root():
    if runfiles_directory() is not None:
        raise RuntimeError("Bazel tests must use declared runfiles")
    return Path(__file__).resolve().parents[2]


def build_bootstrapctl(destination):
    configured = os.environ.get("BOOTSTRAPCTL")
    if configured:
        return Path(configured)
    runfiles = runfiles_directory()
    if runfiles is not None:
        workspace = os.environ.get("TEST_WORKSPACE", "_main")
        for source_root in [runfiles / "_main", runfiles / workspace]:
            candidate = source_root / "tooling" / "bootstrapctl_" / "bootstrapctl"
            if candidate.is_file() and os.access(str(candidate), os.X_OK):
                return candidate
        raise RuntimeError("cannot locate bootstrapctl in Bazel runfiles")
    binary = Path(destination) / "bootstrapctl"
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/bootstrapctl"],
        cwd=local_repository_root() / "tooling",
        check=True,
    )
    return binary


class MinimumPrivilegePlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.bootstrapctl = build_bootstrapctl(cls._temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def check_plan(self, resources):
        return self.run_plan_command("plan-resource-check", resources)

    def check_root_plan(self, resources, root):
        return self.run_plan_command("plan-check", resources, "--root", root)

    def run_plan_command(self, command, resources, *arguments):
        return self.run_plan_document(
            command,
            {
                "format_version": "1.2",
                "terraform_version": "1.12.6",
                "resource_changes": resources,
                "configuration": {
                    "provider_config": {
                        "google": {
                            "name": "google",
                            "full_name": "registry.opentofu.org/hashicorp/google",
                        }
                    },
                    "root_module": {},
                },
            },
            *arguments,
        )

    def run_plan_document(self, command, document, *arguments):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            json.dump(document, handle)
            path = handle.name
        try:
            return subprocess.run(
                [str(self.bootstrapctl), command, "--plan", path, *arguments],
                text=True,
                capture_output=True,
                check=False,
            )
        finally:
            Path(path).unlink()

    def resource(self, resource_type, actions, after):
        if isinstance(after, dict) and resource_type in {
            "google_iam_workforce_pool",
            "google_iam_workforce_pool_provider",
            "google_iam_workload_identity_pool",
            "google_iam_workload_identity_pool_provider",
            "google_kms_crypto_key",
            "google_kms_crypto_key_version",
            "google_logging_organization_sink",
            "google_logging_project_bucket_config",
            "google_organization_iam_custom_role",
            "google_privileged_access_manager_entitlement",
            "google_project",
            "google_project_iam_custom_role",
            "google_project_service",
            "google_service_account",
            "google_storage_bucket",
            "google_storage_transfer_job",
        }:
            after.setdefault("deletion_policy", "PREVENT")
        return {
            "address": "module.test." + resource_type + ".example",
            "mode": "managed",
            "type": resource_type,
            "change": {"actions": actions, "after": after, "after_unknown": {}},
        }

    def project_resource(self, logical_name, project_id):
        resource = self.resource(
            "google_project",
            ["create"],
            {
                "project_id": project_id,
                "name": project_id,
                "org_id": "123456789",
                "billing_account": "ABCDEF-123456-ABCDEF",
                "auto_create_network": False,
                "deletion_policy": "PREVENT",
            },
        )
        addresses = {
            "identity": "google_project.identity",
            "root_state": 'google_project.state["root_state"]',
            "recovery": 'google_project.state["recovery"]',
            "audit": "module.audit_root.google_project.audit",
            "signing": "module.signing_root.google_project.signing",
        }
        resource["address"] = addresses[logical_name]
        return resource

    def replication_custom_role(self, module, instance, role_id, permissions):
        resource = self.resource(
            "google_project_iam_custom_role",
            ["create"],
            {
                "project": "bootstrap-state-root",
                "role_id": role_id,
                "permissions": permissions,
                "stage": "GA",
                "deleted": False,
            },
        )
        resource["address"] = f'{module}.google_project_iam_custom_role.replication["{instance}"]'
        return resource

    def replication_transfer_job(
        self,
        module="module.root_state",
        prefix="root-trust/default.tfstate",
        source="bootstrap-primary-state",
        destination="bootstrap-replica-state",
    ):
        resource = self.resource(
            "google_storage_transfer_job",
            ["create"],
            {
                "project": "bootstrap-state-root",
                "description": "Replicate reviewed state objects",
                "status": "ENABLED",
                "deletion_policy": "PREVENT",
                "event_stream": [],
                "logging_config": [],
                "notification_config": [],
                "schedule": [],
                "service_account": "",
                "transfer_spec": [],
                "replication_spec": [
                    {
                        "gcs_data_source": [{"bucket_name": source, "path": ""}],
                        "gcs_data_sink": [{"bucket_name": destination, "path": ""}],
                        "object_conditions": [
                            {
                                "include_prefixes": [prefix],
                                "exclude_prefixes": [],
                                "last_modified_before": "",
                                "last_modified_since": "",
                                "max_time_elapsed_since_last_modification": "",
                                "min_time_elapsed_since_last_modification": "",
                            }
                        ],
                        "transfer_options": [
                            {
                                "delete_objects_from_source_after_transfer": False,
                                "delete_objects_unique_in_sink": False,
                                "overwrite_objects_already_existing_in_sink": False,
                                "overwrite_when": "DIFFERENT",
                                "metadata_options": [
                                    {
                                        "acl": "ACL_DESTINATION_BUCKET_DEFAULT",
                                        "kms_key": "KMS_KEY_DESTINATION_BUCKET_DEFAULT",
                                        "storage_class": "STORAGE_CLASS_DESTINATION_BUCKET_DEFAULT",
                                        "gid": "",
                                        "mode": "",
                                        "symlink": "",
                                        "temporary_hold": "",
                                        "time_created": "",
                                        "uid": "",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
        )
        resource["address"] = f"{module}.google_storage_transfer_job.replication"
        return resource

    def state_export_custom_role(self, name, role_id, permissions, key=None):
        project = "bootstrap-recovery"
        if key == "root-trust":
            project = "bootstrap-state-root"
        resource = self.resource(
            "google_project_iam_custom_role",
            ["create"],
            {
                "project": project,
                "role_id": role_id,
                "permissions": permissions,
                "stage": "GA",
                "deleted": False,
            },
        )
        resource["address"] = (
            f"module.recovery_exports.google_project_iam_custom_role.state_export_{name}"
        )
        if key is not None:
            resource["address"] += f'["{key}"]'
        return resource

    def state_export_job(self, key):
        project = {
            "root-trust": "bootstrap-state-root",
            "recovery-plane": "bootstrap-recovery",
        }[key]
        source = {
            "root-trust": "bootstrap-primary-state",
            "recovery-plane": "bootstrap-recovery-primary",
        }[key]
        resource = self.replication_transfer_job(
            prefix=f"{key}/default.tfstate",
            source=source,
            destination="bootstrap-recovery-recovery-exports",
        )
        resource["address"] = (
            f'module.recovery_exports.google_storage_transfer_job.state_export["{key}"]'
        )
        resource["change"]["after"].update(
            {
                "project": project,
                "service_account": (f"bootstrap-recovery-export@{project}.iam.gserviceaccount.com"),
            }
        )
        return resource

    def public_trust_metadata(self):
        signing_versions = {
            key: (
                "projects/bootstrap-signing/locations/us-central1/keyRings/"
                f"bootstrap-signing/cryptoKeys/{key}/cryptoKeyVersions/1"
            )
            for key in (
                "audit-anchor",
                "bootstrap-handoff",
                "connected-observation-evidence",
                "github-config-plan-evidence",
                "infrastructure-export",
                "recovery-evidence",
            )
        }

        signing_windows = {
            key: {
                "active_version_ref": "v20260829",
                "activation_window_start": "2026-08-29T00:00:00Z",
                "rotation_deadline": "2026-11-27T00:00:00Z",
            }
            for key in (
                "audit-anchor",
                "bootstrap-handoff",
                "recovery-evidence",
            )
        }
        return {
            "schema_version": 2,
            "manifest_digests": dict.fromkeys(
                (
                    "manifests/audit-roots.yaml",
                    "manifests/break-glass-roles.yaml",
                    "manifests/identity-federation.yaml",
                    "manifests/recovery-policy.yaml",
                    "manifests/signing-roots.yaml",
                    "manifests/state-backends.yaml",
                    "manifests/trust-anchors.yaml",
                ),
                "sha256:" + "a" * 64,
            ),
            "signing_key_versions": signing_versions,
            "signing_public_key_pem_sha256": {
                key: hashlib.sha256(ACTIVE_SIGNING_PUBLIC_KEY_PEM.encode("utf-8")).hexdigest()
                for key in signing_versions
            },
            "signing_windows": signing_windows,
            "federation_providers": {
                "github-plan": "projects/123456789/locations/global/workloadIdentityPools/bootstrap-github-plan/providers/github-actions-plan",
                "github-apply": "projects/123456789/locations/global/workloadIdentityPools/bootstrap-github-apply/providers/github-actions-apply",
                "github-recovery": "projects/987654321/locations/global/workloadIdentityPools/bootstrap-github-recovery/providers/github-actions-recovery",
                "buildkite": "projects/123456789/locations/global/workloadIdentityPools/bootstrap-buildkite/providers/buildkite",
                "gitops": "projects/123456789/locations/global/workloadIdentityPools/bootstrap-gitops/providers/gitops",
            },
            "federation_audiences": {
                key: f"https://identity.example.com/{key}"
                for key in (
                    "github-plan",
                    "github-apply",
                    "github-recovery",
                    "buildkite",
                    "gitops",
                )
            },
            "state_backends": {
                "root-trust": {
                    "bucket": "bootstrap-primary-state",
                    "prefix": "root-trust",
                    "replica_bucket": "bootstrap-replica-state",
                },
                "recovery-plane": {
                    "bucket": "bootstrap-recovery-primary",
                    "prefix": "recovery-plane",
                    "replica_bucket": "bootstrap-recovery-replica",
                },
            },
        }

    def recovery_variables(self):
        return {
            "project_id": "bootstrap-recovery",
            "location": "us-east4",
            "key_ring_name": "bootstrap-recovery",
            "export_key_name": "recovery-exports",
            "export_bucket_name": "bootstrap-recovery-recovery-exports",
            "evidence_bucket_name": "bootstrap-recovery-recovery-evidence",
            "exporter_principal": (
                "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com"
            ),
            "recovery_principal": (
                "serviceAccount:bootstrap-recovery@bootstrap-recovery.iam.gserviceaccount.com"
            ),
            "plan_principal": (
                "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com"
            ),
            "minimum_retained_state_generations": 3,
            "source_state_backends": {
                "root-trust": {
                    "project_id": "bootstrap-state-root",
                    "bucket": "bootstrap-primary-state",
                    "prefix": "root-trust",
                },
                "recovery-plane": {
                    "project_id": "bootstrap-recovery",
                    "bucket": "bootstrap-recovery-primary",
                    "prefix": "recovery-plane",
                },
            },
            "restore_manifest_digest": "sha256:" + "a" * 64,
            "public_trust_metadata": self.public_trust_metadata(),
            "labels": {},
        }

    def strict_recovery_document(self, resources):
        return {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": resources,
            "configuration": {
                "provider_config": {
                    "google": {
                        "name": "google",
                        "full_name": "registry.opentofu.org/hashicorp/google",
                    }
                },
                "root_module": {},
            },
            "variables": {"recovery": {"value": self.recovery_variables()}},
        }

    def complete_recovery_plane_resources(self):
        recovery_project = "bootstrap-recovery"
        export_bucket = "bootstrap-recovery-recovery-exports"
        evidence_bucket = "bootstrap-recovery-recovery-evidence"
        plan_member = "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com"
        apply_member = "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com"
        recovery_member = (
            "serviceAccount:bootstrap-recovery@bootstrap-recovery.iam.gserviceaccount.com"
        )
        resources = []

        def custom_role(address, project, role_id, permissions):
            resource = self.resource(
                "google_project_iam_custom_role",
                ["no-op"],
                {
                    "project": project,
                    "role_id": role_id,
                    "permissions": permissions,
                    "stage": "GA",
                    "deleted": False,
                },
            )
            resource["address"] = address
            resources.append(resource)

        custom_role(
            "module.recovery_exports.google_project_iam_custom_role.plan_read",
            recovery_project,
            "bootstrapRecoveryPlanRead",
            ["storage.buckets.get", "storage.buckets.getIamPolicy"],
        )
        custom_role(
            "module.recovery_exports.google_project_iam_custom_role.plan_object_read",
            recovery_project,
            "bootstrapRecoveryPlanObjectRead",
            ["storage.objects.get"],
        )

        key_ring = self.resource(
            "google_kms_key_ring",
            ["no-op"],
            {
                "project": recovery_project,
                "name": "bootstrap-recovery",
                "location": "us-east4",
            },
        )
        key_ring["address"] = "module.recovery_exports.google_kms_key_ring.recovery"
        resources.append(key_ring)

        storage_agent = self.resource(
            "google_storage_project_service_account",
            ["read"],
            {
                "project": recovery_project,
                "email_address": "service-123@gs-project-accounts.iam.gserviceaccount.com",
                "member": "serviceAccount:service-123@gs-project-accounts.iam.gserviceaccount.com",
            },
        )
        storage_agent["mode"] = "data"
        storage_agent["address"] = (
            "module.recovery_exports.data.google_storage_project_service_account.recovery"
        )
        resources.append(storage_agent)

        bucket_specs = {
            "exports": (export_bucket, "2592000", "recovery-exports"),
            "evidence": (evidence_bucket, "220752000", "recovery-evidence"),
        }
        for key, (bucket_name, retention, key_name) in bucket_specs.items():
            crypto_key_name = (
                f"projects/{recovery_project}/locations/us-east4/keyRings/"
                f"bootstrap-recovery/cryptoKeys/{key_name}"
            )
            crypto_key = self.resource(
                "google_kms_crypto_key",
                ["no-op"],
                {
                    "name": key_name,
                    "key_ring": (
                        f"projects/{recovery_project}/locations/us-east4/"
                        "keyRings/bootstrap-recovery"
                    ),
                    "purpose": "ENCRYPT_DECRYPT",
                    "rotation_period": "7776000s",
                    "destroy_scheduled_duration": "2592000s",
                    "version_template": [
                        {
                            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                            "protection_level": "HSM",
                        }
                    ],
                },
            )
            crypto_key["address"] = (
                f"module.recovery_exports.google_kms_crypto_key.recovery[{json.dumps(key)}]"
            )
            resources.append(crypto_key)

            kms_binding = self.resource(
                "google_kms_crypto_key_iam_member",
                ["no-op"],
                {
                    "crypto_key_id": crypto_key_name,
                    "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                    "member": "serviceAccount:service-123@gs-project-accounts.iam.gserviceaccount.com",
                },
            )
            kms_binding["address"] = (
                "module.recovery_exports.google_kms_crypto_key_iam_member.storage"
                f"[{json.dumps(key)}]"
            )
            resources.append(kms_binding)

            bucket = self.resource(
                "google_storage_bucket",
                ["no-op"],
                {
                    "project": recovery_project,
                    "name": bucket_name,
                    "location": "US-EAST4",
                    "storage_class": "STANDARD",
                    "uniform_bucket_level_access": True,
                    "public_access_prevention": "enforced",
                    "force_destroy": False,
                    "versioning": [{"enabled": True}],
                    "encryption": [{"default_kms_key_name": crypto_key_name}],
                    "retention_policy": [{"retention_period": retention, "is_locked": True}],
                    "soft_delete_policy": [{"retention_duration_seconds": 2592000}],
                },
            )
            bucket["address"] = (
                f"module.recovery_exports.google_storage_bucket.recovery[{json.dumps(key)}]"
            )
            resources.append(bucket)

            metadata_binding = self.resource(
                "google_storage_bucket_iam_member",
                ["no-op"],
                {
                    "bucket": bucket_name,
                    "role": (f"projects/{recovery_project}/roles/bootstrapRecoveryPlanRead"),
                    "member": plan_member,
                    "condition": [],
                },
            )
            metadata_binding["address"] = (
                "module.recovery_exports.google_storage_bucket_iam_member.plan_read"
                f"[{json.dumps(key)}]"
            )
            resources.append(metadata_binding)

            object_name = {
                "exports": "restore/inventory.json",
                "evidence": "trust/public-trust-metadata.json",
            }[key]
            object_binding = self.resource(
                "google_storage_bucket_iam_member",
                ["no-op"],
                {
                    "bucket": bucket_name,
                    "role": (f"projects/{recovery_project}/roles/bootstrapRecoveryPlanObjectRead"),
                    "member": plan_member,
                    "condition": [
                        {
                            "title": f"read-{key}-declared-object-only",
                            "expression": (
                                "resource.type == 'storage.googleapis.com/Object' "
                                "&& resource.name == "
                                f"'projects/_/buckets/{bucket_name}/objects/{object_name}'"
                            ),
                        }
                    ],
                },
            )
            object_binding["address"] = (
                "module.recovery_exports.google_storage_bucket_iam_member.plan_object_read"
                f"[{json.dumps(key)}]"
            )
            resources.append(object_binding)

        access_contracts = {
            "exports-exporter": (export_bucket, "roles/storage.objectCreator", apply_member),
            "exports-recovery": (export_bucket, "roles/storage.objectViewer", recovery_member),
            "exports-recovery-metadata": (
                export_bucket,
                "roles/storage.legacyBucketReader",
                recovery_member,
            ),
            "evidence-exporter": (evidence_bucket, "roles/storage.objectCreator", apply_member),
            "evidence-recovery": (evidence_bucket, "roles/storage.objectViewer", recovery_member),
            "evidence-recovery-metadata": (
                evidence_bucket,
                "roles/storage.legacyBucketReader",
                recovery_member,
            ),
        }
        for instance, (bucket_name, role, member) in access_contracts.items():
            binding = self.resource(
                "google_storage_bucket_iam_member",
                ["no-op"],
                {
                    "bucket": bucket_name,
                    "role": role,
                    "member": member,
                    "condition": [],
                },
            )
            binding["address"] = (
                "module.recovery_exports.google_storage_bucket_iam_member.access"
                f"[{json.dumps(instance)}]"
            )
            resources.append(binding)

        role_contracts = {
            "source_metadata": (
                "bootstrapRecoveryExportSourceMetadata",
                ["storage.buckets.get", "storage.buckets.update"],
                True,
            ),
            "source_object": (
                "bootstrapRecoveryExportSourceObject",
                ["storage.objects.get"],
                True,
            ),
            "transfer_events": (
                "bootstrapRecoveryExportTransferEvents",
                [
                    "pubsub.subscriptions.consume",
                    "pubsub.subscriptions.create",
                    "pubsub.topics.create",
                ],
                True,
            ),
            "storage_events": (
                "bootstrapRecoveryExportStorageEvents",
                [
                    "pubsub.subscriptions.consume",
                    "pubsub.subscriptions.create",
                    "pubsub.topics.publish",
                ],
                True,
            ),
            "destination_metadata": (
                "bootstrapRecoveryExportDestinationMetadata",
                ["storage.buckets.get"],
                False,
            ),
            "destination_object": (
                "bootstrapRecoveryExportDestinationObject",
                ["storage.objects.create", "storage.objects.get"],
                False,
            ),
        }
        for name, (role_id, permissions, indexed) in role_contracts.items():
            keys = ("root-trust", "recovery-plane") if indexed else (None,)
            for key in keys:
                address = (
                    f"module.recovery_exports.google_project_iam_custom_role.state_export_{name}"
                )
                project = recovery_project
                if key == "root-trust":
                    project = "bootstrap-state-root"
                if key is not None:
                    address += f"[{json.dumps(key)}]"
                custom_role(address, project, role_id, permissions)

        export_specs = {
            "root-trust": ("bootstrap-state-root", "bootstrap-primary-state"),
            "recovery-plane": (recovery_project, "bootstrap-recovery-primary"),
        }
        for key, (project, source_bucket) in export_specs.items():
            export_email = f"bootstrap-recovery-export@{project}.iam.gserviceaccount.com"
            export_member = f"serviceAccount:{export_email}"
            service_account_id = f"projects/{project}/serviceAccounts/{export_email}"

            service_account = self.resource(
                "google_service_account",
                ["no-op"],
                {
                    "project": project,
                    "account_id": "bootstrap-recovery-export",
                    "disabled": False,
                    "deletion_policy": "PREVENT",
                    "email": export_email,
                    "id": service_account_id,
                    "member": export_member,
                    "name": service_account_id,
                    "unique_id": "123456789",
                },
            )
            service_account["address"] = (
                f"module.recovery_exports.google_service_account.state_export[{json.dumps(key)}]"
            )
            resources.append(service_account)

            for data_type, name, extra in (
                (
                    "google_storage_project_service_account",
                    "state_export_source",
                    {
                        "email_address": "service-123@gs-project-accounts.iam.gserviceaccount.com",
                        "member": "serviceAccount:service-123@gs-project-accounts.iam.gserviceaccount.com",
                    },
                ),
                (
                    "google_storage_transfer_project_service_account",
                    "state_export",
                    {
                        "email": "project-123@storage-transfer-service.iam.gserviceaccount.com",
                        "member": "serviceAccount:project-123@storage-transfer-service.iam.gserviceaccount.com",
                        "subject_id": "serviceAccount:project-123@storage-transfer-service.iam.gserviceaccount.com",
                    },
                ),
            ):
                data_resource = self.resource(data_type, ["read"], {"project": project, **extra})
                data_resource["mode"] = "data"
                data_resource["address"] = (
                    f"module.recovery_exports.data.{data_type}.{name}[{json.dumps(key)}]"
                )
                resources.append(data_resource)

            definitions = (
                (
                    "google_service_account_iam_member",
                    "state_export_apply",
                    {
                        "service_account_id": service_account_id,
                        "role": "roles/iam.serviceAccountUser",
                        "member": apply_member,
                        "condition": [],
                    },
                ),
                (
                    "google_service_account_iam_member",
                    "state_export_transfer",
                    {
                        "service_account_id": service_account_id,
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "member": "serviceAccount:project-123@storage-transfer-service.iam.gserviceaccount.com",
                        "condition": [],
                    },
                ),
                (
                    "google_project_iam_member",
                    "state_export_transfer_events",
                    {
                        "project": project,
                        "role": f"projects/{project}/roles/bootstrapRecoveryExportTransferEvents",
                        "member": export_member,
                        "condition": [],
                    },
                ),
                (
                    "google_project_iam_member",
                    "state_export_storage_events",
                    {
                        "project": project,
                        "role": f"projects/{project}/roles/bootstrapRecoveryExportStorageEvents",
                        "member": "serviceAccount:service-123@gs-project-accounts.iam.gserviceaccount.com",
                        "condition": [],
                    },
                ),
                (
                    "google_storage_bucket_iam_member",
                    "state_export_source_metadata",
                    {
                        "bucket": source_bucket,
                        "role": f"projects/{project}/roles/bootstrapRecoveryExportSourceMetadata",
                        "member": export_member,
                        "condition": [],
                    },
                ),
                (
                    "google_storage_bucket_iam_member",
                    "state_export_source_object",
                    {
                        "bucket": source_bucket,
                        "role": f"projects/{project}/roles/bootstrapRecoveryExportSourceObject",
                        "member": export_member,
                        "condition": [
                            {
                                "title": f"read-{key}-default-state-only",
                                "expression": (
                                    "resource.type == 'storage.googleapis.com/Object' "
                                    "&& resource.name == "
                                    f"'projects/_/buckets/{source_bucket}/objects/{key}/default.tfstate'"
                                ),
                            }
                        ],
                    },
                ),
                (
                    "google_storage_bucket_iam_member",
                    "state_export_destination_metadata",
                    {
                        "bucket": export_bucket,
                        "role": f"projects/{recovery_project}/roles/bootstrapRecoveryExportDestinationMetadata",
                        "member": export_member,
                        "condition": [],
                    },
                ),
                (
                    "google_storage_bucket_iam_member",
                    "state_export_destination_object",
                    {
                        "bucket": export_bucket,
                        "role": f"projects/{recovery_project}/roles/bootstrapRecoveryExportDestinationObject",
                        "member": export_member,
                        "condition": [
                            {
                                "title": f"write-{key}-default-state-only",
                                "expression": (
                                    "resource.type == 'storage.googleapis.com/Object' "
                                    "&& resource.name == "
                                    f"'projects/_/buckets/{export_bucket}/objects/{key}/default.tfstate'"
                                ),
                            }
                        ],
                    },
                ),
            )
            for resource_type, name, after in definitions:
                binding = self.resource(resource_type, ["no-op"], after)
                binding["address"] = (
                    f"module.recovery_exports.{resource_type}.{name}[{json.dumps(key)}]"
                )
                resources.append(binding)

            job = self.state_export_job(key)
            job["change"]["actions"] = ["no-op"]
            resources.append(job)

        inventory = {
            "schema_version": 1,
            "source_state_objects": {
                "root-trust": {
                    "bucket": "bootstrap-primary-state",
                    "object": "root-trust/default.tfstate",
                },
                "recovery-plane": {
                    "bucket": "bootstrap-recovery-primary",
                    "object": "recovery-plane/default.tfstate",
                },
            },
            "export_state_objects": {
                key: {"bucket": export_bucket, "object": f"{key}/default.tfstate"}
                for key in ("root-trust", "recovery-plane")
            },
            "runtime_selection_required": ["generation", "sha256"],
            "minimum_retained_state_generations": 3,
            "restore_manifest_digest": "sha256:" + "a" * 64,
            "excludes": [
                "kms-private-key-material",
                "service-account-keys",
                "credentials",
            ],
        }
        for name, object_name, bucket_name, content in (
            (
                "public_trust_metadata",
                "trust/public-trust-metadata.json",
                evidence_bucket,
                self.public_trust_metadata(),
            ),
            (
                "restore_inventory",
                "restore/inventory.json",
                export_bucket,
                inventory,
            ),
        ):
            fixed_object = self.resource(
                "google_storage_bucket_object",
                ["no-op"],
                {
                    "name": object_name,
                    "bucket": bucket_name,
                    "content": json.dumps(content),
                    "content_type": "application/json",
                    "deletion_policy": "ABANDON",
                    "source": "",
                },
            )
            fixed_object["address"] = f"module.recovery_exports.google_storage_bucket_object.{name}"
            resources.append(fixed_object)

        return resources

    def signing_crypto_key(self, key_name):
        resource = self.resource(
            "google_kms_crypto_key",
            ["create"],
            {
                "name": key_name,
                "key_ring": (
                    "projects/bootstrap-signing/locations/us-central1/keyRings/bootstrap-signing"
                ),
                "purpose": "ASYMMETRIC_SIGN",
                "destroy_scheduled_duration": "2592000s",
                "skip_initial_version_creation": True,
                "version_template": [
                    {
                        "algorithm": "EC_SIGN_P256_SHA256",
                        "protection_level": "HSM",
                    }
                ],
            },
        )
        resource["address"] = f'module.signing_root.google_kms_crypto_key.signing["{key_name}"]'
        return resource

    def signing_version(
        self,
        key_name,
        actions=None,
        state="ENABLED",
        version_ref="v20260829",
        version_number="1",
    ):
        crypto_key = (
            "projects/bootstrap-signing/locations/us-central1/"
            f"keyRings/bootstrap-signing/cryptoKeys/{key_name}"
        )
        resource = self.resource(
            "google_kms_crypto_key_version",
            actions or ["create"],
            {
                "crypto_key": crypto_key,
                "name": f"{crypto_key}/cryptoKeyVersions/{version_number}",
                "algorithm": "EC_SIGN_P256_SHA256",
                "protection_level": "HSM",
                "state": state,
            },
        )
        resource["address"] = (
            "module.signing_root.google_kms_crypto_key_version.signing"
            f"[{json.dumps(f'{key_name}:{version_ref}')}]"
        )
        return resource

    def active_signing_values(self, key_name, version_number=1):
        crypto_key = (
            "projects/bootstrap-signing/locations/us-central1/"
            f"keyRings/bootstrap-signing/cryptoKeys/{key_name}"
        )
        name = f"{crypto_key}/cryptoKeyVersions/{version_number}"
        return {
            "algorithm": "EC_SIGN_P256_SHA256",
            "crypto_key": crypto_key,
            "id": f"//cloudkms.googleapis.com/v1/{name}",
            "name": name,
            "protection_level": "HSM",
            "public_key": [
                {
                    "algorithm": "EC_SIGN_P256_SHA256",
                    "pem": ACTIVE_SIGNING_PUBLIC_KEY_PEM,
                }
            ],
            "state": "ENABLED",
            "version": version_number,
        }

    def active_signing_data(self, key_name="audit-anchor", version_number=1):
        values = self.active_signing_values(key_name, version_number)
        address = (
            f"module.signing_root.data.google_kms_crypto_key_version.active[{json.dumps(key_name)}]"
        )
        resource = {
            "address": address,
            "mode": "data",
            "type": "google_kms_crypto_key_version",
            "change": {
                "actions": ["no-op"],
                "before": copy.deepcopy(values),
                "after": copy.deepcopy(values),
                "after_unknown": {},
            },
        }
        planned = {
            "address": address,
            "mode": "data",
            "type": "google_kms_crypto_key_version",
            "name": "active",
            "index": key_name,
            "provider_name": "registry.opentofu.org/hashicorp/google",
            "schema_version": 0,
            "values": copy.deepcopy(values),
        }
        return resource, planned

    def active_signing_document(
        self,
        data_resource,
        planned_resource,
        managed_version=None,
    ):
        key_name = data_resource["address"].split('["', 1)[1].split('"]', 1)[0]
        if managed_version is None:
            values = data_resource["change"]["after"]
            version_number = values.get("version", 1)
            managed_version = self.signing_version(
                key_name,
                actions=["no-op"],
                version_number=str(version_number),
            )
        return {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": [managed_version, data_resource],
            "planned_values": {
                "root_module": {
                    "child_modules": [
                        {
                            "address": "module.signing_root",
                            "resources": [planned_resource],
                        }
                    ]
                }
            },
        }

    def signing_binding(
        self,
        key_name,
        principal="serviceAccount:signer@example.iam.gserviceaccount.com",
        version_ref="v20260829",
        version_number="1",
        activation_window_start="2026-08-29T00:00:00Z",
        rotation_deadline="2026-11-27T00:00:00Z",
        actions=None,
    ):
        crypto_key = (
            "projects/bootstrap-signing/locations/us-central1/"
            f"keyRings/bootstrap-signing/cryptoKeys/{key_name}"
        )
        version_name = f"{crypto_key}/cryptoKeyVersions/{version_number}"
        resource = self.resource(
            "google_kms_crypto_key_iam_member",
            actions or ["create"],
            {
                "crypto_key_id": crypto_key,
                "role": "roles/cloudkms.signerVerifier",
                "member": principal,
                "condition": [
                    {
                        "title": f"sign-{key_name}-{version_ref}-within-window",
                        "expression": (
                            "resource.type == 'cloudkms.googleapis.com/CryptoKeyVersion' "
                            f"&& resource.name == '{version_name}' "
                            f"&& request.time >= timestamp('{activation_window_start}') "
                            f"&& request.time < timestamp('{rotation_deadline}')"
                        ),
                    }
                ],
            },
        )
        resource["address"] = (
            "module.signing_root.google_kms_crypto_key_iam_member.signer"
            f"[{json.dumps(f'{key_name}:{principal}')}]"
        )
        return resource

    def initial_signing_create_document(self):
        resources = []
        principals = {
            "audit-anchor": "serviceAccount:audit-signer@example.iam.gserviceaccount.com",
            "bootstrap-handoff": "serviceAccount:handoff-signer@example.iam.gserviceaccount.com",
            "github-config-plan-evidence": "serviceAccount:github-config-plan@example.iam.gserviceaccount.com",
            "recovery-evidence": "serviceAccount:recovery-signer@example.iam.gserviceaccount.com",
        }
        for key_name in (
            "audit-anchor",
            "bootstrap-handoff",
            "connected-observation-evidence",
            "github-config-plan-evidence",
            "infrastructure-export",
            "recovery-evidence",
        ):
            version = self.resource(
                "google_kms_crypto_key_version",
                ["create"],
                {"external_protection_level_options": [], "timeouts": None},
            )
            version["address"] = (
                "module.signing_root.google_kms_crypto_key_version.signing"
                f"[{json.dumps(f'{key_name}:v20260829')}]"
            )
            version["change"]["after_unknown"] = dict.fromkeys(
                (
                    "algorithm",
                    "attestation",
                    "crypto_key",
                    "generate_time",
                    "id",
                    "name",
                    "protection_level",
                    "state",
                ),
                True,
            )
            resources.append(version)

            if key_name in {
                "connected-observation-evidence",
                "infrastructure-export",
            }:
                continue

            principal = principals[key_name]
            signer = self.resource(
                "google_kms_crypto_key_iam_member",
                ["create"],
                {
                    "condition": [
                        {
                            "description": None,
                            "title": f"sign-{key_name}-v20260829-within-window",
                        }
                    ],
                    "member": principal,
                    "role": "roles/cloudkms.signerVerifier",
                },
            )
            signer["address"] = (
                "module.signing_root.google_kms_crypto_key_iam_member.signer"
                f"[{json.dumps(f'{key_name}:{principal}')}]"
            )
            signer["change"]["after_unknown"] = {
                "condition": [{"expression": True}],
                "crypto_key_id": True,
                "etag": True,
                "id": True,
            }
            resources.append(signer)

        recovery = self.resource(
            "google_kms_crypto_key_iam_member",
            ["create"],
            {
                "condition": [
                    {
                        "description": (
                            "Permit connected verification to inspect only the "
                            "recovery-evidence key and its source-selected active version."
                        ),
                        "title": "read-recovery-evidence-active-key-version-only",
                    }
                ],
                "member": "serviceAccount:bootstrap-recovery@bootstrap-recovery.iam.gserviceaccount.com",
                "role": "projects/bootstrap-signing/roles/bootstrapRecoverySigningMetadata",
            },
        )
        recovery["address"] = (
            "module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata"
        )
        recovery["change"]["after_unknown"] = {
            "condition": [{"expression": True}],
            "crypto_key_id": True,
            "etag": True,
            "id": True,
        }
        resources.append(recovery)

        signer_references = [
            "google_kms_crypto_key_version.signing",
            "each.value.active_version_key",
            "each.value",
            "each.value.activation_window_start",
            "each.value",
            "each.value.rotation_deadline",
            "each.value",
        ]
        configuration = {
            "root_module": {
                "module_calls": {
                    "signing_root": {
                        "module": {
                            "resources": [
                                {
                                    "address": "google_kms_crypto_key_iam_member.signer",
                                    "mode": "managed",
                                    "type": "google_kms_crypto_key_iam_member",
                                    "expressions": {
                                        "condition": [
                                            {
                                                "expression": {"references": signer_references},
                                                "title": {
                                                    "references": [
                                                        "each.value.key_name",
                                                        "each.value",
                                                        "each.value.active_version_ref",
                                                        "each.value",
                                                    ]
                                                },
                                            }
                                        ]
                                    },
                                },
                                {
                                    "address": "google_kms_crypto_key_iam_member.recovery_metadata",
                                    "mode": "managed",
                                    "type": "google_kms_crypto_key_iam_member",
                                    "expressions": {
                                        "condition": [
                                            {
                                                "description": {
                                                    "constant_value": (
                                                        "Permit connected verification to inspect only the "
                                                        "recovery-evidence key and its source-selected active version."
                                                    )
                                                },
                                                "expression": {
                                                    "references": [
                                                        'google_kms_crypto_key.signing["recovery-evidence"].id',
                                                        'google_kms_crypto_key.signing["recovery-evidence"]',
                                                        "google_kms_crypto_key.signing",
                                                        "google_kms_crypto_key_version.signing",
                                                        'var.keys["recovery-evidence"].active_version_ref',
                                                        'var.keys["recovery-evidence"]',
                                                        "var.keys",
                                                    ]
                                                },
                                                "title": {
                                                    "constant_value": "read-recovery-evidence-active-key-version-only"
                                                },
                                            }
                                        ]
                                    },
                                },
                            ]
                        }
                    }
                }
            }
        }
        signing_keys = {
            key_name: {
                "active_version_ref": "v20260829",
                "rotation_days": 90,
                "versions": {
                    "v20260829": {
                        "activation_window_start": "2026-08-29T00:00:00Z",
                        "rotation_deadline": "2026-11-27T00:00:00Z",
                    }
                },
            }
            for key_name in (
                "audit-anchor",
                "bootstrap-handoff",
                "connected-observation-evidence",
                "github-config-plan-evidence",
                "infrastructure-export",
                "recovery-evidence",
            )
        }
        return {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": resources,
            "configuration": configuration,
            "variables": {"bootstrap": {"value": {"signing": {"keys": signing_keys}}}},
        }

    def rotating_signing_variables(self, active_version_ref="v20260829"):
        versions = {
            "v20260829": {
                "activation_window_start": "2026-08-29T00:00:00Z",
                "rotation_deadline": "2026-11-27T00:00:00Z",
            },
            "v20261126": {
                "activation_window_start": "2026-11-26T00:00:00Z",
                "rotation_deadline": "2027-02-24T00:00:00Z",
            },
        }
        return {
            "bootstrap": {
                "value": {
                    "signing": {
                        "keys": {
                            key: {
                                "active_version_ref": active_version_ref,
                                "rotation_days": 90,
                                "versions": json.loads(json.dumps(versions)),
                            }
                            for key in (
                                "audit-anchor",
                                "bootstrap-handoff",
                                "connected-observation-evidence",
                                "github-config-plan-evidence",
                                "infrastructure-export",
                                "recovery-evidence",
                            )
                        }
                    }
                }
            }
        }

    def unknown_signing_version(self, key_name, version_ref="v20261126"):
        resource = self.resource(
            "google_kms_crypto_key_version",
            ["create"],
            {"external_protection_level_options": [], "timeouts": None},
        )
        resource["address"] = (
            "module.signing_root.google_kms_crypto_key_version.signing"
            f"[{json.dumps(f'{key_name}:{version_ref}')}]"
        )
        resource["change"]["after_unknown"] = dict.fromkeys(
            (
                "algorithm",
                "attestation",
                "crypto_key",
                "generate_time",
                "id",
                "name",
                "protection_level",
                "state",
            ),
            True,
        )
        return resource

    def github_plan_identity_resources(self):
        identity = self.project_resource("identity", "bootstrap-identity")
        state = self.project_resource("root_state", "bootstrap-state-root")
        pool = self.resource(
            "google_iam_workload_identity_pool",
            ["create"],
            {
                "project": "bootstrap-identity",
                "workload_identity_pool_id": "bootstrap-github-plan",
                "disabled": False,
            },
        )
        pool["address"] = (
            'module.github_federation.google_iam_workload_identity_pool.github["plan"]'
        )
        provider = self.resource(
            "google_iam_workload_identity_pool_provider",
            ["create"],
            {
                "project": "bootstrap-identity",
                "workload_identity_pool_id": "bootstrap-github-plan",
                "workload_identity_pool_provider_id": "github-actions-plan",
                "disabled": False,
                "attribute_mapping": {
                    "google.subject": "'bootstrap-plan:' + assertion.repository_id",
                    "attribute.repository_id": "assertion.repository_id",
                    "attribute.repository_owner_id": "assertion.repository_owner_id",
                    "attribute.ref": "assertion.ref",
                    "attribute.workflow_ref": "assertion.workflow_ref",
                    "attribute.workflow_sha": "assertion.workflow_sha",
                    "attribute.environment": "assertion.environment",
                    "attribute.event_name": "assertion.event_name",
                    "attribute.repository_visibility": "assertion.repository_visibility",
                    "attribute.runner_environment": "assertion.runner_environment",
                },
                "attribute_condition": " && ".join(
                    [
                        "assertion.sub == 'repo:mindclade@316676129/bootstrap@1350991612:environment:trusted-build:workflow_ref:mindclade/bootstrap/.github/workflows/protected-apply.yml@refs/heads/main:workflow_sha:' + assertion.workflow_sha",
                        "assertion.repository == 'mindclade/bootstrap'",
                        "assertion.repository_owner == 'mindclade'",
                        "assertion.repository_id == '1350991612'",
                        "assertion.repository_owner_id == '316676129'",
                        "assertion.repository_visibility == 'public'",
                        "assertion.ref == 'refs/heads/main'",
                        "assertion.workflow_ref == 'mindclade/bootstrap/.github/workflows/protected-apply.yml@refs/heads/main'",
                        "assertion.workflow_sha == assertion.sha",
                        "assertion.event_name == 'workflow_dispatch'",
                        "assertion.environment == 'trusted-build'",
                        "assertion.runner_environment == 'self-hosted'",
                    ]
                ),
                "oidc": [
                    {
                        "issuer_uri": "https://token.actions.githubusercontent.com",
                        "allowed_audiences": ["sts.googleapis.com"],
                    }
                ],
            },
        )
        provider["address"] = (
            'module.github_federation.google_iam_workload_identity_pool_provider.github["plan"]'
        )
        service_account = self.resource(
            "google_service_account",
            ["create"],
            {
                "project": "bootstrap-state-root",
                "account_id": "bootstrap-plan",
                "disabled": False,
            },
        )
        service_account["address"] = (
            'module.github_federation.google_service_account.github["plan"]'
        )
        binding = self.resource(
            "google_service_account_iam_member",
            ["create"],
            {
                "service_account_id": (
                    "projects/bootstrap-state-root/serviceAccounts/"
                    "bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com"
                ),
                "role": "roles/iam.workloadIdentityUser",
                "member": (
                    "principalSet://iam.googleapis.com/projects/123456789/"
                    "locations/global/workloadIdentityPools/bootstrap-github-plan/"
                    "attribute.repository_id/1350991612"
                ),
            },
        )
        binding["address"] = (
            'module.github_federation.google_service_account_iam_member.github["plan"]'
        )
        return [identity, state, pool, provider, service_account, binding]

    def ci_evidence_identity_resources(self):
        identity = self.project_resource("identity", "bootstrap-identity")
        pool = self.resource(
            "google_iam_workload_identity_pool",
            ["create"],
            {
                "project": "bootstrap-identity",
                "workload_identity_pool_id": "github-ci-evidence",
                "name": (
                    "projects/123456789/locations/global/workloadIdentityPools/github-ci-evidence"
                ),
                "disabled": False,
            },
        )
        pool["address"] = (
            'module.github_federation.google_iam_workload_identity_pool.ci_evidence["archive"]'
        )
        repository_ids = (
            "['1350980188', '1350986053', '1350991612', '1350991963', '1350992171', '1351193819']"
        )
        workflow_sha = "a" * 40
        recovery_sha = "b" * 40
        conditions = {
            "writer": " && ".join(
                [
                    "assertion.repository_owner_id == '316676129'",
                    f"assertion.repository_id in {repository_ids}",
                    "assertion.repository_visibility == 'public'",
                    "assertion.runner_environment == 'github-hosted'",
                    (
                        "assertion.job_workflow_ref == "
                        "'mindclade/.github/.github/workflows/"
                        f"reusable-required-check.yml@{workflow_sha}'"
                    ),
                    f"assertion.job_workflow_sha == '{workflow_sha}'",
                    (
                        "((assertion.event_name == 'push' && "
                        "assertion.ref == 'refs/heads/main') || "
                        "(assertion.event_name == 'release' && "
                        "assertion.ref.startsWith('refs/tags/v')))"
                    ),
                ]
            ),
            "verifier": " && ".join(
                [
                    "assertion.repository_owner_id == '316676129'",
                    "assertion.repository_id == '1350992171'",
                    "assertion.repository_visibility == 'public'",
                    "assertion.runner_environment == 'github-hosted'",
                    (
                        "assertion.workflow_ref == "
                        "'mindclade/infrastructure-live/.github/workflows/"
                        "disaster-recovery.yml@refs/heads/main'"
                    ),
                    f"assertion.workflow_sha == '{recovery_sha}'",
                    "assertion.ref == 'refs/heads/main'",
                    "assertion.event_name == 'workflow_dispatch'",
                    "assertion.environment == 'infrastructure-apply'",
                ]
            ),
        }
        resources = [identity, pool]
        for role in ("writer", "verifier"):
            mapping = {
                "google.subject": (f"'ci-evidence-{role}:' + assertion.repository_id"),
                "attribute.evidence_role": f"'{role}'",
                "attribute.repository_id": "assertion.repository_id",
                "attribute.repository_owner_id": "assertion.repository_owner_id",
                "attribute.ref": "assertion.ref",
                "attribute.event_name": "assertion.event_name",
                "attribute.repository_visibility": "assertion.repository_visibility",
                "attribute.runner_environment": "assertion.runner_environment",
            }
            if role == "writer":
                mapping.update(
                    {
                        "attribute.job_workflow_ref": "assertion.job_workflow_ref",
                        "attribute.job_workflow_sha": "assertion.job_workflow_sha",
                    }
                )
            else:
                mapping.update(
                    {
                        "attribute.workflow_ref": "assertion.workflow_ref",
                        "attribute.workflow_sha": "assertion.workflow_sha",
                        "attribute.environment": "assertion.environment",
                    }
                )
            provider = self.resource(
                "google_iam_workload_identity_pool_provider",
                ["create"],
                {
                    "project": "bootstrap-identity",
                    "workload_identity_pool_id": "github-ci-evidence",
                    "workload_identity_pool_provider_id": role,
                    "disabled": False,
                    "attribute_mapping": mapping,
                    "attribute_condition": conditions[role],
                    "oidc": [
                        {
                            "issuer_uri": "https://token.actions.githubusercontent.com",
                            "allowed_audiences": [],
                        }
                    ],
                },
            )
            provider["address"] = (
                "module.github_federation.google_iam_workload_identity_pool_provider."
                f'ci_evidence["{role}"]'
            )
            account_id = f"ci-evidence-{role}"
            service_account = self.resource(
                "google_service_account",
                ["create"],
                {
                    "project": "bootstrap-identity",
                    "account_id": account_id,
                    "disabled": False,
                },
            )
            service_account["address"] = (
                f'module.github_federation.google_service_account.ci_evidence["{role}"]'
            )
            binding = self.resource(
                "google_service_account_iam_member",
                ["create"],
                {
                    "service_account_id": (
                        "projects/bootstrap-identity/serviceAccounts/"
                        f"{account_id}@bootstrap-identity.iam.gserviceaccount.com"
                    ),
                    "role": "roles/iam.workloadIdentityUser",
                    "member": (
                        "principalSet://iam.googleapis.com/projects/123456789/"
                        "locations/global/workloadIdentityPools/github-ci-evidence/"
                        f"attribute.evidence_role/{role}"
                    ),
                },
            )
            binding["address"] = (
                f'module.github_federation.google_service_account_iam_member.ci_evidence["{role}"]'
            )
            resources.extend([provider, service_account, binding])
        return resources

    def infrastructure_identity_resources(self, identity="production-apply"):
        environment, role = identity.split("-")
        execution_environment = "trusted-build" if role == "plan" else "infrastructure-apply"
        project = self.project_resource("identity", "bootstrap-identity")
        pool = self.resource(
            "google_iam_workload_identity_pool",
            ["create"],
            {
                "project": "bootstrap-identity",
                "workload_identity_pool_id": "infrastructure-live",
                "name": (
                    "projects/123456789/locations/global/workloadIdentityPools/infrastructure-live"
                ),
                "disabled": False,
            },
        )
        pool["address"] = (
            'module.github_federation.google_iam_workload_identity_pool.infrastructure_live["pool"]'
        )
        workflow = (
            "mindclade/infrastructure-live/.github/workflows/protected-apply.yml@refs/heads/main"
        )
        immutable_repository = "mindclade@316676129/infrastructure-live@1350992171"
        condition = " && ".join(
            [
                (
                    "assertion.sub == 'repo:"
                    f"{immutable_repository}:environment:"
                    f"{execution_environment}:workflow_ref:{workflow}:workflow_sha:' "
                    "+ assertion.workflow_sha"
                ),
                "assertion.repository == 'mindclade/infrastructure-live'",
                "assertion.repository_owner == 'mindclade'",
                "assertion.repository_owner_id == '316676129'",
                "assertion.repository_id == '1350992171'",
                "assertion.repository_visibility == 'public'",
                "assertion.ref == 'refs/heads/main'",
                f"assertion.workflow_ref == '{workflow}'",
                "assertion.workflow_sha == assertion.sha",
                "assertion.event_name == 'workflow_dispatch'",
                f"assertion.environment == '{execution_environment}'",
                "assertion.runner_environment == 'github-hosted'",
            ]
        )
        provider = self.resource(
            "google_iam_workload_identity_pool_provider",
            ["create"],
            {
                "project": "bootstrap-identity",
                "workload_identity_pool_id": "infrastructure-live",
                "workload_identity_pool_provider_id": identity,
                "disabled": False,
                "attribute_mapping": {
                    "google.subject": (
                        f"'infrastructure-live-{identity}:' + assertion.repository_id"
                    ),
                    "attribute.infrastructure_identity": f"'{identity}'",
                    "attribute.repository_id": "assertion.repository_id",
                    "attribute.repository_owner_id": "assertion.repository_owner_id",
                    "attribute.workflow_ref": "assertion.workflow_ref",
                    "attribute.workflow_sha": "assertion.workflow_sha",
                    "attribute.environment": "assertion.environment",
                },
                "attribute_condition": condition,
                "oidc": [
                    {
                        "issuer_uri": "https://token.actions.githubusercontent.com",
                        "allowed_audiences": [
                            "https://github.mindclade.io/oidc/infrastructure-live/"
                            f"{environment}/{role}"
                        ],
                    }
                ],
            },
        )
        provider["address"] = (
            "module.github_federation.google_iam_workload_identity_pool_provider."
            f'infrastructure_live["{identity}"]'
        )
        service = self.resource(
            "google_service_account",
            ["create"],
            {
                "project": "bootstrap-identity",
                "account_id": identity,
                "disabled": False,
            },
        )
        service["address"] = (
            f'module.github_federation.google_service_account.infrastructure_live["{identity}"]'
        )
        binding = self.resource(
            "google_service_account_iam_member",
            ["create"],
            {
                "service_account_id": (
                    "projects/bootstrap-identity/serviceAccounts/"
                    f"{identity}@bootstrap-identity.iam.gserviceaccount.com"
                ),
                "role": "roles/iam.workloadIdentityUser",
                "member": (
                    "principalSet://iam.googleapis.com/projects/123456789/"
                    "locations/global/workloadIdentityPools/infrastructure-live/"
                    f"attribute.infrastructure_identity/{identity}"
                ),
            },
        )
        binding["address"] = (
            "module.github_federation.google_service_account_iam_member."
            f'infrastructure_live["{identity}"]'
        )
        return [project, pool, provider, service, binding]

    def test_protected_state_resource_is_accepted(self):
        resource = self.resource(
            "google_storage_bucket",
            ["create"],
            {
                "project": "bootstrap-state-root",
                "name": "bootstrap-primary-state",
                "location": "US-CENTRAL1",
                "storage_class": "STANDARD",
                "uniform_bucket_level_access": True,
                "public_access_prevention": "enforced",
                "force_destroy": False,
                "versioning": [{"enabled": True}],
                "encryption": [{"default_kms_key_name": "kms-key"}],
                "soft_delete_policy": [{"retention_duration_seconds": 2592000}],
                "lifecycle_rule": [
                    {
                        "action": [{"type": "Delete"}],
                        "condition": [
                            {
                                "days_since_noncurrent_time": 365,
                                "num_newer_versions": 3,
                                "send_age_if_zero": False,
                            }
                        ],
                    }
                ],
            },
        )
        resource["address"] = 'module.root_state.google_storage_bucket.state["primary"]'
        result = self.check_plan([resource])
        self.assertEqual(result.returncode, 0, result.stderr)

        resource["change"]["after"]["lifecycle_rule"][0]["condition"][0]["num_newer_versions"] = 2
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("preserving the three newest generations", result.stderr)

        resource["change"]["after"]["lifecycle_rule"][0]["condition"][0]["num_newer_versions"] = 3
        resource["change"]["after"]["lifecycle_rule"].append(
            json.loads(json.dumps(resource["change"]["after"]["lifecycle_rule"][0]))
        )
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one explicit", result.stderr)

    def test_primitive_role_is_rejected(self):
        result = self.check_plan(
            [self.resource("google_project_iam_member", ["create"], {"role": "roles/owner"})]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("primitive role", result.stderr)

    def test_service_account_key_is_rejected(self):
        result = self.check_plan(
            [self.resource("google_service_account_key", ["create"], {"service_account_id": "x"})]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("prohibited Ring-0 resource type", result.stderr)

    def test_delete_or_replace_is_rejected(self):
        for actions in (["delete"], ["delete", "create"]):
            with self.subTest(actions=actions):
                result = self.check_plan([self.resource("google_storage_bucket", actions, None)])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must not delete or replace", result.stderr)

    def test_downstream_platform_resource_is_rejected(self):
        result = self.check_plan(
            [self.resource("google_container_node_pool", ["create"], {"name": "forbidden"})]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("prohibited Ring-0 resource type", result.stderr)

    def test_missing_resource_changes_fails_closed(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
            json.dump({}, handle)
            handle.flush()
            result = subprocess.run(
                [str(self.bootstrapctl), "plan-resource-check", "--plan", handle.name],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resource_changes must be an array", result.stderr)

    def test_empty_resource_fragment_remains_valid_for_diagnostics(self):
        result = self.check_plan([])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_root_plan_fails_closed(self):
        result = self.check_root_plan([], "root-trust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configured Ring-0 resources", result.stderr)

    def test_root_aware_check_rejects_partial_and_wrong_compositions(self):
        resource = self.resource(
            "google_organization_iam_member",
            ["no-op"],
            {
                "org_id": "123456789",
                "role": "roles/logging.configWriter",
                "member": "group:root-trust-administrators@example.com",
            },
        )
        resource["address"] = "google_organization_iam_member.apply_logging_config_writer"

        result = self.check_root_plan([resource], "root-trust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("including when it is no-op", result.stderr)

        result = self.check_root_plan([resource], "recovery-plane")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong composition", result.stderr)

        result = self.check_root_plan([resource], "unreviewed-root")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported Ring-0 composition", result.stderr)

    def test_complete_recovery_plane_noop_inventory_is_accepted(self):
        resources = self.complete_recovery_plane_resources()
        result = self.run_plan_document(
            "plan-check",
            self.strict_recovery_document(resources),
            "--root",
            "recovery-plane",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        removed = resources.pop()
        result = self.run_plan_document(
            "plan-check",
            self.strict_recovery_document(resources),
            "--root",
            "recovery-plane",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(removed["address"], result.stderr)

    def test_recovery_plane_rejects_resource_values_outside_compiled_inputs(self):
        resources = self.complete_recovery_plane_resources()
        document = self.strict_recovery_document(resources)
        document["variables"]["recovery"]["value"]["export_key_name"] = "unreviewed-export-key"
        result = self.run_plan_document("plan-check", document, "--root", "recovery-plane")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compiled key name and key ring", result.stderr)

    def test_standing_project_creator_and_billing_user_are_rejected(self):
        resources = (
            self.resource(
                "google_organization_iam_member",
                ["create"],
                {
                    "org_id": "123456789",
                    "role": "roles/resourcemanager.projectCreator",
                    "member": "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com",
                },
            ),
            self.resource(
                "google_billing_account_iam_member",
                ["create"],
                {
                    "billing_account_id": "ABCDEF-123456-ABCDEF",
                    "role": "roles/billing.user",
                    "member": "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com",
                },
            ),
        )
        resources[0]["address"] = "google_organization_iam_member.apply_project_creator"
        resources[1]["address"] = "google_billing_account_iam_member.apply_billing_user"
        for resource in resources:
            with self.subTest(address=resource["address"]):
                result = self.check_plan([resource])
                self.assertNotEqual(result.returncode, 0)

    def test_unknown_iam_role_fails_closed(self):
        resource = self.resource(
            "google_project_iam_member",
            ["create"],
            {"project": "state-root", "role": None, "member": "group:security@example.com"},
        )
        resource["change"]["after_unknown"] = {"role": True}
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown security-relevant", result.stderr)

    def test_literal_secret_resource_is_rejected(self):
        result = self.check_plan(
            [
                self.resource(
                    "google_secret_manager_secret_version",
                    ["create"],
                    {"secret_data": "not-a-real-secret"},
                )
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the Ring-0 allowlist", result.stderr)
        self.assertIn("static credential field", result.stderr)

    def test_insecure_state_bucket_is_rejected(self):
        result = self.check_plan(
            [
                self.resource(
                    "google_storage_bucket",
                    ["create"],
                    {
                        "uniform_bucket_level_access": False,
                        "public_access_prevention": "inherited",
                        "force_destroy": True,
                        "versioning": [{"enabled": False}],
                        "encryption": [],
                        "soft_delete_policy": [],
                    },
                )
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must enable bucket versioning", result.stderr)
        self.assertIn("must use a default CMEK", result.stderr)

    def test_only_exact_bucket_addresses_may_defer_computed_cmek(self):
        for address, accepted in (
            ('module.root_state.google_storage_bucket.state["primary"]', True),
            ('module.unreviewed.google_storage_bucket.state["primary"]', False),
        ):
            with self.subTest(address=address):
                resource = self.resource(
                    "google_storage_bucket",
                    ["create"],
                    {
                        "project": "bootstrap-state-root",
                        "name": "bootstrap-primary-state",
                        "location": "US-CENTRAL1",
                        "storage_class": "STANDARD",
                        "uniform_bucket_level_access": True,
                        "public_access_prevention": "enforced",
                        "force_destroy": False,
                        "versioning": [{"enabled": True}],
                        "encryption": [{"default_kms_key_name": None}],
                        "soft_delete_policy": [{"retention_duration_seconds": 2592000}],
                        "lifecycle_rule": [
                            {
                                "action": [{"type": "Delete"}],
                                "condition": [
                                    {
                                        "days_since_noncurrent_time": 365,
                                        "num_newer_versions": 3,
                                        "send_age_if_zero": False,
                                    }
                                ],
                            }
                        ],
                    },
                )
                resource["address"] = address
                resource["change"]["after_unknown"] = {
                    "encryption": [{"default_kms_key_name": True}]
                }
                result = self.check_plan([resource])
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_nested_unknown_role_fails_closed(self):
        resource = self.resource(
            "google_privileged_access_manager_entitlement",
            ["create"],
            {"entitlement_id": "break-glass"},
        )
        resource["change"]["after_unknown"] = {"wrapper": [{"role": True}]}
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown security-relevant", result.stderr)

    def test_software_kms_key_is_rejected(self):
        result = self.check_plan(
            [
                self.resource(
                    "google_kms_crypto_key",
                    ["create"],
                    {
                        "purpose": "ENCRYPT_DECRYPT",
                        "rotation_period": "7776000s",
                        "destroy_scheduled_duration": "2592000s",
                        "version_template": [
                            {
                                "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                                "protection_level": "SOFTWARE",
                            }
                        ],
                    },
                )
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HSM-protected", result.stderr)

    def test_unapproved_admin_role_is_rejected(self):
        result = self.check_plan(
            [
                self.resource(
                    "google_organization_iam_member",
                    ["create"],
                    {
                        "org_id": "123456789",
                        "role": "roles/resourcemanager.organizationAdmin",
                        "member": "group:platform@example.com",
                    },
                )
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the Ring-0 allowlist", result.stderr)

    def test_approved_role_at_unapproved_scope_is_rejected(self):
        result = self.check_plan(
            [
                self.resource(
                    "google_service_account_iam_member",
                    ["create"],
                    {
                        "service_account_id": "bootstrap@example.invalid",
                        "role": "roles/cloudkms.admin",
                        "member": "group:security@example.invalid",
                    },
                )
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside its approved Ring-0 scope", result.stderr)

    def test_tautological_workload_condition_is_rejected(self):
        resource = self.resource(
            "google_iam_workload_identity_pool_provider",
            ["create"],
            {
                "attribute_condition": "true || assertion.sub == '*'",
                "attribute_mapping": {"google.subject": "assertion.sub"},
                "oidc": [
                    {
                        "issuer_uri": "https://issuer.example.com",
                        "allowed_audiences": ["bootstrap"],
                    }
                ],
            },
        )
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fail-closed attribute condition", result.stderr)

    def test_embedded_secret_object_is_rejected(self):
        result = self.check_plan(
            [
                self.resource(
                    "google_storage_bucket_object",
                    ["create"],
                    {"content": json.dumps({"password": "not-a-real-secret"})},
                )
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("static credential field password", result.stderr)

    def test_unknown_member_exception_name_cannot_be_spoofed(self):
        resource = self.resource(
            "google_project_iam_member",
            ["create"],
            {"project": "audit-root", "role": "roles/logging.bucketWriter", "member": None},
        )
        resource["address"] = "module.test.google_project_iam_member.sink_writer_backdoor"
        resource["change"]["after_unknown"] = {"member": True}
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown security-relevant", result.stderr)

    def test_unknown_target_project_fails_closed(self):
        resource = self.resource(
            "google_project_iam_member",
            ["create"],
            {
                "project": None,
                "role": "roles/logging.viewer",
                "member": "group:security@example.com",
            },
        )
        resource["change"]["after_unknown"] = {"project": True}
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown security-relevant", result.stderr)

    def test_replication_predefined_roles_are_limited_to_exact_instances(self):
        state_project = self.project_resource("root_state", "bootstrap-state-root")
        approved = {
            "roles/iam.roleViewer": (
                'google_project_iam_member.plan_read["state:roles/iam.roleViewer"]'
            ),
            "roles/storagetransfer.viewer": (
                'google_project_iam_member.plan_read["state:roles/storagetransfer.viewer"]'
            ),
        }
        for role, address in approved.items():
            with self.subTest(role=role, address=address):
                resource = self.resource(
                    "google_project_iam_member",
                    ["create"],
                    {
                        "project": "bootstrap-state-root",
                        "role": role,
                        "member": (
                            "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com"
                            if ".plan_read" in address
                            else "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com"
                        ),
                    },
                )
                resource["address"] = address
                result = self.check_plan([state_project, resource])
                self.assertEqual(result.returncode, 0, result.stderr)

                resource["address"] = address.replace('"state:', '"audit:')
                result = self.check_plan([state_project, resource])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("outside its approved Ring-0 scope", result.stderr)

                resource["address"] = "google_project_iam_member.workload_read"
                result = self.check_plan([state_project, resource])
                self.assertNotEqual(result.returncode, 0)

        for role in ("roles/iam.roleAdmin", "roles/storagetransfer.user"):
            with self.subTest(role=role, standing_apply=True):
                resource = self.resource(
                    "google_project_iam_member",
                    ["create"],
                    {
                        "project": "bootstrap-state-root",
                        "role": role,
                        "member": (
                            "serviceAccount:bootstrap-apply@bootstrap-state-root."
                            "iam.gserviceaccount.com"
                        ),
                    },
                )
                resource["address"] = (
                    f'google_project_iam_member.apply_administration["state:{role}"]'
                )
                result = self.check_plan([state_project, resource])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("outside", result.stderr)

    def test_every_compiler_declared_apply_and_plan_project_role_is_accepted(self):
        administration = {
            "identity": (
                "roles/iam.workloadIdentityPoolAdmin",
                "roles/privilegedaccessmanager.admin",
                "roles/resourcemanager.projectIamAdmin",
                "roles/serviceusage.serviceUsageAdmin",
            ),
            "audit": (
                "roles/cloudkms.admin",
                "roles/resourcemanager.projectIamAdmin",
                "roles/serviceusage.serviceUsageAdmin",
            ),
        }
        reads = {
            "identity": (
                "roles/browser",
                "roles/iam.securityReviewer",
                "roles/iam.serviceAccountViewer",
                "roles/iam.workloadIdentityPoolViewer",
                "roles/privilegedaccessmanager.viewer",
                "roles/serviceusage.serviceUsageViewer",
            ),
            "state": (
                "roles/browser",
                "roles/cloudkms.viewer",
                "roles/iam.roleViewer",
                "roles/iam.securityReviewer",
                "roles/iam.serviceAccountViewer",
                "roles/privilegedaccessmanager.viewer",
                "roles/serviceusage.serviceUsageViewer",
                "roles/storagetransfer.viewer",
            ),
            "recovery": (
                "roles/browser",
                "roles/cloudkms.viewer",
                "roles/iam.roleViewer",
                "roles/iam.securityReviewer",
                "roles/iam.serviceAccountViewer",
                "roles/iam.workloadIdentityPoolViewer",
                "roles/privilegedaccessmanager.viewer",
                "roles/serviceusage.serviceUsageViewer",
                "roles/storagetransfer.viewer",
            ),
            "audit": (
                "roles/browser",
                "roles/cloudkms.viewer",
                "roles/iam.securityReviewer",
                "roles/serviceusage.serviceUsageViewer",
            ),
            "signing": (
                "roles/browser",
                "roles/cloudkms.publicKeyViewer",
                "roles/cloudkms.viewer",
                "roles/iam.roleViewer",
                "roles/iam.securityReviewer",
                "roles/privilegedaccessmanager.viewer",
                "roles/serviceusage.serviceUsageViewer",
            ),
        }
        project_ids = {
            "identity": "bootstrap-identity",
            "state": "bootstrap-state-root",
            "recovery": "bootstrap-recovery",
            "audit": "bootstrap-audit",
            "signing": "bootstrap-signing",
        }
        project_logicals = {
            "identity": "identity",
            "state": "root_state",
            "recovery": "recovery",
            "audit": "audit",
            "signing": "signing",
        }
        resources = [
            self.project_resource(project_logicals[key], project_id)
            for key, project_id in project_ids.items()
        ]
        for name, role_sets, member in (
            (
                "apply_administration",
                administration,
                "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com",
            ),
            (
                "plan_read",
                reads,
                "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com",
            ),
        ):
            for logical, roles in role_sets.items():
                for role in roles:
                    resource = self.resource(
                        "google_project_iam_member",
                        ["create"],
                        {
                            "project": project_ids[logical],
                            "role": role,
                            "member": member,
                        },
                    )
                    resource["address"] = f'google_project_iam_member.{name}["{logical}:{role}"]'
                    resources.append(resource)
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_key_viewer_is_limited_to_the_plan_identity_signing_project(self):
        signing_project = self.project_resource("signing", "bootstrap-signing")
        binding = self.resource(
            "google_project_iam_member",
            ["create"],
            {
                "project": "bootstrap-signing",
                "role": "roles/cloudkms.publicKeyViewer",
                "member": (
                    "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com"
                ),
            },
        )
        binding["address"] = (
            'google_project_iam_member.plan_read["signing:roles/cloudkms.publicKeyViewer"]'
        )
        result = self.check_plan([signing_project, binding])
        self.assertEqual(result.returncode, 0, result.stderr)

        mutations = (
            (
                "apply-member",
                lambda value: value[1]["change"]["after"].update(
                    {
                        "member": (
                            "serviceAccount:bootstrap-apply@bootstrap-state-root."
                            "iam.gserviceaccount.com"
                        )
                    }
                ),
            ),
            (
                "state-project",
                lambda value: (
                    value[1].update(
                        {
                            "address": (
                                "google_project_iam_member.plan_read["
                                '"state:roles/cloudkms.publicKeyViewer"]'
                            )
                        }
                    ),
                    value[1]["change"]["after"].update({"project": "bootstrap-state-root"}),
                ),
            ),
            (
                "apply-address",
                lambda value: value[1].update(
                    {
                        "address": (
                            "google_project_iam_member.apply_administration["
                            '"signing:roles/cloudkms.publicKeyViewer"]'
                        )
                    }
                ),
            ),
            (
                "signer-role",
                lambda value: (
                    value[1].update(
                        {
                            "address": (
                                "google_project_iam_member.plan_read["
                                '"signing:roles/cloudkms.signerVerifier"]'
                            )
                        }
                    ),
                    value[1]["change"]["after"].update({"role": "roles/cloudkms.signerVerifier"}),
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                resources = copy.deepcopy([signing_project, binding])
                mutate(resources)
                result = self.check_plan(resources)
                self.assertNotEqual(result.returncode, 0)

    def test_replication_custom_roles_exact_permissions_are_accepted(self):
        contracts = {
            "source_bucket": (
                "bootstrapStateReplicationSource",
                [
                    "storage.buckets.get",
                    "storage.buckets.update",
                    "storage.objects.get",
                ],
            ),
            "destination_bucket": (
                "bootstrapStateReplicationDestination",
                [
                    "storage.buckets.get",
                    "storage.objects.create",
                    "storage.objects.get",
                ],
            ),
            "transfer_events": (
                "bootstrapStateReplicationTransferEvents",
                [
                    "pubsub.subscriptions.consume",
                    "pubsub.subscriptions.create",
                    "pubsub.topics.create",
                ],
            ),
            "storage_events": (
                "bootstrapStateReplicationStorageEvents",
                [
                    "pubsub.subscriptions.consume",
                    "pubsub.subscriptions.create",
                    "pubsub.topics.publish",
                ],
            ),
        }
        resources = [
            self.replication_custom_role("module.root_state", instance, role_id, permissions)
            for instance, (role_id, permissions) in contracts.items()
        ]
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_replication_custom_role_scope_stage_and_permissions_fail_closed(self):
        permissions = [
            "storage.buckets.get",
            "storage.buckets.update",
            "storage.objects.get",
        ]
        mutations = (
            (
                "address",
                'module.root_state.google_project_iam_custom_role.replication["source_bucket_backdoor"]',
            ),
            ("role_id", "bootstrapStateReplicationDestination"),
            ("stage", "BETA"),
            ("permissions", [*permissions, "storage.objects.delete"]),
            ("permissions", permissions[:-1]),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                resource = self.replication_custom_role(
                    "module.root_state",
                    "source_bucket",
                    "bootstrapStateReplicationSource",
                    permissions,
                )
                if field == "address":
                    resource["address"] = value
                else:
                    resource["change"]["after"][field] = value
                result = self.check_plan([resource])
                self.assertNotEqual(result.returncode, 0)

    def test_recovery_administration_is_one_group_on_exact_project_and_roles(self):
        project = self.resource(
            "google_project",
            ["create"],
            {
                "project_id": "bootstrap-recovery",
                "name": "bootstrap-recovery",
                "org_id": "123456789",
                "billing_account": "ABCDEF-123456-ABCDEF",
                "auto_create_network": False,
                "deletion_policy": "PREVENT",
            },
        )
        project["address"] = 'google_project.state["recovery"]'
        roles = (
            "roles/cloudkms.admin",
            "roles/iam.roleAdmin",
            "roles/iam.serviceAccountAdmin",
            "roles/logging.admin",
            "roles/resourcemanager.projectIamAdmin",
            "roles/serviceusage.serviceUsageAdmin",
            "roles/storage.admin",
            "roles/storagetransfer.user",
        )
        bindings = []
        for role in roles:
            binding = self.resource(
                "google_project_iam_member",
                ["create"],
                {
                    "project": "bootstrap-recovery",
                    "role": role,
                    "member": "group:recovery-admins@example.com",
                },
            )
            binding["address"] = f'google_project_iam_member.recovery_administration["{role}"]'
            bindings.append(binding)
        result = self.check_plan([project, *bindings])
        self.assertEqual(result.returncode, 0, result.stderr)

        variables = self.initial_signing_create_document()["variables"]
        bootstrap = variables["bootstrap"]["value"]
        bootstrap.update(
            {
                "organization_id": "123456789",
                "billing_account": "ABCDEF-123456-ABCDEF",
                "projects": {},
                "recovery_administrator_principal": ("group:recovery-admins@example.com"),
            }
        )
        declarations = {
            key: value["versions"] for key, value in bootstrap["signing"]["keys"].items()
        }
        strict_document = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": [project, *bindings],
            "configuration": {
                "provider_config": {
                    "google": {
                        "name": "google",
                        "full_name": "registry.opentofu.org/hashicorp/google",
                    }
                },
                "root_module": {},
            },
            "variables": variables,
            "output_changes": {
                "signing_version_declarations": {
                    "actions": ["create"],
                    "before": None,
                    "after": declarations,
                    "after_unknown": {},
                }
            },
        }
        diagnostic = (
            "recovery-administration bindings must exactly equal the single "
            "compiled recovery-administrator group"
        )
        result = self.run_plan_document("plan-check", strict_document, "--root", "root-trust")
        self.assertNotIn(diagnostic, result.stderr)
        for binding in bindings:
            binding["change"]["after"]["member"] = "group:unreviewed-recovery-admins@example.com"
        result = self.run_plan_document("plan-check", strict_document, "--root", "root-trust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(diagnostic, result.stderr)
        for binding in bindings:
            binding["change"]["after"]["member"] = "group:recovery-admins@example.com"

        bindings[0]["change"]["after"]["project"] = "bootstrap-audit"
        result = self.check_plan([project, *bindings])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only the declared recovery project", result.stderr)

        bindings[0]["change"]["after"]["project"] = "bootstrap-recovery"
        bindings[0]["change"]["after"]["member"] = (
            "serviceAccount:bootstrap-apply@bootstrap-state.iam.gserviceaccount.com"
        )
        result = self.check_plan([project, *bindings])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recovery-administrator group email", result.stderr)

        bindings[0]["change"]["after"]["member"] = "group:recovery-admins@example.com"
        result = self.check_plan([project, *bindings[:-1]])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact recovery-administration role set", result.stderr)

    def test_nonexistent_service_account_iam_admin_role_is_rejected(self):
        resource = self.resource(
            "google_project_iam_member",
            ["create"],
            {
                "project": "bootstrap-recovery",
                "role": "roles/iam.serviceAccountIamAdmin",
                "member": "group:recovery-admins@example.com",
            },
        )
        resource["address"] = (
            "google_project_iam_member.apply_administration"
            '["recovery:roles/iam.serviceAccountIamAdmin"]'
        )
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the Ring-0 allowlist", result.stderr)

    def test_recovery_plan_read_role_and_bucket_scope_are_exact(self):
        metadata_role = self.resource(
            "google_project_iam_custom_role",
            ["create"],
            {
                "project": "bootstrap-recovery",
                "role_id": "bootstrapRecoveryPlanRead",
                "permissions": [
                    "storage.buckets.get",
                    "storage.buckets.getIamPolicy",
                ],
                "stage": "GA",
                "deleted": False,
            },
        )
        metadata_role["address"] = (
            "module.recovery_exports.google_project_iam_custom_role.plan_read"
        )
        object_role = self.resource(
            "google_project_iam_custom_role",
            ["create"],
            {
                "project": "bootstrap-recovery",
                "role_id": "bootstrapRecoveryPlanObjectRead",
                "permissions": ["storage.objects.get"],
                "stage": "GA",
                "deleted": False,
            },
        )
        object_role["address"] = (
            "module.recovery_exports.google_project_iam_custom_role.plan_object_read"
        )
        bindings = []
        objects = {
            "exports": "restore/inventory.json",
            "evidence": "trust/public-trust-metadata.json",
        }
        for bucket, object_name in objects.items():
            bucket_name = f"bootstrap-recovery-recovery-{bucket}"
            metadata_binding = self.resource(
                "google_storage_bucket_iam_member",
                ["create"],
                {
                    "bucket": bucket_name,
                    "role": "projects/bootstrap-recovery/roles/bootstrapRecoveryPlanRead",
                    "member": "serviceAccount:bootstrap-plan@bootstrap-identity.iam.gserviceaccount.com",
                    "condition": [],
                },
            )
            metadata_binding["address"] = (
                f'module.recovery_exports.google_storage_bucket_iam_member.plan_read["{bucket}"]'
            )
            bindings.append(metadata_binding)

            object_binding = self.resource(
                "google_storage_bucket_iam_member",
                ["create"],
                {
                    "bucket": bucket_name,
                    "role": "projects/bootstrap-recovery/roles/bootstrapRecoveryPlanObjectRead",
                    "member": "serviceAccount:bootstrap-plan@bootstrap-identity.iam.gserviceaccount.com",
                    "condition": [
                        {
                            "title": f"read-{bucket}-declared-object-only",
                            "expression": (
                                "resource.type == 'storage.googleapis.com/Object' "
                                "&& resource.name == "
                                f"'projects/_/buckets/{bucket_name}/objects/{object_name}'"
                            ),
                        }
                    ],
                },
            )
            object_binding["address"] = (
                "module.recovery_exports.google_storage_bucket_iam_member."
                f'plan_object_read["{bucket}"]'
            )
            bindings.append(object_binding)
        result = self.check_plan([metadata_role, object_role, *bindings])
        self.assertEqual(result.returncode, 0, result.stderr)

        bindings[0]["change"]["after"]["member"] = "group:platform@example.com"
        result = self.check_plan([metadata_role, object_role, *bindings])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compiler-derived bootstrap-plan", result.stderr)

        bindings[0]["change"]["after"]["member"] = (
            "serviceAccount:bootstrap-plan@bootstrap-identity.iam.gserviceaccount.com"
        )
        metadata_role["change"]["after"]["permissions"].append("storage.objects.list")
        result = self.check_plan([metadata_role, object_role, *bindings])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions must exactly match", result.stderr)

    def test_state_backend_plan_access_distinguishes_primary_and_replica(self):
        plan_lock_role = self.resource(
            "google_project_iam_custom_role",
            ["create"],
            {
                "project": "bootstrap-state-root",
                "role_id": "bootstrapStatePlanLock",
                "permissions": [
                    "storage.objects.create",
                    "storage.objects.delete",
                    "storage.objects.get",
                    "storage.objects.update",
                ],
                "stage": "GA",
                "deleted": False,
            },
        )
        plan_lock_role["address"] = "module.root_state.google_project_iam_custom_role.plan_lock"
        plan_access = {
            "primary-plan-state": (
                "bootstrap-primary-state",
                "roles/storage.objectViewer",
                "bootstrap-plan-primary-state-read",
                "root-trust/default.tfstate",
            ),
            "primary-plan-metadata": (
                "bootstrap-primary-state",
                "roles/storage.legacyBucketReader",
                None,
                None,
            ),
            "primary-plan-lock": (
                "bootstrap-primary-state",
                "projects/bootstrap-state-root/roles/bootstrapStatePlanLock",
                "bootstrap-plan-primary-lock",
                "root-trust/default.tflock",
            ),
            "replica-plan-state": (
                "bootstrap-replica-state",
                "roles/storage.objectViewer",
                "bootstrap-plan-replica-state-read",
                "root-trust/default.tfstate",
            ),
            "replica-plan-metadata": (
                "bootstrap-replica-state",
                "roles/storage.legacyBucketReader",
                None,
                None,
            ),
            "primary-recovery": (
                "bootstrap-primary-state",
                "roles/storage.objectViewer",
                "bootstrap-recovery-primary-state-read",
                "root-trust/default.tfstate",
            ),
            "primary-recovery-metadata": (
                "bootstrap-primary-state",
                "roles/storage.legacyBucketReader",
                None,
                None,
            ),
            "replica-recovery": (
                "bootstrap-replica-state",
                "roles/storage.objectViewer",
                "bootstrap-recovery-replica-state-read",
                "root-trust/default.tfstate",
            ),
            "replica-recovery-metadata": (
                "bootstrap-replica-state",
                "roles/storage.legacyBucketReader",
                None,
                None,
            ),
        }
        resources = [plan_lock_role]
        for instance, (bucket, role, title, object_name) in plan_access.items():
            condition = []
            if title is not None:
                condition = [
                    {
                        "title": title,
                        "expression": (
                            f"resource.name == 'projects/_/buckets/{bucket}/objects/{object_name}'"
                        ),
                    }
                ]
            resource = self.resource(
                "google_storage_bucket_iam_member",
                ["create"],
                {
                    "bucket": bucket,
                    "role": role,
                    "member": (
                        "serviceAccount:bootstrap-recovery@bootstrap-recovery.iam.gserviceaccount.com"
                        if "-recovery" in instance
                        else "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com"
                    ),
                    "condition": condition,
                },
            )
            resource["address"] = (
                f'module.root_state.google_storage_bucket_iam_member.backend_access["{instance}"]'
            )
            resources.append(resource)
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        primary_state = resources[1]
        primary_state["change"]["after"]["role"] = "roles/storage.objectAdmin"
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside its approved Ring-0 scope", result.stderr)

        primary_state["change"]["after"]["role"] = "roles/storage.objectViewer"
        primary_state["change"]["after"]["condition"][0]["expression"] = (
            "resource.name.startsWith('projects/_/buckets/bootstrap-primary-state/objects/root-trust/')"
        )
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact state or lock object", result.stderr)

        primary_state["change"]["after"]["condition"][0]["expression"] = (
            "resource.name == 'projects/_/buckets/bootstrap-primary-state/objects/root-trust/default.tfstate'"
        )
        recovery_state = next(
            resource
            for resource in resources
            if 'backend_access["primary-recovery"]' in resource["address"]
        )
        recovery_condition = recovery_state["change"]["after"]["condition"]
        recovery_state["change"]["after"]["condition"] = []
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("object-scoped IAM condition", result.stderr)
        recovery_state["change"]["after"]["condition"] = recovery_condition

        plan_lock_role["change"]["after"]["permissions"].append("storage.objects.list")
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions must exactly match", result.stderr)

    def test_replication_custom_role_bindings_accept_only_exact_instances(self):
        bindings = (
            (
                "google_storage_bucket_iam_member",
                'module.root_state.google_storage_bucket_iam_member.replication["source"]',
                "projects/bootstrap-state-root/roles/bootstrapStateReplicationSource",
                "bootstrap-primary-state",
            ),
            (
                "google_storage_bucket_iam_member",
                'module.root_state.google_storage_bucket_iam_member.replication["destination"]',
                "projects/bootstrap-state-root/roles/bootstrapStateReplicationDestination",
                "bootstrap-replica-state",
            ),
            (
                "google_project_iam_member",
                'module.root_state.google_project_iam_member.replication_events["transfer"]',
                "projects/bootstrap-state-root/roles/bootstrapStateReplicationTransferEvents",
                None,
            ),
            (
                "google_project_iam_member",
                'module.root_state.google_project_iam_member.replication_events["storage"]',
                "projects/bootstrap-state-root/roles/bootstrapStateReplicationStorageEvents",
                None,
            ),
        )
        resources = []
        for resource_type, address, role, bucket in bindings:
            after = {
                "role": role,
                "member": None,
            }
            if bucket is None:
                after["project"] = "bootstrap-state-root"
            else:
                after["bucket"] = bucket
                instance = "source" if '["source"]' in address else "destination"
                after["condition"] = [
                    {
                        "title": f"bootstrap-replication-{instance}-state-only",
                        "expression": (
                            "(resource.type == 'storage.googleapis.com/Bucket' && "
                            f"resource.name == 'projects/_/buckets/{bucket}') || "
                            "(resource.type == 'storage.googleapis.com/Object' && "
                            f"resource.name == 'projects/_/buckets/{bucket}/objects/root-trust/default.tfstate')"
                        ),
                    }
                ]
            resource = self.resource(resource_type, ["create"], after)
            resource["address"] = address
            resource["change"]["after_unknown"] = {"member": True}
            resources.append(resource)
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        resources[0]["address"] = (
            'module.root_state.google_storage_bucket_iam_member.replication["source_backdoor"]'
        )
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside its approved Ring-0 scope", result.stderr)

    def test_replication_bindings_reject_non_service_agent_members(self):
        resource = self.resource(
            "google_storage_bucket_iam_member",
            ["create"],
            {
                "bucket": "bootstrap-primary-state",
                "role": "projects/bootstrap-state-root/roles/bootstrapStateReplicationSource",
                "member": "group:platform@example.com",
            },
        )
        resource["address"] = (
            'module.root_state.google_storage_bucket_iam_member.replication["source"]'
        )
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected Google-managed transfer service agent", result.stderr)

    def test_transfer_service_agent_data_is_exact_and_computed(self):
        resource = self.resource(
            "google_storage_transfer_project_service_account",
            ["read"],
            {
                "project": "bootstrap-state-root",
                "email": None,
                "subject_id": None,
                "member": None,
            },
        )
        resource["mode"] = "data"
        resource["address"] = (
            "module.root_state.data.google_storage_transfer_project_service_account.replication"
        )
        resource["change"]["after_unknown"] = {
            "email": True,
            "subject_id": True,
            "member": True,
        }
        result = self.check_plan([resource])
        self.assertEqual(result.returncode, 0, result.stderr)

        resource["address"] = (
            "module.unreviewed.data.google_storage_transfer_project_service_account.replication"
        )
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact approved transfer-agent data addresses", result.stderr)

    def test_native_replication_jobs_are_accepted_for_both_state_roots(self):
        root = self.replication_transfer_job()
        recovery = self.replication_transfer_job(
            module="module.recovery_state",
            prefix="recovery-plane/default.tfstate",
            source="bootstrap-recovery-primary",
            destination="bootstrap-recovery-replica",
        )
        for resource in (root, recovery):
            resource["change"]["after"].update(
                {
                    "name": None,
                    "creation_time": None,
                    "last_modification_time": None,
                    "deletion_time": None,
                }
            )
            resource["change"]["after_unknown"] = {
                "name": True,
                "creation_time": True,
                "last_modification_time": True,
                "deletion_time": True,
            }
        result = self.check_plan([root, recovery])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_replication_allows_only_expected_computed_bucket_names(self):
        resource = self.replication_transfer_job(source=None, destination=None)
        resource["change"]["after_unknown"] = {
            "replication_spec": [
                {
                    "gcs_data_source": [{"bucket_name": True}],
                    "gcs_data_sink": [{"bucket_name": True}],
                }
            ]
        }
        result = self.check_plan([resource])
        self.assertEqual(result.returncode, 0, result.stderr)

        resource["change"]["after_unknown"]["replication_spec"][0]["transfer_options"] = [
            {"delete_objects_unique_in_sink": True}
        ]
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("delete_objects_unique_in_sink disabled", result.stderr)

    def test_native_replication_rejects_wide_prefix_and_delete_options(self):
        mutations = (
            ("prefix", "root-trust/"),
            ("source", "bootstrap-replica-state"),
            ("delete_source", True),
            ("delete_sink", True),
            ("overwrite", "ALWAYS"),
            ("kms", "KMS_KEY_PRESERVE"),
            ("status", "DISABLED"),
            ("deletion_policy", "DELETE"),
        )
        for mutation, value in mutations:
            with self.subTest(mutation=mutation):
                resource = self.replication_transfer_job()
                after = resource["change"]["after"]
                spec = after["replication_spec"][0]
                options = spec["transfer_options"][0]
                if mutation == "prefix":
                    spec["object_conditions"][0]["include_prefixes"] = [value]
                elif mutation == "source":
                    spec["gcs_data_source"][0]["bucket_name"] = value
                elif mutation == "delete_source":
                    options["delete_objects_from_source_after_transfer"] = value
                elif mutation == "delete_sink":
                    options["delete_objects_unique_in_sink"] = value
                elif mutation == "overwrite":
                    options["overwrite_when"] = value
                elif mutation == "kms":
                    options["metadata_options"][0]["kms_key"] = value
                else:
                    after[mutation] = value
                result = self.check_plan([resource])
                self.assertNotEqual(result.returncode, 0)

    def test_native_replication_job_address_cannot_be_spoofed(self):
        resource = self.replication_transfer_job()
        resource["address"] = "module.unreviewed.google_storage_transfer_job.replication"
        resource["change"]["after"].update(
            {"name": None, "creation_time": None, "last_modification_time": None}
        )
        resource["change"]["after_unknown"] = {
            "name": True,
            "creation_time": True,
            "last_modification_time": True,
        }
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact approved native-replication transfer-job addresses", result.stderr)

    def test_recovery_export_custom_roles_are_exact(self):
        contracts = {
            "source_metadata": (
                "bootstrapRecoveryExportSourceMetadata",
                ["storage.buckets.get", "storage.buckets.update"],
                True,
            ),
            "source_object": (
                "bootstrapRecoveryExportSourceObject",
                ["storage.objects.get"],
                True,
            ),
            "transfer_events": (
                "bootstrapRecoveryExportTransferEvents",
                [
                    "pubsub.subscriptions.consume",
                    "pubsub.subscriptions.create",
                    "pubsub.topics.create",
                ],
                True,
            ),
            "storage_events": (
                "bootstrapRecoveryExportStorageEvents",
                [
                    "pubsub.subscriptions.consume",
                    "pubsub.subscriptions.create",
                    "pubsub.topics.publish",
                ],
                True,
            ),
            "destination_metadata": (
                "bootstrapRecoveryExportDestinationMetadata",
                ["storage.buckets.get"],
                False,
            ),
            "destination_object": (
                "bootstrapRecoveryExportDestinationObject",
                ["storage.objects.create", "storage.objects.get"],
                False,
            ),
        }
        resources = []
        for name, (role_id, permissions, indexed) in contracts.items():
            keys = ("root-trust", "recovery-plane") if indexed else (None,)
            for key in keys:
                resources.append(self.state_export_custom_role(name, role_id, permissions, key))
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        resources[0]["change"]["after"]["permissions"].append("storage.objects.list")
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions must exactly match", result.stderr)

    def test_recovery_export_service_accounts_and_agent_data_are_exact(self):
        resources = []
        for key, project in (
            ("root-trust", "bootstrap-state-root"),
            ("recovery-plane", "bootstrap-recovery"),
        ):
            service_account = self.resource(
                "google_service_account",
                ["create"],
                {
                    "project": project,
                    "account_id": "bootstrap-recovery-export",
                    "disabled": False,
                    "deletion_policy": "PREVENT",
                    "email": None,
                    "id": None,
                    "member": None,
                    "name": None,
                    "unique_id": None,
                },
            )
            service_account["address"] = (
                f'module.recovery_exports.google_service_account.state_export["{key}"]'
            )
            service_account["change"]["after_unknown"] = dict.fromkeys(
                ("email", "id", "member", "name", "unique_id"), True
            )
            resources.append(service_account)

            storage_agent = self.resource(
                "google_storage_project_service_account",
                ["read"],
                {"project": project, "email_address": None, "member": None},
            )
            storage_agent["mode"] = "data"
            storage_agent["address"] = (
                "module.recovery_exports.data.google_storage_project_service_account."
                f'state_export_source["{key}"]'
            )
            storage_agent["change"]["after_unknown"] = {
                "email_address": True,
                "member": True,
            }
            resources.append(storage_agent)

            transfer_agent = self.resource(
                "google_storage_transfer_project_service_account",
                ["read"],
                {"project": project, "email": None, "member": None, "subject_id": None},
            )
            transfer_agent["mode"] = "data"
            transfer_agent["address"] = (
                "module.recovery_exports.data.google_storage_transfer_project_service_account."
                f'state_export["{key}"]'
            )
            transfer_agent["change"]["after_unknown"] = {
                "email": True,
                "member": True,
                "subject_id": True,
            }
            resources.append(transfer_agent)
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        resources[0]["change"]["after"]["account_id"] = "recovery-export-admin"
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bootstrap-recovery-export", result.stderr)

    def test_recovery_export_iam_bindings_are_exact_and_object_scoped(self):
        resources = []
        for key, project, source_bucket in (
            ("root-trust", "bootstrap-state-root", "bootstrap-primary-state"),
            ("recovery-plane", "bootstrap-recovery", "bootstrap-recovery-primary"),
        ):
            export_email = f"bootstrap-recovery-export@{project}.iam.gserviceaccount.com"
            export_member = f"serviceAccount:{export_email}"
            service_account_id = f"projects/{project}/serviceAccounts/{export_email}"
            destination_bucket = "bootstrap-recovery-recovery-exports"
            definitions = (
                (
                    "google_service_account_iam_member",
                    "state_export_apply",
                    {
                        "service_account_id": service_account_id,
                        "role": "roles/iam.serviceAccountUser",
                        "member": "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com",
                        "condition": [],
                    },
                ),
                (
                    "google_service_account_iam_member",
                    "state_export_transfer",
                    {
                        "service_account_id": service_account_id,
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "member": "serviceAccount:project-123@storage-transfer-service.iam.gserviceaccount.com",
                        "condition": [],
                    },
                ),
                (
                    "google_project_iam_member",
                    "state_export_transfer_events",
                    {
                        "project": project,
                        "role": f"projects/{project}/roles/bootstrapRecoveryExportTransferEvents",
                        "member": export_member,
                        "condition": [],
                    },
                ),
                (
                    "google_project_iam_member",
                    "state_export_storage_events",
                    {
                        "project": project,
                        "role": f"projects/{project}/roles/bootstrapRecoveryExportStorageEvents",
                        "member": "serviceAccount:service-123@gs-project-accounts.iam.gserviceaccount.com",
                        "condition": [],
                    },
                ),
                (
                    "google_storage_bucket_iam_member",
                    "state_export_source_metadata",
                    {
                        "bucket": source_bucket,
                        "role": f"projects/{project}/roles/bootstrapRecoveryExportSourceMetadata",
                        "member": export_member,
                        "condition": [],
                    },
                ),
                (
                    "google_storage_bucket_iam_member",
                    "state_export_source_object",
                    {
                        "bucket": source_bucket,
                        "role": f"projects/{project}/roles/bootstrapRecoveryExportSourceObject",
                        "member": export_member,
                        "condition": [
                            {
                                "title": f"read-{key}-default-state-only",
                                "expression": (
                                    "resource.type == 'storage.googleapis.com/Object' "
                                    "&& resource.name == "
                                    f"'projects/_/buckets/{source_bucket}/objects/{key}/default.tfstate'"
                                ),
                            }
                        ],
                    },
                ),
                (
                    "google_storage_bucket_iam_member",
                    "state_export_destination_metadata",
                    {
                        "bucket": destination_bucket,
                        "role": "projects/bootstrap-recovery/roles/bootstrapRecoveryExportDestinationMetadata",
                        "member": export_member,
                        "condition": [],
                    },
                ),
                (
                    "google_storage_bucket_iam_member",
                    "state_export_destination_object",
                    {
                        "bucket": destination_bucket,
                        "role": "projects/bootstrap-recovery/roles/bootstrapRecoveryExportDestinationObject",
                        "member": export_member,
                        "condition": [
                            {
                                "title": f"write-{key}-default-state-only",
                                "expression": (
                                    "resource.type == 'storage.googleapis.com/Object' "
                                    "&& resource.name == "
                                    f"'projects/_/buckets/{destination_bucket}/objects/{key}/default.tfstate'"
                                ),
                            }
                        ],
                    },
                ),
            )
            for resource_type, name, after in definitions:
                resource = self.resource(resource_type, ["create"], after)
                resource["address"] = f'module.recovery_exports.{resource_type}.{name}["{key}"]'
                resources.append(resource)
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        source_object = next(
            resource
            for resource in resources
            if 'state_export_source_object["root-trust"]' in resource["address"]
        )
        source_object["change"]["after"]["condition"][0]["expression"] = (
            "resource.name.startsWith('projects/_/buckets/bootstrap-primary-state/objects/root-trust/')"
        )
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exclude locks", result.stderr)

    def test_recovery_export_jobs_are_native_and_exact(self):
        resources = [
            self.state_export_job("root-trust"),
            self.state_export_job("recovery-plane"),
        ]
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        mutations = (
            (
                "wide-prefix",
                lambda after: after["replication_spec"][0]["object_conditions"][0].update(
                    {"include_prefixes": ["root-trust/"]}
                ),
            ),
            ("managed-agent", lambda after: after.update({"service_account": ""})),
            (
                "same-bucket",
                lambda after: after["replication_spec"][0]["gcs_data_sink"][0].update(
                    {"bucket_name": "bootstrap-primary-state"}
                ),
            ),
            (
                "delete",
                lambda after: after["replication_spec"][0]["transfer_options"][0].update(
                    {"delete_objects_unique_in_sink": True}
                ),
            ),
            (
                "preserve-kms",
                lambda after: after["replication_spec"][0]["transfer_options"][0][
                    "metadata_options"
                ][0].update({"kms_key": "KMS_KEY_PRESERVE"}),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                resource = self.state_export_job("root-trust")
                mutate(resource["change"]["after"])
                result = self.check_plan([resource])
                self.assertNotEqual(result.returncode, 0)

    def test_fixed_recovery_objects_are_explicit_abandoned_json(self):
        resources = []
        for name, object_name, bucket in (
            (
                "public_trust_metadata",
                "trust/public-trust-metadata.json",
                "bootstrap-recovery-recovery-evidence",
            ),
            (
                "restore_inventory",
                "restore/inventory.json",
                "bootstrap-recovery-recovery-exports",
            ),
        ):
            content = self.public_trust_metadata()
            if name == "restore_inventory":
                content = {
                    "schema_version": 1,
                    "source_state_objects": {
                        "root-trust": {
                            "bucket": "bootstrap-primary-state",
                            "object": "root-trust/default.tfstate",
                        },
                        "recovery-plane": {
                            "bucket": "bootstrap-recovery-primary",
                            "object": "recovery-plane/default.tfstate",
                        },
                    },
                    "export_state_objects": {
                        "root-trust": {
                            "bucket": "bootstrap-recovery-recovery-exports",
                            "object": "root-trust/default.tfstate",
                        },
                        "recovery-plane": {
                            "bucket": "bootstrap-recovery-recovery-exports",
                            "object": "recovery-plane/default.tfstate",
                        },
                    },
                    "runtime_selection_required": ["generation", "sha256"],
                    "minimum_retained_state_generations": 3,
                    "restore_manifest_digest": "sha256:" + "a" * 64,
                    "excludes": [
                        "kms-private-key-material",
                        "service-account-keys",
                        "credentials",
                    ],
                }
            resource = self.resource(
                "google_storage_bucket_object",
                ["create"],
                {
                    "name": object_name,
                    "bucket": bucket,
                    "content": json.dumps(content),
                    "content_type": "application/json",
                    "deletion_policy": "ABANDON",
                    "source": "",
                },
            )
            resource["address"] = f"module.recovery_exports.google_storage_bucket_object.{name}"
            resources.append(resource)
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        collocated = self.public_trust_metadata()
        collocated["federation_providers"]["github-recovery"] = collocated["federation_providers"][
            "github-recovery"
        ].replace("projects/987654321/", "projects/123456789/")
        resources[0]["change"]["after"]["content"] = json.dumps(collocated)
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public trust contract", result.stderr)

        resources[0]["change"]["after"]["content"] = json.dumps(self.public_trust_metadata())
        metadata = json.loads(resources[0]["change"]["after"]["content"])
        removed_digest = metadata["manifest_digests"].pop("manifests/trust-anchors.yaml")
        resources[0]["change"]["after"]["content"] = json.dumps(metadata)
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public trust contract", result.stderr)

        metadata["manifest_digests"]["manifests/trust-anchors.yaml"] = removed_digest
        metadata["state_backends"]["root-trust"]["bucket"] = "bootstrap-other-primary-state"
        resources[0]["change"]["after"]["content"] = json.dumps(metadata)
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("agree on the root-trust state coordinates", result.stderr)

        resources[0]["change"]["after"]["content"] = json.dumps(self.public_trust_metadata())

        resources[0]["change"]["after"]["deletion_policy"] = "DELETE"
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ABANDON", result.stderr)

    def test_signing_versions_and_time_scoped_signers_are_exact(self):
        resources = []
        for key in (
            "audit-anchor",
            "bootstrap-handoff",
            "connected-observation-evidence",
            "github-config-plan-evidence",
            "infrastructure-export",
            "recovery-evidence",
        ):
            resources.extend([self.signing_crypto_key(key), self.signing_version(key)])
            if key not in {"connected-observation-evidence", "infrastructure-export"}:
                resources.append(self.signing_binding(key))
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        resources[0]["change"]["after"]["skip_initial_version_creation"] = False
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("skip_initial_version_creation", result.stderr)

    def test_active_signing_version_accepts_google_7_42_resolved_shape(self):
        resource, planned = self.active_signing_data(version_number=2)
        document = self.active_signing_document(
            resource,
            planned,
            self.signing_version(
                "audit-anchor",
                actions=["no-op"],
                version_number="2",
            ),
        )
        result = self.run_plan_document("plan-resource-check", document)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_active_signing_version_accepts_exact_deferred_reads(self):
        resource, planned = self.active_signing_data()
        resource["change"].update(
            {
                "actions": ["read"],
                "before": None,
                "after": {},
                "after_unknown": dict.fromkeys(
                    (
                        "algorithm",
                        "crypto_key",
                        "id",
                        "name",
                        "protection_level",
                        "public_key",
                        "state",
                        "version",
                    ),
                    True,
                ),
            }
        )
        planned["values"] = None
        result = self.run_plan_document(
            "plan-resource-check",
            self.active_signing_document(resource, planned),
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        resource, planned = self.active_signing_data()
        prior = copy.deepcopy(resource["change"]["before"])
        crypto_key = resource["change"]["after"]["crypto_key"]
        resource["change"].update(
            {
                "actions": ["read"],
                "before": prior,
                "after": {"crypto_key": crypto_key},
                "after_unknown": dict.fromkeys(
                    (
                        "algorithm",
                        "id",
                        "name",
                        "protection_level",
                        "public_key",
                        "state",
                        "version",
                    ),
                    True,
                ),
            }
        )
        planned["values"] = {
            "crypto_key": crypto_key,
            **dict.fromkeys(resource["change"]["after_unknown"]),
        }
        result = self.run_plan_document(
            "plan-resource-check",
            self.active_signing_document(resource, planned),
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_active_signing_version_rejects_malformed_provider_shapes(self):
        resource, planned = self.active_signing_data()
        base = self.active_signing_document(resource, planned)

        def planned_path(value):
            return value["planned_values"]["root_module"]["child_modules"][0]["resources"][0]

        mutations = (
            (
                "string-version",
                lambda value: value["resource_changes"][1]["change"]["after"].update(
                    {"version": "1"}
                ),
            ),
            (
                "fractional-version",
                lambda value: value["resource_changes"][1]["change"]["after"].update(
                    {"version": 1.5}
                ),
            ),
            (
                "zero-version",
                lambda value: value["resource_changes"][1]["change"]["after"].update(
                    {"version": 0}
                ),
            ),
            (
                "provider-id-equals-name",
                lambda value: value["resource_changes"][1]["change"]["after"].update(
                    {"id": value["resource_changes"][1]["change"]["after"]["name"]}
                ),
            ),
            (
                "scalar-public-key",
                lambda value: value["resource_changes"][1]["change"]["after"].update(
                    {"public_key": ACTIVE_SIGNING_PUBLIC_KEY_PEM}
                ),
            ),
            (
                "multiple-public-keys",
                lambda value: value["resource_changes"][1]["change"]["after"]["public_key"].append(
                    copy.deepcopy(value["resource_changes"][1]["change"]["after"]["public_key"][0])
                ),
            ),
            (
                "malformed-pem",
                lambda value: value["resource_changes"][1]["change"]["after"]["public_key"][
                    0
                ].update({"pem": "not a public key"}),
            ),
            (
                "resolved-unknown",
                lambda value: value["resource_changes"][1]["change"].update(
                    {"after_unknown": {"state": True}}
                ),
            ),
            (
                "before-after-mismatch",
                lambda value: value["resource_changes"][1]["change"]["before"].update(
                    {"state": "DISABLED"}
                ),
            ),
            (
                "planned-value-mismatch",
                lambda value: planned_path(value)["values"].update({"state": "DISABLED"}),
            ),
            (
                "wrong-planned-provider",
                lambda value: planned_path(value).update(
                    {"provider_name": "registry.opentofu.org/example/google"}
                ),
            ),
            (
                "missing-planned-values",
                lambda value: value.pop("planned_values"),
            ),
            (
                "duplicate-planned-address",
                lambda value: value["planned_values"]["root_module"]["child_modules"][0][
                    "resources"
                ].append(copy.deepcopy(planned_path(value))),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                document = copy.deepcopy(base)
                mutate(document)
                result = self.run_plan_document("plan-resource-check", document)
                self.assertNotEqual(result.returncode, 0, result.stderr)

        resource, planned = self.active_signing_data(version_number=1)
        stale = self.active_signing_document(
            resource,
            planned,
            self.signing_version(
                "audit-anchor",
                actions=["no-op"],
                version_number="2",
            ),
        )
        result = self.run_plan_document("plan-resource-check", stale)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("activeVersionRef", result.stderr)

        resource, planned = self.active_signing_data()
        resource["change"].update(
            {
                "actions": ["no-op"],
                "before": None,
                "after": {},
                "after_unknown": dict.fromkeys(
                    (
                        "algorithm",
                        "crypto_key",
                        "id",
                        "name",
                        "protection_level",
                        "public_key",
                        "state",
                        "version",
                    ),
                    True,
                ),
            }
        )
        planned["values"] = dict.fromkeys(resource["change"]["after_unknown"])
        result = self.run_plan_document(
            "plan-resource-check",
            self.active_signing_document(resource, planned),
        )
        self.assertNotEqual(result.returncode, 0)

    def test_initial_signing_create_unknowns_require_exact_bound_configuration(self):
        document = self.initial_signing_create_document()
        result = self.run_plan_document("plan-resource-check", document)
        self.assertEqual(result.returncode, 0, result.stderr)

        mutations = (
            (
                "extra-unknown",
                lambda value: value["resource_changes"][1]["change"]["after_unknown"].update(
                    {"condition": [{"expression": True, "title": True}]}
                ),
            ),
            (
                "wrong-window",
                lambda value: value["variables"]["bootstrap"]["value"]["signing"]["keys"][
                    "audit-anchor"
                ]["versions"]["v20260829"].update({"rotation_deadline": "2026-12-01T00:00:00Z"}),
            ),
            (
                "missing-reference",
                lambda value: value["configuration"]["root_module"]["module_calls"]["signing_root"][
                    "module"
                ]["resources"][0]["expressions"]["condition"][0]["expression"]["references"].pop(),
            ),
            (
                "not-create",
                lambda value: value["resource_changes"][1]["change"].update({"actions": ["no-op"]}),
            ),
            (
                "missing-version",
                lambda value: value["resource_changes"].pop(0),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                document = self.initial_signing_create_document()
                mutate(document)
                result = self.run_plan_document("plan-resource-check", document)
                self.assertNotEqual(result.returncode, 0)

    def test_signing_versions_reject_extra_instances_and_mutation(self):
        mutations = (
            ("actions", ["update"]),
            ("state", "DISABLED"),
            ("algorithm", "RSA_SIGN_PSS_2048_SHA256"),
            ("protection_level", "SOFTWARE"),
            (
                "crypto_key",
                "projects/bootstrap-signing/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/other",
            ),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                resource = self.signing_version("audit-anchor")
                if field == "actions":
                    resource["change"]["actions"] = value
                else:
                    resource["change"]["after"][field] = value
                result = self.check_plan([resource])
                self.assertNotEqual(result.returncode, 0)

        extra = self.signing_version("audit-anchor")
        extra["address"] = (
            'module.signing_root.google_kms_crypto_key_version.signing["audit-anchor:v20260531"]'
        )
        extra["change"]["after"]["state"] = "DISABLED"
        result = self.check_plan([extra])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resource-address allowlist", result.stderr)

    def test_signing_rotation_allows_prestage_then_concrete_activation(self):
        prestage_resources = []
        for key in (
            "audit-anchor",
            "bootstrap-handoff",
            "connected-observation-evidence",
            "github-config-plan-evidence",
            "infrastructure-export",
            "recovery-evidence",
        ):
            prestage_resources.extend(
                [
                    self.signing_version(key, actions=["no-op"]),
                    self.unknown_signing_version(key),
                ]
            )
            if key not in {"connected-observation-evidence", "infrastructure-export"}:
                prestage_resources.append(self.signing_binding(key, actions=["no-op"]))
        prestage = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": prestage_resources,
            "variables": self.rotating_signing_variables(),
        }
        result = self.run_plan_document("plan-resource-check", prestage)
        self.assertEqual(result.returncode, 0, result.stderr)

        activation_resources = []
        for key in (
            "audit-anchor",
            "bootstrap-handoff",
            "connected-observation-evidence",
            "github-config-plan-evidence",
            "infrastructure-export",
            "recovery-evidence",
        ):
            activation_resources.extend(
                [
                    self.signing_version(key, actions=["no-op"], state="DISABLED"),
                    self.signing_version(
                        key,
                        actions=["no-op"],
                        version_ref="v20261126",
                        version_number="2",
                    ),
                ]
            )
            if key not in {"connected-observation-evidence", "infrastructure-export"}:
                activation_resources.append(
                    self.signing_binding(
                        key,
                        version_ref="v20261126",
                        version_number="2",
                        activation_window_start="2026-11-26T00:00:00Z",
                        rotation_deadline="2027-02-24T00:00:00Z",
                        actions=["update"],
                    )
                )
        activation = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": activation_resources,
            "variables": self.rotating_signing_variables("v20261126"),
        }
        result = self.run_plan_document("plan-resource-check", activation)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_signing_rotation_rejects_undeclared_gap_and_window_mutation(self):
        resources = []
        for key in (
            "audit-anchor",
            "bootstrap-handoff",
            "connected-observation-evidence",
            "github-config-plan-evidence",
            "infrastructure-export",
            "recovery-evidence",
        ):
            resources.extend(
                [
                    self.signing_version(key, actions=["no-op"]),
                    self.unknown_signing_version(key),
                ]
            )
            if key not in {"connected-observation-evidence", "infrastructure-export"}:
                resources.append(self.signing_binding(key, actions=["no-op"]))
        base = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": resources,
            "variables": self.rotating_signing_variables(),
        }

        def replace_declared_version(value, key, new_ref, start, deadline):
            versions = value["variables"]["bootstrap"]["value"]["signing"]["keys"][key]["versions"]
            versions.pop("v20261126")
            versions[new_ref] = {
                "activation_window_start": start,
                "rotation_deadline": deadline,
            }
            old_address = (
                "module.signing_root.google_kms_crypto_key_version.signing"
                f"[{json.dumps(f'{key}:v20261126')}]"
            )
            for resource in value["resource_changes"]:
                if resource["address"] == old_address:
                    resource["address"] = (
                        "module.signing_root.google_kms_crypto_key_version.signing"
                        f"[{json.dumps(f'{key}:{new_ref}')}]"
                    )

        mutations = (
            (
                "undeclared",
                lambda value: value["resource_changes"][1].update(
                    {
                        "address": 'module.signing_root.google_kms_crypto_key_version.signing["audit-anchor:v20270225"]'
                    }
                ),
            ),
            (
                "gap",
                lambda value: replace_declared_version(
                    value,
                    "audit-anchor",
                    "v20261128",
                    "2026-11-28T00:00:00Z",
                    "2027-02-26T00:00:00Z",
                ),
            ),
            (
                "excess-overlap",
                lambda value: replace_declared_version(
                    value,
                    "audit-anchor",
                    "v20261125",
                    "2026-11-25T00:00:00Z",
                    "2027-02-23T00:00:00Z",
                ),
            ),
            (
                "deadline",
                lambda value: value["variables"]["bootstrap"]["value"]["signing"]["keys"][
                    "bootstrap-handoff"
                ]["versions"]["v20261126"].update({"rotation_deadline": "2027-02-26T00:00:00Z"}),
            ),
            (
                "historical-update",
                lambda value: value["resource_changes"][0]["change"].update(
                    {"actions": ["update"]}
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                document = json.loads(json.dumps(base))
                mutate(document)
                result = self.run_plan_document("plan-resource-check", document)
                self.assertNotEqual(result.returncode, 0)

    def test_signer_bindings_reject_absent_or_broadened_conditions(self):
        mutations = (
            ("absent", []),
            (
                "wrong-title",
                [
                    {
                        "title": "sign-any-version",
                        "expression": self.signing_binding("audit-anchor")["change"]["after"][
                            "condition"
                        ][0]["expression"],
                    }
                ],
            ),
            (
                "or-expression",
                [
                    {
                        "title": "sign-audit-anchor-v20260829-within-window",
                        "expression": "resource.type == 'cloudkms.googleapis.com/CryptoKeyVersion' || true",
                    }
                ],
            ),
            (
                "wrong-deadline",
                [
                    {
                        "title": "sign-audit-anchor-v20260829-within-window",
                        "expression": self.signing_binding("audit-anchor")["change"]["after"][
                            "condition"
                        ][0]["expression"].replace("2026-11-27T00:00:00Z", "2026-11-28T00:00:00Z"),
                    }
                ],
            ),
        )
        for name, condition in mutations:
            with self.subTest(name=name):
                version = self.signing_version("audit-anchor")
                binding = self.signing_binding("audit-anchor")
                binding["change"]["after"]["condition"] = condition
                result = self.check_plan([version, binding])
                self.assertNotEqual(result.returncode, 0)

    def test_recovery_signing_metadata_is_exact_key_and_active_version_only(self):
        signing_project = self.project_resource("signing", "bootstrap-signing")
        custom_role = self.resource(
            "google_project_iam_custom_role",
            ["create"],
            {
                "project": "bootstrap-signing",
                "role_id": "bootstrapRecoverySigningMetadata",
                "permissions": [
                    "cloudkms.cryptoKeys.get",
                    "cloudkms.cryptoKeyVersions.get",
                ],
                "stage": "GA",
                "deleted": False,
            },
        )
        custom_role["address"] = (
            "module.signing_root.google_project_iam_custom_role.recovery_metadata"
        )
        version = self.signing_version("recovery-evidence")
        crypto_key = (
            "projects/bootstrap-signing/locations/us-central1/keyRings/"
            "bootstrap-signing/cryptoKeys/recovery-evidence"
        )
        version_name = f"{crypto_key}/cryptoKeyVersions/1"
        binding = self.resource(
            "google_kms_crypto_key_iam_member",
            ["create"],
            {
                "crypto_key_id": crypto_key,
                "role": "projects/bootstrap-signing/roles/bootstrapRecoverySigningMetadata",
                "member": "serviceAccount:bootstrap-recovery@bootstrap-recovery.iam.gserviceaccount.com",
                "condition": [
                    {
                        "title": "read-recovery-evidence-active-key-version-only",
                        "expression": (
                            "(resource.type == 'cloudkms.googleapis.com/CryptoKey' "
                            f"&& resource.name == '{crypto_key}') || "
                            "(resource.type == 'cloudkms.googleapis.com/CryptoKeyVersion' "
                            f"&& resource.name == '{version_name}')"
                        ),
                    }
                ],
            },
        )
        binding["address"] = (
            "module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata"
        )
        resources = [signing_project, custom_role, version, binding]
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        custom_role["change"]["after"]["permissions"].append("cloudkms.cryptoKeyVersions.list")
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions must exactly match", result.stderr)

        custom_role["change"]["after"]["permissions"].pop()
        binding["change"]["after"]["condition"][0]["expression"] += " || true"
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active version metadata", result.stderr)

    def test_root_administrator_logging_is_config_writer_not_logging_admin(self):
        resource = self.resource(
            "google_organization_iam_member",
            ["create"],
            {
                "org_id": "123456789",
                "role": "roles/logging.configWriter",
                "member": "group:root-trust-administrators@example.com",
            },
        )
        resource["address"] = "google_organization_iam_member.apply_logging_config_writer"
        result = self.check_plan([resource])
        self.assertEqual(result.returncode, 0, result.stderr)

        resource["change"]["after"]["member"] = (
            "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com"
        )
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("never bootstrap-apply", result.stderr)
        resource["change"]["after"]["member"] = "group:root-trust-administrators@example.com"

        resource["change"]["after"]["role"] = "roles/logging.admin"
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside its approved Ring-0 scope", result.stderr)

        resource["address"] = "google_organization_iam_member.apply_logging_admin"
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resource-address allowlist", result.stderr)

    def test_exact_resource_address_gate_rejects_arbitrary_families(self):
        cases = (
            ("google_service_account", "google_service_account.evil"),
            ("google_project", "google_project.evil"),
            (
                "google_project_service",
                'google_project_service.evil["iam.googleapis.com"]',
            ),
            (
                "google_iam_workload_identity_pool",
                "module.github_federation.google_iam_workload_identity_pool.evil",
            ),
            (
                "google_kms_key_ring",
                "module.signing_root.google_kms_key_ring.evil",
            ),
            (
                "google_kms_crypto_key_version",
                'module.signing_root.google_kms_crypto_key_version.signing["evil:v20260829"]',
            ),
            (
                "google_logging_project_bucket_config",
                'module.audit_root.google_logging_project_bucket_config.evil["primary"]',
            ),
            (
                "google_logging_organization_sink",
                'module.audit_root.google_logging_organization_sink.evil["admin-activity"]',
            ),
            (
                "google_privileged_access_manager_entitlement",
                'module.break_glass.google_privileged_access_manager_entitlement.evil["root-trust-administration"]',
            ),
        )
        for resource_type, address in cases:
            with self.subTest(address=address):
                resource = self.resource(resource_type, ["create"], {})
                resource["address"] = address
                result = self.check_plan([resource])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("resource-address allowlist", result.stderr)

    def test_workload_provider_claims_and_principal_set_are_exact(self):
        resources = self.github_plan_identity_resources()
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        mutations = (
            (
                "subject-spoof",
                lambda provider, binding: provider["change"]["after"].update(
                    {
                        "attribute_condition": provider["change"]["after"][
                            "attribute_condition"
                        ].replace("assertion.sub ==", "assertion.subject ==", 1)
                    }
                ),
            ),
            (
                "non-equality",
                lambda provider, binding: provider["change"]["after"].update(
                    {
                        "attribute_condition": provider["change"]["after"][
                            "attribute_condition"
                        ].replace(
                            "assertion.repository_id == '1350991612'",
                            "assertion.repository_id != ''",
                        )
                    }
                ),
            ),
            (
                "prefix",
                lambda provider, binding: provider["change"]["after"].update(
                    {
                        "attribute_condition": provider["change"]["after"][
                            "attribute_condition"
                        ].replace(
                            "assertion.repository_id == '1350991612'",
                            "assertion.repository_id.startsWith('987')",
                        )
                    }
                ),
            ),
            (
                "wildcard",
                lambda provider, binding: provider["change"]["after"].update(
                    {
                        "attribute_condition": provider["change"]["after"][
                            "attribute_condition"
                        ].replace("1350991612", "*", 1)
                    }
                ),
            ),
            (
                "mapping",
                lambda provider, binding: provider["change"]["after"]["attribute_mapping"].update(
                    {"google.subject": "assertion.actor"}
                ),
            ),
            (
                "principal-mismatch",
                lambda provider, binding: binding["change"]["after"].update(
                    {
                        "member": binding["change"]["after"]["member"].replace(
                            "1350991612", "111111111"
                        )
                    }
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                resources = self.github_plan_identity_resources()
                provider = resources[3]
                binding = resources[5]
                mutate(provider, binding)
                result = self.check_plan(resources)
                self.assertNotEqual(result.returncode, 0)

    def test_ci_evidence_provider_claims_and_role_separation_are_exact(self):
        resources = self.ci_evidence_identity_resources()
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        mutations = (
            (
                "arbitrary-audience",
                lambda writer, writer_binding, verifier: writer["change"]["after"]["oidc"][
                    0
                ].update({"allowed_audiences": ["https://attacker.example/audience"]}),
            ),
            (
                "repository-allowlist",
                lambda writer, writer_binding, verifier: writer["change"]["after"].update(
                    {
                        "attribute_condition": writer["change"]["after"][
                            "attribute_condition"
                        ].replace(", '1350992171'", "")
                    }
                ),
            ),
            (
                "mutable-central-workflow",
                lambda writer, writer_binding, verifier: writer["change"]["after"].update(
                    {
                        "attribute_condition": writer["change"]["after"][
                            "attribute_condition"
                        ].replace("@" + "a" * 40, "@main", 1)
                    }
                ),
            ),
            (
                "workflow-sha-mismatch",
                lambda writer, writer_binding, verifier: writer["change"]["after"].update(
                    {
                        "attribute_condition": writer["change"]["after"][
                            "attribute_condition"
                        ].replace(
                            "assertion.job_workflow_sha == '" + "a" * 40 + "'",
                            "assertion.job_workflow_sha == '" + "c" * 40 + "'",
                        )
                    }
                ),
            ),
            (
                "release-tag-prefix",
                lambda writer, writer_binding, verifier: writer["change"]["after"].update(
                    {
                        "attribute_condition": writer["change"]["after"][
                            "attribute_condition"
                        ].replace("refs/tags/v", "refs/tags/")
                    }
                ),
            ),
            (
                "provider-role",
                lambda writer, writer_binding, verifier: writer["change"]["after"][
                    "attribute_mapping"
                ].update({"attribute.evidence_role": "'verifier'"}),
            ),
            (
                "unbounded-subject",
                lambda writer, writer_binding, verifier: writer["change"]["after"][
                    "attribute_mapping"
                ].update({"google.subject": "assertion.sub"}),
            ),
            (
                "principal-role",
                lambda writer, writer_binding, verifier: writer_binding["change"]["after"].update(
                    {
                        "member": writer_binding["change"]["after"]["member"].replace(
                            "/writer", "/verifier"
                        )
                    }
                ),
            ),
            (
                "verifier-workflow",
                lambda writer, writer_binding, verifier: verifier["change"]["after"].update(
                    {
                        "attribute_condition": verifier["change"]["after"][
                            "attribute_condition"
                        ].replace("@refs/heads/main", "@refs/heads/development")
                    }
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                resources = self.ci_evidence_identity_resources()
                mutate(resources[2], resources[4], resources[5])
                result = self.check_plan(resources)
                self.assertNotEqual(result.returncode, 0)

    def test_infrastructure_live_subjects_and_eight_audiences_are_exact(self):
        for identity in (
            "development-plan",
            "development-apply",
            "staging-plan",
            "staging-apply",
            "production-plan",
            "production-apply",
            "restricted-plan",
            "restricted-apply",
        ):
            with self.subTest(identity=identity):
                resources = self.infrastructure_identity_resources(identity)
                result = self.check_plan(resources)
                self.assertEqual(result.returncode, 0, result.stderr)

        mutations = (
            lambda provider, binding: provider["change"]["after"]["oidc"][0].update(
                {"allowed_audiences": ["sts.googleapis.com"]}
            ),
            lambda provider, binding: provider["change"]["after"].update(
                {
                    "attribute_condition": provider["change"]["after"][
                        "attribute_condition"
                    ].replace("assertion.workflow_sha == assertion.sha", "true")
                }
            ),
            lambda provider, binding: provider["change"]["after"].update(
                {
                    "attribute_condition": provider["change"]["after"][
                        "attribute_condition"
                    ].replace(
                        "repository_visibility == 'public'", "repository_visibility != 'public'"
                    )
                }
            ),
            lambda provider, binding: provider["change"]["after"]["attribute_mapping"].update(
                {"google.subject": "assertion.sub"}
            ),
            lambda provider, binding: binding["change"]["after"].update(
                {
                    "member": binding["change"]["after"]["member"].replace(
                        "production-apply", "production-plan"
                    )
                }
            ),
        )
        for mutate in mutations:
            resources = self.infrastructure_identity_resources()
            mutate(resources[2], resources[4])
            result = self.check_plan(resources)
            self.assertNotEqual(result.returncode, 0)

    def test_buildkite_and_gitops_subject_claims_are_exact(self):
        identity = self.project_resource("identity", "bootstrap-identity")
        buildkite = self.resource(
            "google_iam_workload_identity_pool_provider",
            ["create"],
            {
                "project": "bootstrap-identity",
                "workload_identity_pool_id": "bootstrap-buildkite",
                "workload_identity_pool_provider_id": "buildkite",
                "disabled": False,
                "attribute_mapping": {
                    "google.subject": "assertion.sub",
                    "attribute.organization_slug": "assertion.organization_slug",
                    "attribute.pipeline_slug": "assertion.pipeline_slug",
                    "attribute.pipeline_id": "assertion.pipeline_id",
                    "attribute.build_branch": "assertion.build_branch",
                    "attribute.step_key": "assertion.step_key",
                },
                "attribute_condition": " && ".join(
                    [
                        "assertion.sub == '0184990a-4782-42b5-afc1-16715b10b8ff'",
                        "assertion.organization_slug == 'mindclade'",
                        "assertion.pipeline_slug == 'bootstrap'",
                        "assertion.pipeline_id == '0184990a-4782-42b5-afc1-16715b10b8ff'",
                        "assertion.build_branch == 'main'",
                        "assertion.step_key == 'bootstrap-ring0-signing'",
                    ]
                ),
                "oidc": [
                    {
                        "issuer_uri": "https://agent.buildkite.com",
                        "allowed_audiences": ["https://buildkite.com/mindclade/bootstrap"],
                    }
                ],
            },
        )
        buildkite["address"] = (
            "module.buildkite_federation.google_iam_workload_identity_pool_provider.buildkite"
        )
        gitops = self.resource(
            "google_iam_workload_identity_pool_provider",
            ["create"],
            {
                "project": "bootstrap-identity",
                "workload_identity_pool_id": "bootstrap-gitops",
                "workload_identity_pool_provider_id": "gitops",
                "disabled": False,
                "attribute_mapping": {
                    "google.subject": "assertion.sub",
                    "attribute.repository": "assertion.repository",
                    "attribute.ref": "assertion.ref",
                },
                "attribute_condition": " && ".join(
                    [
                        "assertion.sub == 'repo:mindclade/gitops:ref:refs/heads/main'",
                        "assertion.repository == 'mindclade/gitops'",
                        "assertion.ref == 'refs/heads/main'",
                    ]
                ),
                "oidc": [
                    {
                        "issuer_uri": "https://gitops.example.com",
                        "allowed_audiences": ["https://gitops.example.com/mindclade/bootstrap"],
                    }
                ],
            },
        )
        gitops["address"] = (
            "module.gitops_federation.google_iam_workload_identity_pool_provider.gitops"
        )
        result = self.check_plan([identity, buildkite, gitops])
        self.assertEqual(result.returncode, 0, result.stderr)

        gitops["change"]["after"]["attribute_condition"] = gitops["change"]["after"][
            "attribute_condition"
        ].replace("assertion.sub ==", "assertion.subject ==")
        result = self.check_plan([identity, buildkite, gitops])
        self.assertNotEqual(result.returncode, 0)

        gitops["change"]["after"]["attribute_condition"] = gitops["change"]["after"][
            "attribute_condition"
        ].replace("assertion.subject ==", "assertion.sub ==")
        buildkite["change"]["after"]["attribute_condition"] = buildkite["change"]["after"][
            "attribute_condition"
        ].replace(
            "assertion.sub == '0184990a-4782-42b5-afc1-16715b10b8ff'",
            "assertion.sub == 'another-pipeline'",
        )
        result = self.check_plan([identity, buildkite, gitops])
        self.assertNotEqual(result.returncode, 0)

        buildkite["change"]["after"]["attribute_condition"] = (
            buildkite["change"]["after"]["attribute_condition"]
            .replace(
                "assertion.sub == 'another-pipeline'",
                "assertion.sub == '0184990a-4782-42b5-afc1-16715b10b8ff'",
            )
            .replace("assertion.build_branch == 'main'", "assertion.build_branch == 'feature'")
        )
        result = self.check_plan([identity, buildkite, gitops])
        self.assertNotEqual(result.returncode, 0)

    def test_exact_resource_address_gate_rejects_arbitrary_for_each_keys(self):
        cases = (
            (
                "google_storage_bucket",
                'module.root_state.google_storage_bucket.state["archive"]',
            ),
            (
                "google_logging_organization_sink",
                'module.audit_root.google_logging_organization_sink.audit["debug"]',
            ),
            (
                "google_privileged_access_manager_entitlement",
                'module.break_glass.google_privileged_access_manager_entitlement.break_glass["organization-administration"]',
            ),
            (
                "google_storage_transfer_job",
                'module.recovery_exports.google_storage_transfer_job.state_export["all-state"]',
            ),
        )
        for resource_type, address in cases:
            with self.subTest(address=address):
                resource = self.resource(resource_type, ["create"], {})
                resource["address"] = address
                result = self.check_plan([resource])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("resource-address allowlist", result.stderr)

    def test_github_config_impersonation_is_provider_role_separated(self):
        identity_project = self.project_resource("identity", "bootstrap-identity")
        for identity in ("plan", "apply"):
            with self.subTest(identity=identity):
                binding = self.resource(
                    "google_service_account_iam_member",
                    ["create"],
                    {
                        "service_account_id": (
                            "projects/bootstrap-identity/serviceAccounts/"
                            f"github-config-{identity}@bootstrap-identity.iam.gserviceaccount.com"
                        ),
                        "role": "roles/iam.workloadIdentityUser",
                        "member": (
                            "principalSet://iam.googleapis.com/projects/123456789/"
                            "locations/global/workloadIdentityPools/github-config/"
                            f"attribute.github_config_identity/{identity}"
                        ),
                    },
                )
                binding["address"] = (
                    "module.github_federation.google_service_account_iam_member."
                    f'github_config["{identity}"]'
                )
                result = self.check_plan([identity_project, binding])
                self.assertEqual(result.returncode, 0, result.stderr)

                opposite = "apply" if identity == "plan" else "plan"
                binding["change"]["after"]["member"] = binding["change"]["after"]["member"].replace(
                    f"/{identity}", f"/{opposite}"
                )
                result = self.check_plan([identity_project, binding])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("provider-owned github-config identity", result.stderr)

                binding["change"]["after"]["member"] = (
                    "principalSet://iam.googleapis.com/projects/123456789/"
                    "locations/global/workloadIdentityPools/github-config/"
                    "attribute.repository_id/1350986053"
                )
                result = self.check_plan([identity_project, binding])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("provider-owned github-config identity", result.stderr)

    def test_project_service_and_audit_destinations_follow_planned_projects(self):
        identity = self.project_resource("identity", "bootstrap-identity")
        service = self.resource(
            "google_project_service",
            ["create"],
            {
                "project": "bootstrap-identity",
                "service": "iam.googleapis.com",
                "disable_on_destroy": False,
            },
        )
        service["address"] = 'google_project_service.identity["iam.googleapis.com"]'
        result = self.check_plan([identity, service])
        self.assertEqual(result.returncode, 0, result.stderr)

        for project_key, project_id, approved_services in (
            (
                "root_state",
                "bootstrap-state-root",
                ("iamcredentials.googleapis.com",),
            ),
            (
                "recovery",
                "bootstrap-recovery",
                ("iamcredentials.googleapis.com", "sts.googleapis.com"),
            ),
        ):
            for approved_service in approved_services:
                with self.subTest(project_key=project_key, service=approved_service):
                    project = self.project_resource(project_key, project_id)
                    identity_service = self.resource(
                        "google_project_service",
                        ["create"],
                        {
                            "project": project_id,
                            "service": approved_service,
                            "disable_on_destroy": False,
                        },
                    )
                    identity_service["address"] = (
                        f'google_project_service.state["{project_key}:{approved_service}"]'
                    )
                    result = self.check_plan([project, identity_service])
                    self.assertEqual(result.returncode, 0, result.stderr)

        root_sts = self.resource(
            "google_project_service",
            ["create"],
            {
                "project": "bootstrap-state-root",
                "service": "sts.googleapis.com",
                "disable_on_destroy": False,
            },
        )
        root_sts["address"] = 'google_project_service.state["root_state:sts.googleapis.com"]'
        result = self.check_plan(
            [self.project_resource("root_state", "bootstrap-state-root"), root_sts]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resource-address allowlist", result.stderr)

        audit = self.project_resource("audit", "bootstrap-audit")
        recovery = self.project_resource("recovery", "bootstrap-recovery")
        bucket = self.resource(
            "google_logging_project_bucket_config",
            ["create"],
            {
                "project": "bootstrap-audit",
                "location": "us-central1",
                "bucket_id": "bootstrap-audit-primary",
                "retention_days": 2555,
                "locked": False,
                "deletion_policy": "PREVENT",
                "cmek_settings": [{"kms_key_name": "kms-key"}],
            },
        )
        bucket["address"] = (
            'module.audit_root.google_logging_project_bucket_config.audit["primary"]'
        )
        sink = self.resource(
            "google_logging_organization_sink",
            ["create"],
            {
                "name": "bootstrap-admin-activity",
                "org_id": "123456789",
                "destination": (
                    "logging.googleapis.com/projects/bootstrap-audit/locations/"
                    "us-central1/buckets/bootstrap-audit-primary"
                ),
                "filter": 'log_id("cloudaudit.googleapis.com/activity")',
                "include_children": True,
                "intercept_children": False,
                "deletion_policy": "PREVENT",
                "disabled": False,
                "exclusions": [],
            },
        )
        sink["address"] = (
            'module.audit_root.google_logging_organization_sink.audit["admin-activity"]'
        )
        result = self.check_plan([audit, recovery, bucket, sink])
        self.assertEqual(result.returncode, 0, result.stderr)

        sink["change"]["after"]["destination"] = (
            "logging.googleapis.com/projects/bootstrap-audit/locations/"
            "us-central1/buckets/unreviewed"
        )
        result = self.check_plan([audit, recovery, bucket, sink])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("protected audit bucket", result.stderr)

        sink["change"]["after"]["destination"] = (
            "logging.googleapis.com/projects/bootstrap-audit/locations/"
            "us-central1/buckets/bootstrap-audit-primary"
        )
        sink["change"]["after"]["intercept_children"] = True
        result = self.check_plan([audit, recovery, bucket, sink])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("intercept_children", result.stderr)
        sink["change"]["after"]["intercept_children"] = False

        sink["change"]["after"]["unique_writer_identity"] = True
        result = self.check_plan([audit, recovery, bucket, sink])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unique_writer_identity", result.stderr)
        del sink["change"]["after"]["unique_writer_identity"]

        sink["change"]["after"]["destination"] = (
            "logging.googleapis.com/projects/bootstrap-audit/locations/"
            "us-central1/buckets/bootstrap-audit-primary"
        )
        for field, value in (("disabled", True), ("exclusions", [{"name": "all"}])):
            with self.subTest(field=field):
                original = sink["change"]["after"][field]
                sink["change"]["after"][field] = value
                result = self.check_plan([audit, recovery, bucket, sink])
                self.assertNotEqual(result.returncode, 0)
                sink["change"]["after"][field] = original

    def test_audit_configuration_read_role_and_binding_are_exact(self):
        audit = self.project_resource("audit", "bootstrap-audit")
        role = self.resource(
            "google_project_iam_custom_role",
            ["create"],
            {
                "project": "bootstrap-audit",
                "role_id": "bootstrapAuditPlanRead",
                "permissions": [
                    "iam.roles.get",
                    "logging.buckets.get",
                    "logging.cmekSettings.get",
                    "logging.views.getIamPolicy",
                ],
                "stage": "GA",
            },
        )
        role["address"] = 'module.audit_root.google_project_iam_custom_role.plan_read["primary"]'
        role["change"]["after_unknown"] = {"deleted": True}
        binding = self.resource(
            "google_project_iam_member",
            ["create"],
            {
                "project": "bootstrap-audit",
                "role": "projects/bootstrap-audit/roles/bootstrapAuditPlanRead",
                "member": (
                    "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com"
                ),
            },
        )
        binding["address"] = 'module.audit_root.google_project_iam_member.plan_read["primary"]'

        result = self.check_plan([audit, role, binding])
        self.assertEqual(result.returncode, 0, result.stderr)

        for actions in (["no-op"], ["update"]):
            with self.subTest(actions=actions):
                role["change"]["actions"] = actions
                result = self.check_plan([audit, role, binding])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("deleted state must be explicit false", result.stderr)
        role["change"]["actions"] = ["create"]

        role["change"]["after_unknown"] = {}
        result = self.check_plan([audit, role, binding])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deleted state must be explicit false", result.stderr)
        role["change"]["after_unknown"] = {"deleted": True}

        role["change"]["after_unknown"] = {"deleted": True, "permissions": True}
        result = self.check_plan([audit, role, binding])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions must exactly match", result.stderr)
        role["change"]["after_unknown"] = {"deleted": True}

        role["change"]["after"]["permissions"].append("logging.logEntries.list")
        result = self.check_plan([audit, role, binding])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions must exactly match", result.stderr)
        role["change"]["after"]["permissions"].pop()

        binding["change"]["after"]["member"] = (
            "serviceAccount:bootstrap-apply@bootstrap-state-root.iam.gserviceaccount.com"
        )
        result = self.check_plan([audit, role, binding])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bootstrap-plan", result.stderr)
        binding["change"]["after"]["member"] = (
            "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com"
        )
        binding["change"]["after"]["role"] = "projects/other-audit/roles/bootstrapAuditPlanRead"
        result = self.check_plan([audit, role, binding])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact audit configuration-read role", result.stderr)

    def test_organization_configuration_roles_and_bindings_are_exact(self):
        plan_role = self.resource(
            "google_organization_iam_custom_role",
            ["create"],
            {
                "org_id": "123456789",
                "role_id": "bootstrapOrganizationPlanRead",
                "permissions": [
                    "iam.roles.get",
                    "logging.sinks.get",
                    "resourcemanager.organizations.get",
                    "resourcemanager.organizations.getIamPolicy",
                ],
                "stage": "GA",
            },
        )
        plan_role["address"] = "google_organization_iam_custom_role.plan_read"
        plan_role["change"]["after_unknown"] = {"deleted": True}
        recovery_role = self.resource(
            "google_organization_iam_custom_role",
            ["create"],
            {
                "org_id": "123456789",
                "role_id": "bootstrapRecoverySinkRead",
                "permissions": [
                    "logging.sinks.get",
                    "resourcemanager.organizations.getIamPolicy",
                ],
                "stage": "GA",
            },
        )
        recovery_role["address"] = "google_organization_iam_custom_role.recovery_sink_read"
        recovery_role["change"]["after_unknown"] = {"deleted": True}
        apply_role = self.resource(
            "google_organization_iam_custom_role",
            ["create"],
            {
                "org_id": "123456789",
                "role_id": "bootstrapOrganizationIamApply",
                "permissions": [
                    "resourcemanager.organizations.getIamPolicy",
                    "resourcemanager.organizations.setIamPolicy",
                ],
                "stage": "GA",
            },
        )
        apply_role["address"] = "google_organization_iam_custom_role.apply_iam"
        apply_role["change"]["after_unknown"] = {"deleted": True}
        bindings = []
        for address, role, member in (
            (
                "google_organization_iam_member.plan_read",
                "organizations/123456789/roles/bootstrapOrganizationPlanRead",
                "serviceAccount:bootstrap-plan@bootstrap-state-root.iam.gserviceaccount.com",
            ),
            (
                "google_organization_iam_member.recovery_sink_read",
                "organizations/123456789/roles/bootstrapRecoverySinkRead",
                "serviceAccount:bootstrap-recovery@bootstrap-state-root.iam.gserviceaccount.com",
            ),
            (
                "google_organization_iam_member.apply_iam",
                "organizations/123456789/roles/bootstrapOrganizationIamApply",
                "group:root-trust-administrators@example.com",
            ),
            (
                "google_organization_iam_member.apply_organization_role_admin",
                "roles/iam.organizationRoleAdmin",
                "group:root-trust-administrators@example.com",
            ),
        ):
            binding = self.resource(
                "google_organization_iam_member",
                ["create"],
                {"org_id": "123456789", "role": role, "member": member},
            )
            binding["address"] = address
            bindings.append(binding)

        resources = [plan_role, recovery_role, apply_role, *bindings]
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        for custom_role in (plan_role, recovery_role, apply_role):
            with self.subTest(address=custom_role["address"], field="deleted"):
                custom_role["change"]["after_unknown"] = {}
                result = self.check_plan(resources)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("deleted state must be explicit false", result.stderr)
                custom_role["change"]["after_unknown"] = {"deleted": True}
            for actions in (["no-op"], ["update"]):
                with self.subTest(address=custom_role["address"], actions=actions):
                    custom_role["change"]["actions"] = actions
                    result = self.check_plan(resources)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("deleted state must be explicit false", result.stderr)
            custom_role["change"]["actions"] = ["create"]
            with self.subTest(address=custom_role["address"], field="stage"):
                custom_role["change"]["after_unknown"] = {
                    "deleted": True,
                    "stage": True,
                }
                result = self.check_plan(resources)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("stage must be explicit", result.stderr)
                custom_role["change"]["after_unknown"] = {"deleted": True}

        recovery_role["change"]["after"]["permissions"].append("logging.logEntries.list")
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions must exactly match", result.stderr)
        recovery_role["change"]["after"]["permissions"].pop()

        apply_role["change"]["after"]["permissions"].append("resourcemanager.projects.setIamPolicy")
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions must exactly match", result.stderr)
        apply_role["change"]["after"]["permissions"].pop()

        bindings[0]["change"]["after"]["role"] = (
            "organizations/987654321/roles/bootstrapOrganizationPlanRead"
        )
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same exact organization", result.stderr)
        bindings[0]["change"]["after"]["role"] = (
            "organizations/123456789/roles/bootstrapOrganizationPlanRead"
        )

        plan_role["change"]["after"]["org_id"] = "987654321"
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("matching custom role in the same exact organization", result.stderr)

    def test_audit_reader_is_scoped_to_the_exact_all_logs_view(self):
        audit = self.project_resource("audit", "bootstrap-audit")
        reader = self.resource(
            "google_project_iam_member",
            ["create"],
            {
                "project": "bootstrap-audit",
                "role": "roles/logging.viewAccessor",
                "member": "group:security@example.com",
                "condition": [
                    {
                        "title": "bootstrap-audit-primary-all-logs-view",
                        "description": "Exact protected audit view only.",
                        "expression": (
                            "resource.name == 'projects/bootstrap-audit/locations/"
                            "us-central1/buckets/bootstrap-audit-primary/views/_AllLogs'"
                        ),
                    }
                ],
            },
        )
        reader["address"] = (
            "module.audit_root.google_project_iam_member.reader["
            '"primary:group:security@example.com"]'
        )
        result = self.check_plan([audit, reader])
        self.assertEqual(result.returncode, 0, result.stderr)

        original_condition = json.loads(json.dumps(reader["change"]["after"]["condition"]))
        for condition, after_unknown in (
            ([], {}),
            (
                [
                    {
                        "title": "bootstrap-audit-primary-all-logs-view",
                        "expression": "resource.name.startsWith('projects/')",
                    }
                ],
                {},
            ),
            (original_condition, {"condition": [{"expression": True}]}),
        ):
            with self.subTest(condition=condition, after_unknown=after_unknown):
                reader["change"]["after"]["condition"] = condition
                reader["change"]["after_unknown"] = after_unknown
                result = self.check_plan([audit, reader])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("exact audit-bucket _AllLogs view", result.stderr)
        reader["change"]["after"]["condition"] = original_condition
        reader["change"]["after_unknown"] = {}

        reader["change"]["after"]["member"] = "group:not-an-email"
        result = self.check_plan([audit, reader])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical group", result.stderr)

    def test_federated_principal_kind_and_selector_must_match(self):
        invalid_principals = (
            (
                "principalSet://iam.googleapis.com/projects/123456789/locations/"
                "global/workloadIdentityPools/bootstrap-pool/subject/workload"
            ),
            (
                "principal://iam.googleapis.com/projects/123456789/locations/"
                "global/workloadIdentityPools/bootstrap-pool/group/security"
            ),
            (
                "principal://iam.googleapis.com/projects/123456789/locations/"
                "global/workloadIdentityPools/bootstrap-pool/"
                "attribute.repository/mindclade"
            ),
        )
        for principal in invalid_principals:
            with self.subTest(principal=principal):
                binding = self.resource(
                    "google_kms_key_ring_iam_member",
                    ["create"],
                    {
                        "key_ring_id": (
                            "projects/bootstrap-signing/locations/us-central1/"
                            "keyRings/bootstrap-signing"
                        ),
                        "role": "roles/cloudkms.admin",
                        "member": principal,
                    },
                )
                binding["address"] = (
                    "module.signing_root.google_kms_key_ring_iam_member."
                    f"administrator[{json.dumps(principal)}]"
                )
                result = self.check_plan([binding])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("resource-address allowlist", result.stderr)

    def test_all_audit_sinks_share_one_exact_bucket_scoped_writer(self):
        writer_identity = (
            "serviceAccount:service-org-123456789@gcp-sa-logging.iam.gserviceaccount.com"
        )
        contracts = {
            "admin-activity": (
                "bootstrap-admin-activity",
                'log_id("cloudaudit.googleapis.com/activity")',
                "bootstrap-audit",
                "us-central1",
                "bootstrap-audit-primary",
            ),
            "security-events": (
                "bootstrap-security-events",
                'severity>=WARNING OR protoPayload.serviceName="iam.googleapis.com"',
                "bootstrap-audit",
                "us-central1",
                "bootstrap-audit-primary",
            ),
            "data-access": (
                "bootstrap-data-access",
                'log_id("cloudaudit.googleapis.com/data_access") AND protoPayload.serviceName="storage.googleapis.com"',
                "bootstrap-audit",
                "us-central1",
                "bootstrap-audit-primary",
            ),
            "admin-activity-recovery": (
                "bootstrap-admin-activity-recovery",
                'log_id("cloudaudit.googleapis.com/activity")',
                "bootstrap-recovery",
                "us-east4",
                "bootstrap-audit-recovery",
            ),
            "security-events-recovery": (
                "bootstrap-security-events-recovery",
                'severity>=WARNING OR protoPayload.serviceName="iam.googleapis.com"',
                "bootstrap-recovery",
                "us-east4",
                "bootstrap-audit-recovery",
            ),
            "data-access-recovery": (
                "bootstrap-data-access-recovery",
                'log_id("cloudaudit.googleapis.com/data_access") AND protoPayload.serviceName="storage.googleapis.com"',
                "bootstrap-recovery",
                "us-east4",
                "bootstrap-audit-recovery",
            ),
        }

        sinks = []
        for key, (name, filter_value, project, location, bucket) in contracts.items():
            sink = self.resource(
                "google_logging_organization_sink",
                ["no-op"],
                {
                    "name": name,
                    "org_id": "123456789",
                    "destination": (
                        f"logging.googleapis.com/projects/{project}/locations/"
                        f"{location}/buckets/{bucket}"
                    ),
                    "filter": filter_value,
                    "include_children": True,
                    "intercept_children": False,
                    "deletion_policy": "PREVENT",
                    "disabled": False,
                    "exclusions": [],
                    "writer_identity": writer_identity,
                },
            )
            sink["address"] = f'module.audit_root.google_logging_organization_sink.audit["{key}"]'
            sinks.append(sink)

        writers = []
        for key, project, location, bucket in (
            (
                "primary",
                "bootstrap-audit",
                "us-central1",
                "bootstrap-audit-primary",
            ),
            (
                "recovery",
                "bootstrap-recovery",
                "us-east4",
                "bootstrap-audit-recovery",
            ),
        ):
            writer = self.resource(
                "google_project_iam_member",
                ["no-op"],
                {
                    "project": project,
                    "role": "roles/logging.bucketWriter",
                    "member": writer_identity,
                    "condition": [
                        {
                            "title": f"bootstrap-audit-{key}-bucket-only",
                            "description": "Exact protected audit bucket only.",
                            "expression": (
                                "resource.type == 'logging.googleapis.com/LogBucket' "
                                "&& resource.name == "
                                f"'projects/{project}/locations/{location}/buckets/{bucket}'"
                            ),
                        }
                    ],
                },
            )
            writer["address"] = f'module.audit_root.google_project_iam_member.sink_writer["{key}"]'
            writers.append(writer)

        projects = [
            self.project_resource("audit", "bootstrap-audit"),
            self.project_resource("recovery", "bootstrap-recovery"),
        ]
        resources = [*projects, *sinks, *writers]
        result = self.check_plan(resources)
        self.assertEqual(result.returncode, 0, result.stderr)

        original_condition = writers[0]["change"]["after"]["condition"]
        writers[0]["change"]["after"]["condition"] = []
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact protected audit bucket", result.stderr)
        writers[0]["change"]["after"]["condition"] = original_condition

        sinks[1]["change"]["after"]["writer_identity"] = (
            "serviceAccount:service-org-987654321@gcp-sa-logging.iam.gserviceaccount.com"
        )
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("all destination bucket sinks", result.stderr)

        sinks[1]["change"]["after"]["writer_identity"] = writer_identity
        different_organization_identity = (
            "serviceAccount:service-org-987654321@gcp-sa-logging.iam.gserviceaccount.com"
        )
        for sink in sinks[2:]:
            sink["change"]["after"]["org_id"] = "987654321"
            sink["change"]["after"]["writer_identity"] = different_organization_identity
        writers[1]["change"]["after"]["member"] = different_organization_identity
        result = self.check_plan(resources)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("across all six sinks", result.stderr)

    def test_audit_retention_lock_is_one_way_and_qualification_bound(self):
        project = self.project_resource("audit", "bootstrap-audit")

        def audit_bucket(actions, before_locked, after_locked):
            resource = self.resource(
                "google_logging_project_bucket_config",
                actions,
                {
                    "project": "bootstrap-audit",
                    "location": "us-central1",
                    "bucket_id": "bootstrap-audit-primary",
                    "retention_days": 2555,
                    "locked": after_locked,
                    "deletion_policy": "PREVENT",
                    "cmek_settings": [{"kms_key_name": "kms-key"}],
                },
            )
            resource["address"] = (
                'module.audit_root.google_logging_project_bucket_config.audit["primary"]'
            )
            if before_locked is not None:
                resource["change"]["before"] = dict(resource["change"]["after"])
                resource["change"]["before"]["locked"] = before_locked
            return resource

        signing = self.initial_signing_create_document()["variables"]
        bootstrap = signing["bootstrap"]["value"]
        bootstrap["audit"] = {
            "lock_after_qualification": True,
            "qualification_evidence": {
                "artifact_sha256": "sha256:" + "a" * 64,
                "signature_sha256": "sha256:" + "b" * 64,
                "signing_key_ref": "audit-anchor:v20260829",
                "qualified_source_sha": "c" * 40,
                "qualified_at": "2026-08-29T12:00:00Z",
            },
        }

        valid = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": [project, audit_bucket(["update"], False, True)],
            "variables": signing,
        }
        result = self.run_plan_document("plan-resource-check", valid)
        self.assertEqual(result.returncode, 0, result.stderr)

        cases = (
            audit_bucket(["create"], None, True),
            audit_bucket(["update"], True, False),
            audit_bucket(["update"], True, True),
        )
        for resource in cases:
            with self.subTest(
                actions=resource["change"]["actions"], after=resource["change"]["after"]["locked"]
            ):
                document = json.loads(json.dumps(valid))
                document["resource_changes"] = [project, resource]
                result = self.run_plan_document("plan-resource-check", document)
                self.assertNotEqual(result.returncode, 0)

        no_evidence = json.loads(json.dumps(valid))
        no_evidence["variables"]["bootstrap"]["value"]["audit"]["qualification_evidence"] = None
        result = self.run_plan_document("plan-resource-check", no_evidence)
        self.assertNotEqual(result.returncode, 0)

    def test_pam_entitlement_is_tied_to_its_planned_project(self):
        project = self.project_resource("root_state", "bootstrap-state-root")
        entitlement = self.resource(
            "google_privileged_access_manager_entitlement",
            ["create"],
            {
                "entitlement_id": "root-trust-administration",
                "location": "global",
                "parent": "projects/bootstrap-state-root",
                "max_request_duration": "7200s",
                "deletion_policy": "PREVENT",
                "requester_justification_config": [{"unstructured": [{}]}],
                "eligible_users": [
                    {
                        "principals": [
                            "user:requester-one@example.com",
                            "user:requester-two@example.com",
                        ]
                    }
                ],
                "privileged_access": [
                    {
                        "gcp_iam_access": [
                            {
                                "resource": "//cloudresourcemanager.googleapis.com/projects/bootstrap-state-root",
                                "resource_type": "cloudresourcemanager.googleapis.com/Project",
                                "role_bindings": [
                                    {"role": "roles/iam.securityAdmin"},
                                    {"role": "roles/resourcemanager.projectIamAdmin"},
                                ],
                            }
                        ]
                    }
                ],
                "approval_workflow": [
                    {
                        "manual_approvals": [
                            {
                                "require_approver_justification": True,
                                "steps": [
                                    {
                                        "approvals_needed": 1,
                                        "approver_email_recipients": [
                                            "approver-one@example.com",
                                            "approver-two@example.com",
                                        ],
                                        "approvers": [
                                            {"principals": ["user:approver-one@example.com"]}
                                        ],
                                    },
                                    {
                                        "approvals_needed": 1,
                                        "approver_email_recipients": [
                                            "approver-one@example.com",
                                            "approver-two@example.com",
                                        ],
                                        "approvers": [
                                            {"principals": ["user:approver-two@example.com"]}
                                        ],
                                    },
                                ],
                            }
                        ]
                    }
                ],
                "additional_notification_targets": [
                    {
                        "admin_email_recipients": ["security@example.com"],
                        "requester_email_recipients": ["security@example.com"],
                    }
                ],
            },
        )
        entitlement["address"] = (
            "module.break_glass.google_privileged_access_manager_entitlement."
            'break_glass["root-trust-administration"]'
        )
        result = self.check_plan([project, entitlement])
        self.assertEqual(result.returncode, 0, result.stderr)

        variables = self.initial_signing_create_document()["variables"]
        bootstrap = variables["bootstrap"]["value"]
        bootstrap.update(
            {
                "organization_id": "123456789",
                "billing_account": "ABCDEF-123456-ABCDEF",
                "projects": {},
                "break_glass": {
                    "requester_principals": [
                        "user:requester-one@example.com",
                        "user:requester-two@example.com",
                    ],
                    "approver_principals": [
                        "user:approver-one@example.com",
                        "user:approver-two@example.com",
                    ],
                    "notification_recipients": ["security@example.com"],
                },
            }
        )
        declarations = {
            key: value["versions"] for key, value in bootstrap["signing"]["keys"].items()
        }
        strict_document = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": [project, entitlement],
            "configuration": {
                "provider_config": {
                    "google": {
                        "name": "google",
                        "full_name": "registry.opentofu.org/hashicorp/google",
                    }
                },
                "root_module": {},
            },
            "variables": variables,
            "output_changes": {
                "signing_version_declarations": {
                    "actions": ["create"],
                    "before": None,
                    "after": declarations,
                    "after_unknown": {},
                }
            },
        }
        diagnostic = (
            "requesters, approvers, and notification recipients must exactly "
            "equal the compiled break-glass principals"
        )
        result = self.run_plan_document("plan-check", strict_document, "--root", "root-trust")
        self.assertNotIn(diagnostic, result.stderr)
        notifications = entitlement["change"]["after"]["additional_notification_targets"][0]
        notifications["admin_email_recipients"] = ["unreviewed-security@example.com"]
        notifications["requester_email_recipients"] = ["unreviewed-security@example.com"]
        result = self.run_plan_document("plan-check", strict_document, "--root", "root-trust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(diagnostic, result.stderr)
        notifications["admin_email_recipients"] = ["security@example.com"]
        notifications["requester_email_recipients"] = ["security@example.com"]

        entitlement["change"]["after"]["parent"] = "projects/arbitrary-project"
        entitlement["change"]["after"]["privileged_access"][0]["gcp_iam_access"][0]["resource"] = (
            "//cloudresourcemanager.googleapis.com/projects/arbitrary-project"
        )
        result = self.check_plan([project, entitlement])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact planned root project", result.stderr)

    def test_write_only_workforce_secret_metadata_is_accepted(self):
        resource = self.resource(
            "google_iam_workforce_pool_provider",
            ["create"],
            {
                "workforce_pool_id": "mindclade-workforce",
                "provider_id": "primary-idp",
                "location": "global",
                "detailed_audit_logging": True,
                "disabled": False,
                "attribute_condition": "assertion.groups.exists(group, group == 'group:admins@example.com')",
                "attribute_mapping": {
                    "google.subject": "assertion.sub",
                    "google.display_name": "assertion.name",
                    "google.groups": "assertion.groups",
                },
                "oidc": [
                    {
                        "issuer_uri": "https://identity.example.com",
                        "client_id": "bootstrap",
                        "client_secret": [
                            {
                                "value": [
                                    {
                                        "plain_text_wo": None,
                                        "plain_text_wo_version": 1,
                                    }
                                ]
                            }
                        ],
                        "web_sso_config": [
                            {
                                "response_type": "CODE",
                                "assertion_claims_behavior": "MERGE_USER_INFO_OVER_ID_TOKEN_CLAIMS",
                                "additional_scopes": ["groups"],
                            }
                        ],
                    }
                ],
            },
        )
        resource["address"] = "module.workforce_identity.google_iam_workforce_pool_provider.oidc"
        result = self.check_plan([resource])
        self.assertEqual(result.returncode, 0, result.stderr)

        before = json.loads(json.dumps(resource["change"]["after"]))
        before["oidc"][0]["client_secret"][0]["value"][0]["plain_text_wo_version"] = 2
        resource["change"]["actions"] = ["update"]
        resource["change"]["before"] = before
        result = self.check_plan([resource])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("revision must increase", result.stderr)

    def test_strict_workforce_graph_equals_the_compiled_manifest_values(self):
        workforce = {
            "pool_id": "mindclade-workforce",
            "provider_id": "primary-idp",
            "issuer_uri": "https://identity.example.com",
            "client_id": "mindclade-bootstrap",
            "administrator_group": "group:administrators@example.com",
            "attribute_mapping": {
                "google.subject": "assertion.sub",
                "google.display_name": "assertion.name",
                "google.groups": "assertion.groups",
            },
            "attribute_condition": (
                "assertion.groups.exists(group, group == 'group:administrators@example.com')"
            ),
            "additional_scopes": ["groups"],
        }
        pool = self.resource(
            "google_iam_workforce_pool",
            ["create"],
            {
                "workforce_pool_id": workforce["pool_id"],
                "parent": "organizations/123456789",
                "location": "global",
                "disabled": False,
            },
        )
        pool["address"] = "module.workforce_identity.google_iam_workforce_pool.workforce"
        provider = self.resource(
            "google_iam_workforce_pool_provider",
            ["create"],
            {
                "workforce_pool_id": workforce["pool_id"],
                "provider_id": workforce["provider_id"],
                "location": "global",
                "detailed_audit_logging": True,
                "disabled": False,
                "attribute_condition": workforce["attribute_condition"],
                "attribute_mapping": workforce["attribute_mapping"],
                "oidc": [
                    {
                        "issuer_uri": workforce["issuer_uri"],
                        "client_id": workforce["client_id"],
                        "client_secret": [
                            {
                                "value": [
                                    {
                                        "plain_text_wo": None,
                                        "plain_text_wo_version": 1,
                                    }
                                ]
                            }
                        ],
                        "web_sso_config": [
                            {
                                "response_type": "CODE",
                                "assertion_claims_behavior": (
                                    "MERGE_USER_INFO_OVER_ID_TOKEN_CLAIMS"
                                ),
                                "additional_scopes": workforce["additional_scopes"],
                            }
                        ],
                    }
                ],
            },
        )
        provider["address"] = "module.workforce_identity.google_iam_workforce_pool_provider.oidc"
        variables = self.initial_signing_create_document()["variables"]
        bootstrap = variables["bootstrap"]["value"]
        bootstrap.update(
            {
                "organization_id": "123456789",
                "billing_account": "ABCDEF-123456-ABCDEF",
                "projects": {},
                "workforce": workforce,
            }
        )
        declarations = {
            key: value["versions"] for key, value in bootstrap["signing"]["keys"].items()
        }
        document = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": [pool, provider],
            "configuration": {
                "provider_config": {
                    "google": {
                        "name": "google",
                        "full_name": "registry.opentofu.org/hashicorp/google",
                    }
                },
                "root_module": {},
            },
            "variables": variables,
            "output_changes": {
                "signing_version_declarations": {
                    "actions": ["create"],
                    "before": None,
                    "after": declarations,
                    "after_unknown": {},
                }
            },
        }
        result = self.run_plan_document("plan-check", document, "--root", "root-trust")
        diagnostic = "workforce pool and provider must exactly equal the compiled"
        self.assertNotIn(diagnostic, result.stderr)

        document["resource_changes"][1]["change"]["after"]["oidc"][0]["issuer_uri"] = (
            "https://unreviewed.example.com"
        )
        result = self.run_plan_document("plan-check", document, "--root", "root-trust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(diagnostic, result.stderr)

    def test_strict_state_backends_equal_the_compiled_names_and_keys(self):
        declarations = {
            "root_trust": {
                "bucket_name": "bootstrap-root-state",
                "replica_bucket_name": "bootstrap-root-replica",
                "key_name": "root-state-key",
                "replica_key_name": "root-replica-key",
                "prefix": "root-trust",
            },
            "recovery_plane": {
                "bucket_name": "bootstrap-recovery-state",
                "replica_bucket_name": "bootstrap-recovery-replica",
                "key_name": "recovery-state-key",
                "replica_key_name": "recovery-replica-key",
                "prefix": "recovery-plane",
            },
        }

        def bucket(address, project, name, location, key):
            resource = self.resource(
                "google_storage_bucket",
                ["no-op"],
                {
                    "project": project,
                    "name": name,
                    "location": location,
                    "storage_class": "STANDARD",
                    "uniform_bucket_level_access": True,
                    "public_access_prevention": "enforced",
                    "force_destroy": False,
                    "versioning": [{"enabled": True}],
                    "encryption": [{"default_kms_key_name": key}],
                    "soft_delete_policy": [{"retention_duration_seconds": 2592000}],
                    "lifecycle_rule": [
                        {
                            "action": [{"type": "Delete"}],
                            "condition": [
                                {
                                    "days_since_noncurrent_time": 365,
                                    "num_newer_versions": 3,
                                    "send_age_if_zero": False,
                                }
                            ],
                        }
                    ],
                },
            )
            resource["address"] = address
            return resource

        def crypto_key(address, name, key_ring):
            resource = self.resource(
                "google_kms_crypto_key",
                ["no-op"],
                {
                    "name": name,
                    "key_ring": key_ring,
                    "purpose": "ENCRYPT_DECRYPT",
                    "rotation_period": "7776000s",
                    "destroy_scheduled_duration": "2592000s",
                    "version_template": [
                        {
                            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                            "protection_level": "HSM",
                        }
                    ],
                },
            )
            resource["address"] = address
            return resource

        resources = []
        contracts = (
            (
                "module.root_state",
                declarations["root_trust"],
                "bootstrap-state-root",
                "bootstrap-recovery",
                "us-central1",
                "us-east4",
            ),
            (
                "module.recovery_state",
                declarations["recovery_plane"],
                "bootstrap-recovery",
                "bootstrap-state-root",
                "us-east4",
                "us-central1",
            ),
        )
        for (
            module,
            declared,
            primary_project,
            replica_project,
            primary_region,
            replica_region,
        ) in contracts:
            primary_ring = (
                f"projects/{primary_project}/locations/{primary_region}/keyRings/state-backend"
            )
            replica_ring = (
                f"projects/{replica_project}/locations/{replica_region}/keyRings/state-replica"
            )
            primary_key = f"{primary_ring}/cryptoKeys/{declared['key_name']}"
            replica_key = f"{replica_ring}/cryptoKeys/{declared['replica_key_name']}"
            resources.extend(
                [
                    crypto_key(
                        f"{module}.google_kms_crypto_key.state",
                        declared["key_name"],
                        primary_ring,
                    ),
                    crypto_key(
                        f"{module}.google_kms_crypto_key.replica",
                        declared["replica_key_name"],
                        replica_ring,
                    ),
                    bucket(
                        f'{module}.google_storage_bucket.state["primary"]',
                        primary_project,
                        declared["bucket_name"],
                        primary_region.upper(),
                        primary_key,
                    ),
                    bucket(
                        f'{module}.google_storage_bucket.state["replica"]',
                        replica_project,
                        declared["replica_bucket_name"],
                        replica_region.upper(),
                        replica_key,
                    ),
                ]
            )

        variables = self.initial_signing_create_document()["variables"]
        bootstrap = variables["bootstrap"]["value"]
        bootstrap.update(
            {
                "organization_id": "123456789",
                "billing_account": "ABCDEF-123456-ABCDEF",
                "projects": {},
                "state_backends": declarations,
            }
        )
        signing_declarations = {
            key: value["versions"] for key, value in bootstrap["signing"]["keys"].items()
        }
        document = {
            "format_version": "1.2",
            "terraform_version": "1.12.6",
            "resource_changes": resources,
            "configuration": {
                "provider_config": {
                    "google": {
                        "name": "google",
                        "full_name": "registry.opentofu.org/hashicorp/google",
                    }
                },
                "root_module": {},
            },
            "variables": variables,
            "output_changes": {
                "signing_version_declarations": {
                    "actions": ["create"],
                    "before": None,
                    "after": signing_declarations,
                    "after_unknown": {},
                }
            },
        }
        diagnostic = "bucket, replica, CMEKs, and prefix must exactly equal"
        result = self.run_plan_document("plan-check", document, "--root", "root-trust")
        self.assertNotIn(diagnostic, result.stderr)

        document["variables"]["bootstrap"]["value"]["state_backends"]["root_trust"]["key_name"] = (
            "unreviewed-state-key"
        )
        result = self.run_plan_document("plan-check", document, "--root", "root-trust")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(diagnostic, result.stderr)

    def test_concrete_write_only_secret_value_is_rejected(self):
        result = self.check_plan(
            [
                self.resource(
                    "google_iam_workforce_pool_provider",
                    ["create"],
                    {
                        "attribute_condition": "assertion.groups.exists(group, group == 'admins')",
                        "attribute_mapping": {"google.subject": "assertion.sub"},
                        "client_secret": [
                            {
                                "value": [
                                    {
                                        "plain_text_wo": "not-a-real-secret",
                                        "plain_text_wo_version": 1,
                                    }
                                ]
                            }
                        ],
                    },
                )
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("static credential field plain_text_wo", result.stderr)


if __name__ == "__main__":
    unittest.main()
