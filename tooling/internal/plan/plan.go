// Package plan provides fail-closed inspection of OpenTofu JSON plans.
package plan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var prohibitedResourceTypes = map[string]bool{
	"google_service_account_key": true,
}

var prohibitedResourcePrefixes = []string{
	"google_cloud_run_",
	"google_cloudfunctions_",
	"google_compute_",
	"google_container_",
	"google_sql_",
	"helm_",
	"kubernetes_",
}

var preventDeletionPolicyTypes = map[string]bool{
	"google_iam_workforce_pool":                    true,
	"google_iam_workforce_pool_provider":           true,
	"google_iam_workload_identity_pool":            true,
	"google_iam_workload_identity_pool_provider":   true,
	"google_kms_crypto_key":                        true,
	"google_kms_crypto_key_version":                true,
	"google_logging_organization_sink":             true,
	"google_logging_project_bucket_config":         true,
	"google_organization_iam_custom_role":          true,
	"google_privileged_access_manager_entitlement": true,
	"google_project":                               true,
	"google_project_iam_custom_role":               true,
	"google_project_service":                       true,
	"google_service_account":                       true,
	"google_storage_bucket":                        true,
	"google_storage_transfer_job":                  true,
}

var approvedResourceTypes = map[string]bool{
	"google_iam_workforce_pool":                       true,
	"google_iam_workforce_pool_provider":              true,
	"google_iam_workload_identity_pool":               true,
	"google_iam_workload_identity_pool_provider":      true,
	"google_kms_crypto_key":                           true,
	"google_kms_crypto_key_iam_member":                true,
	"google_kms_crypto_key_version":                   true,
	"google_kms_key_ring":                             true,
	"google_kms_key_ring_iam_member":                  true,
	"google_logging_organization_sink":                true,
	"google_logging_project_bucket_config":            true,
	"google_logging_project_cmek_settings":            true,
	"google_organization_iam_audit_config":            true,
	"google_organization_iam_custom_role":             true,
	"google_organization_iam_member":                  true,
	"google_privileged_access_manager_entitlement":    true,
	"google_project":                                  true,
	"google_project_iam_custom_role":                  true,
	"google_project_iam_member":                       true,
	"google_project_service":                          true,
	"google_secret_manager_secret":                    true,
	"google_secret_manager_secret_iam_member":         true,
	"google_secret_manager_secret_version":            true,
	"google_service_account":                          true,
	"google_service_account_iam_member":               true,
	"google_storage_bucket":                           true,
	"google_storage_bucket_iam_member":                true,
	"google_storage_bucket_object":                    true,
	"google_storage_project_service_account":          true,
	"google_storage_transfer_job":                     true,
	"google_storage_transfer_project_service_account": true,
}

var approvedResourceAddressFamilies = map[string]bool{
	"managed|google_organization_iam_member|google_organization_iam_member.apply_logging_config_writer":     true,
	"managed|google_organization_iam_member|google_organization_iam_member.apply_iam":                       true,
	"managed|google_organization_iam_member|google_organization_iam_member.apply_organization_role_admin":   true,
	"managed|google_organization_iam_member|google_organization_iam_member.apply_workforce_admin":           true,
	"managed|google_organization_iam_custom_role|google_organization_iam_custom_role.plan_read":             true,
	"managed|google_organization_iam_custom_role|google_organization_iam_custom_role.recovery_sink_read":    true,
	"managed|google_organization_iam_custom_role|google_organization_iam_custom_role.apply_iam":             true,
	"managed|google_organization_iam_member|google_organization_iam_member.plan_read":                       true,
	"managed|google_organization_iam_member|google_organization_iam_member.plan_workforce_viewer":           true,
	"managed|google_organization_iam_member|google_organization_iam_member.recovery_sink_read":              true,
	"managed|google_organization_iam_audit_config|google_organization_iam_audit_config.storage_data_access": true,
	"managed|google_project|google_project.identity":                                                        true,
	"managed|google_project|google_project.state":                                                           true,
	"managed|google_project_iam_member|google_project_iam_member.apply_administration":                      true,
	"managed|google_project_iam_member|google_project_iam_member.plan_read":                                 true,
	"managed|google_project_iam_member|google_project_iam_member.recovery_administration":                   true,
	"managed|google_project_service|google_project_service.identity":                                        true,
	"managed|google_project_service|google_project_service.state":                                           true,

	"managed|google_iam_workload_identity_pool|module.buildkite_federation.google_iam_workload_identity_pool.buildkite":                           true,
	"managed|google_iam_workload_identity_pool_provider|module.buildkite_federation.google_iam_workload_identity_pool_provider.buildkite":         true,
	"managed|google_service_account|module.buildkite_federation.google_service_account.buildkite":                                                 true,
	"managed|google_service_account_iam_member|module.buildkite_federation.google_service_account_iam_member.buildkite":                           true,
	"managed|google_iam_workload_identity_pool|module.github_federation.google_iam_workload_identity_pool.github":                                 true,
	"managed|google_iam_workload_identity_pool_provider|module.github_federation.google_iam_workload_identity_pool_provider.github":               true,
	"managed|google_service_account|module.github_federation.google_service_account.github":                                                       true,
	"managed|google_service_account_iam_member|module.github_federation.google_service_account_iam_member.github":                                 true,
	"managed|google_iam_workload_identity_pool|module.github_federation.google_iam_workload_identity_pool.github_config":                          true,
	"managed|google_iam_workload_identity_pool_provider|module.github_federation.google_iam_workload_identity_pool_provider.github_config":        true,
	"managed|google_service_account|module.github_federation.google_service_account.github_config":                                                true,
	"managed|google_service_account_iam_member|module.github_federation.google_service_account_iam_member.github_config":                          true,
	"managed|google_iam_workload_identity_pool|module.github_federation.google_iam_workload_identity_pool.infrastructure_live":                    true,
	"managed|google_iam_workload_identity_pool_provider|module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_live":  true,
	"managed|google_service_account|module.github_federation.google_service_account.infrastructure_live":                                          true,
	"managed|google_service_account_iam_member|module.github_federation.google_service_account_iam_member.infrastructure_live":                    true,
	"managed|google_iam_workload_identity_pool_provider|module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_drift": true,
	"managed|google_service_account|module.github_federation.google_service_account.infrastructure_drift":                                         true,
	"managed|google_service_account_iam_member|module.github_federation.google_service_account_iam_member.infrastructure_drift":                   true,
	"managed|google_iam_workload_identity_pool|module.github_federation.google_iam_workload_identity_pool.ci_evidence":                            true,
	"managed|google_iam_workload_identity_pool_provider|module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence":          true,
	"managed|google_service_account|module.github_federation.google_service_account.ci_evidence":                                                  true,
	"managed|google_service_account_iam_member|module.github_federation.google_service_account_iam_member.ci_evidence":                            true,
	"managed|google_iam_workload_identity_pool|module.gitops_federation.google_iam_workload_identity_pool.gitops":                                 true,
	"managed|google_iam_workload_identity_pool_provider|module.gitops_federation.google_iam_workload_identity_pool_provider.gitops":               true,
	"managed|google_service_account|module.gitops_federation.google_service_account.gitops":                                                       true,
	"managed|google_service_account_iam_member|module.gitops_federation.google_service_account_iam_member.gitops":                                 true,

	"managed|google_project|module.audit_root.google_project.audit":                                               true,
	"managed|google_project_service|module.audit_root.google_project_service.required":                            true,
	"managed|google_kms_key_ring|module.audit_root.google_kms_key_ring.audit":                                     true,
	"managed|google_kms_crypto_key|module.audit_root.google_kms_crypto_key.audit":                                 true,
	"managed|google_kms_crypto_key_iam_member|module.audit_root.google_kms_crypto_key_iam_member.logging":         true,
	"managed|google_logging_project_bucket_config|module.audit_root.google_logging_project_bucket_config.audit":   true,
	"managed|google_logging_organization_sink|module.audit_root.google_logging_organization_sink.audit":           true,
	"managed|google_project_iam_member|module.audit_root.google_project_iam_member.sink_writer":                   true,
	"managed|google_project_iam_member|module.audit_root.google_project_iam_member.reader":                        true,
	"managed|google_project_iam_member|module.audit_root.google_project_iam_member.administrator":                 true,
	"managed|google_project_iam_custom_role|module.audit_root.google_project_iam_custom_role.plan_read":           true,
	"managed|google_project_iam_member|module.audit_root.google_project_iam_member.plan_read":                     true,
	"data|google_logging_project_cmek_settings|module.audit_root.data.google_logging_project_cmek_settings.audit": true,

	"managed|google_iam_workforce_pool|module.workforce_identity.google_iam_workforce_pool.workforce":                                  true,
	"managed|google_iam_workforce_pool_provider|module.workforce_identity.google_iam_workforce_pool_provider.oidc":                     true,
	"managed|google_project_service|module.break_glass.google_project_service.pam":                                                     true,
	"managed|google_privileged_access_manager_entitlement|module.break_glass.google_privileged_access_manager_entitlement.break_glass": true,

	"managed|google_project|module.signing_root.google_project.signing":                                                              true,
	"managed|google_project_service|module.signing_root.google_project_service.required":                                             true,
	"managed|google_project_iam_custom_role|module.signing_root.google_project_iam_custom_role.recovery_metadata":                    true,
	"managed|google_kms_key_ring|module.signing_root.google_kms_key_ring.signing":                                                    true,
	"managed|google_kms_crypto_key|module.signing_root.google_kms_crypto_key.signing":                                                true,
	"managed|google_kms_crypto_key_version|module.signing_root.google_kms_crypto_key_version.signing":                                true,
	"data|google_kms_crypto_key_version|module.signing_root.data.google_kms_crypto_key_version.active":                               true,
	"managed|google_kms_key_ring_iam_member|module.signing_root.google_kms_key_ring_iam_member.administrator":                        true,
	"managed|google_kms_crypto_key_iam_member|module.signing_root.google_kms_crypto_key_iam_member.signer":                           true,
	"managed|google_kms_crypto_key_iam_member|module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata":                true,
	"managed|google_secret_manager_secret|module.signing_root.google_secret_manager_secret.nix_cache_signing":                        true,
	"managed|google_secret_manager_secret_iam_member|module.signing_root.google_secret_manager_secret_iam_member.nix_cache_accessor": true,
	"managed|google_secret_manager_secret_version|module.signing_root.google_secret_manager_secret_version.nix_cache_signing":        true,

	"managed|google_project_iam_custom_role|module.recovery_exports.google_project_iam_custom_role.plan_read":                                        true,
	"managed|google_project_iam_custom_role|module.recovery_exports.google_project_iam_custom_role.plan_object_read":                                 true,
	"managed|google_kms_key_ring|module.recovery_exports.google_kms_key_ring.recovery":                                                               true,
	"managed|google_kms_crypto_key|module.recovery_exports.google_kms_crypto_key.recovery":                                                           true,
	"managed|google_service_account|module.recovery_exports.google_service_account.state_export":                                                     true,
	"managed|google_project_iam_custom_role|module.recovery_exports.google_project_iam_custom_role.state_export_source_metadata":                     true,
	"managed|google_project_iam_custom_role|module.recovery_exports.google_project_iam_custom_role.state_export_source_object":                       true,
	"managed|google_project_iam_custom_role|module.recovery_exports.google_project_iam_custom_role.state_export_transfer_events":                     true,
	"managed|google_project_iam_custom_role|module.recovery_exports.google_project_iam_custom_role.state_export_storage_events":                      true,
	"managed|google_project_iam_custom_role|module.recovery_exports.google_project_iam_custom_role.state_export_destination_metadata":                true,
	"managed|google_project_iam_custom_role|module.recovery_exports.google_project_iam_custom_role.state_export_destination_object":                  true,
	"managed|google_kms_crypto_key_iam_member|module.recovery_exports.google_kms_crypto_key_iam_member.storage":                                      true,
	"managed|google_storage_bucket|module.recovery_exports.google_storage_bucket.recovery":                                                           true,
	"managed|google_storage_bucket_iam_member|module.recovery_exports.google_storage_bucket_iam_member.access":                                       true,
	"managed|google_storage_bucket_iam_member|module.recovery_exports.google_storage_bucket_iam_member.plan_read":                                    true,
	"managed|google_storage_bucket_iam_member|module.recovery_exports.google_storage_bucket_iam_member.plan_object_read":                             true,
	"managed|google_service_account_iam_member|module.recovery_exports.google_service_account_iam_member.state_export_apply":                         true,
	"managed|google_service_account_iam_member|module.recovery_exports.google_service_account_iam_member.state_export_transfer":                      true,
	"managed|google_project_iam_member|module.recovery_exports.google_project_iam_member.state_export_transfer_events":                               true,
	"managed|google_project_iam_member|module.recovery_exports.google_project_iam_member.state_export_storage_events":                                true,
	"managed|google_storage_bucket_iam_member|module.recovery_exports.google_storage_bucket_iam_member.state_export_source_metadata":                 true,
	"managed|google_storage_bucket_iam_member|module.recovery_exports.google_storage_bucket_iam_member.state_export_source_object":                   true,
	"managed|google_storage_bucket_iam_member|module.recovery_exports.google_storage_bucket_iam_member.state_export_destination_metadata":            true,
	"managed|google_storage_bucket_iam_member|module.recovery_exports.google_storage_bucket_iam_member.state_export_destination_object":              true,
	"managed|google_storage_transfer_job|module.recovery_exports.google_storage_transfer_job.state_export":                                           true,
	"managed|google_storage_bucket_object|module.recovery_exports.google_storage_bucket_object.public_trust_metadata":                                true,
	"managed|google_storage_bucket_object|module.recovery_exports.google_storage_bucket_object.restore_inventory":                                    true,
	"data|google_storage_project_service_account|module.recovery_exports.data.google_storage_project_service_account.recovery":                       true,
	"data|google_storage_project_service_account|module.recovery_exports.data.google_storage_project_service_account.state_export_source":            true,
	"data|google_storage_transfer_project_service_account|module.recovery_exports.data.google_storage_transfer_project_service_account.state_export": true,
}

var exactResourceAddressKeys = map[string]map[string]bool{
	"google_project.state": stringSet("root_state", "recovery"),
	"google_project_service.identity": stringSet(
		"cloudresourcemanager.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com",
		"serviceusage.googleapis.com", "sts.googleapis.com",
	),
	"google_project_iam_member.recovery_administration": stringSet(
		"roles/cloudkms.admin", "roles/iam.roleAdmin", "roles/iam.serviceAccountAdmin", "roles/logging.admin",
		"roles/resourcemanager.projectIamAdmin", "roles/serviceusage.serviceUsageAdmin", "roles/storage.admin", "roles/storagetransfer.user",
	),
	"module.github_federation.google_iam_workload_identity_pool.github":                          stringSet("plan", "apply", "recovery"),
	"module.github_federation.google_iam_workload_identity_pool_provider.github":                 stringSet("plan", "apply", "recovery"),
	"module.github_federation.google_service_account.github":                                     stringSet("plan", "apply", "recovery"),
	"module.github_federation.google_service_account_iam_member.github":                          stringSet("plan", "apply", "recovery"),
	"module.github_federation.google_iam_workload_identity_pool.github_config":                   stringSet("pool"),
	"module.github_federation.google_iam_workload_identity_pool_provider.github_config":          stringSet("plan", "apply"),
	"module.github_federation.google_service_account.github_config":                              stringSet("plan", "apply"),
	"module.github_federation.google_service_account_iam_member.github_config":                   stringSet("plan", "apply"),
	"module.github_federation.google_iam_workload_identity_pool.infrastructure_live":             stringSet("pool"),
	"module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_live":    stringSet("development-plan", "development-apply", "staging-plan", "staging-apply", "production-plan", "production-apply", "restricted-plan", "restricted-apply"),
	"module.github_federation.google_service_account.infrastructure_live":                        stringSet("development-plan", "development-apply", "staging-plan", "staging-apply", "production-plan", "production-apply", "restricted-plan", "restricted-apply"),
	"module.github_federation.google_service_account_iam_member.infrastructure_live":             stringSet("development-plan", "development-apply", "staging-plan", "staging-apply", "production-plan", "production-apply", "restricted-plan", "restricted-apply"),
	"module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_drift":   stringSet("drift"),
	"module.github_federation.google_service_account.infrastructure_drift":                       stringSet("drift"),
	"module.github_federation.google_service_account_iam_member.infrastructure_drift":            stringSet("drift"),
	"module.github_federation.google_iam_workload_identity_pool.ci_evidence":                     stringSet("archive"),
	"module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence":            stringSet("writer", "verifier"),
	"module.github_federation.google_service_account.ci_evidence":                                stringSet("writer", "verifier"),
	"module.github_federation.google_service_account_iam_member.ci_evidence":                     stringSet("writer", "verifier"),
	"module.audit_root.google_project_service.required":                                          stringSet("cloudkms.googleapis.com", "cloudresourcemanager.googleapis.com", "iam.googleapis.com", "logging.googleapis.com", "serviceusage.googleapis.com"),
	"module.audit_root.google_kms_key_ring.audit":                                                stringSet("primary", "recovery"),
	"module.audit_root.google_kms_crypto_key.audit":                                              stringSet("primary", "recovery"),
	"module.audit_root.data.google_logging_project_cmek_settings.audit":                          stringSet("primary", "recovery"),
	"module.audit_root.google_kms_crypto_key_iam_member.logging":                                 stringSet("primary", "recovery"),
	"module.audit_root.google_logging_project_bucket_config.audit":                               stringSet("primary", "recovery"),
	"module.audit_root.google_logging_organization_sink.audit":                                   stringSet("admin-activity", "admin-activity-recovery", "data-access", "data-access-recovery", "security-events", "security-events-recovery"),
	"module.audit_root.google_project_iam_member.sink_writer":                                    stringSet("primary", "recovery"),
	"module.audit_root.google_project_iam_custom_role.plan_read":                                 stringSet("primary", "recovery"),
	"module.audit_root.google_project_iam_member.plan_read":                                      stringSet("primary", "recovery"),
	"module.signing_root.google_project_service.required":                                        stringSet("cloudkms.googleapis.com", "cloudresourcemanager.googleapis.com", "iam.googleapis.com", "secretmanager.googleapis.com", "serviceusage.googleapis.com"),
	"module.signing_root.google_kms_crypto_key.signing":                                          stringSet("audit-anchor", "bootstrap-handoff", "connected-observation-evidence", "github-config-plan-evidence", "infrastructure-export", "recovery-evidence", "supply-chain-provenance"),
	"module.signing_root.data.google_kms_crypto_key_version.active":                              stringSet("audit-anchor", "bootstrap-handoff", "connected-observation-evidence", "github-config-plan-evidence", "infrastructure-export", "recovery-evidence", "supply-chain-provenance"),
	"module.signing_root.google_secret_manager_secret_version.nix_cache_signing":                 stringSet("active"),
	"module.recovery_exports.google_kms_crypto_key.recovery":                                     stringSet("exports", "evidence"),
	"module.recovery_exports.google_kms_crypto_key_iam_member.storage":                           stringSet("exports", "evidence"),
	"module.recovery_exports.google_storage_bucket.recovery":                                     stringSet("exports", "evidence"),
	"module.recovery_exports.google_storage_bucket_iam_member.access":                            stringSet("exports-exporter", "exports-recovery", "exports-recovery-metadata", "evidence-exporter", "evidence-recovery", "evidence-recovery-metadata"),
	"module.recovery_exports.google_storage_bucket_iam_member.plan_read":                         stringSet("exports", "evidence"),
	"module.recovery_exports.google_storage_bucket_iam_member.plan_object_read":                  stringSet("exports", "evidence"),
	"module.recovery_exports.data.google_storage_project_service_account.state_export_source":    stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.data.google_storage_transfer_project_service_account.state_export":  stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_service_account.state_export":                                stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_project_iam_custom_role.state_export_source_metadata":        stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_project_iam_custom_role.state_export_source_object":          stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_project_iam_custom_role.state_export_transfer_events":        stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_project_iam_custom_role.state_export_storage_events":         stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_service_account_iam_member.state_export_apply":               stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_service_account_iam_member.state_export_transfer":            stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_project_iam_member.state_export_transfer_events":             stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_project_iam_member.state_export_storage_events":              stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_storage_bucket_iam_member.state_export_source_metadata":      stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_storage_bucket_iam_member.state_export_source_object":        stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_storage_bucket_iam_member.state_export_destination_metadata": stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_storage_bucket_iam_member.state_export_destination_object":   stringSet("root-trust", "recovery-plane"),
	"module.recovery_exports.google_storage_transfer_job.state_export":                           stringSet("root-trust", "recovery-plane"),
	"module.break_glass.google_privileged_access_manager_entitlement.break_glass": stringSet(
		"identity-root-administration", "recovery-root-administration", "root-trust-administration", "signing-root-administration",
	),
}

var dynamicResourceAddressKeys = map[string]string{
	"module.audit_root.google_project_iam_member.reader":                             "audit-bucket-principal",
	"module.audit_root.google_project_iam_member.administrator":                      "role-principal",
	"module.signing_root.google_kms_key_ring_iam_member.administrator":               "principal",
	"module.signing_root.google_kms_crypto_key_iam_member.signer":                    "signing-key-principal",
	"module.signing_root.google_secret_manager_secret_iam_member.nix_cache_accessor": "principal",
	"module.break_glass.google_project_service.pam":                                  "project",
}

func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func addStateBackendAddressFamilies() {
	for _, module := range []string{"module.root_state", "module.recovery_state"} {
		for resourceType, names := range map[string][]string{
			"google_kms_key_ring":              {"state", "replica"},
			"google_kms_crypto_key":            {"state", "replica"},
			"google_project_iam_custom_role":   {"replication", "plan_lock"},
			"google_kms_crypto_key_iam_member": {"state_service_agent", "replica_service_agent"},
			"google_storage_bucket":            {"state"},
			"google_storage_bucket_iam_member": {"backend_access", "replication"},
			"google_project_iam_member":        {"replication_events"},
			"google_storage_transfer_job":      {"replication"},
		} {
			for _, name := range names {
				approvedResourceAddressFamilies["managed|"+resourceType+"|"+module+"."+resourceType+"."+name] = true
			}
		}
		exactResourceAddressKeys[module+".google_project_iam_custom_role.replication"] = stringSet("source_bucket", "destination_bucket", "transfer_events", "storage_events")
		exactResourceAddressKeys[module+".google_storage_bucket.state"] = stringSet("primary", "replica")
		exactResourceAddressKeys[module+".google_storage_bucket_iam_member.backend_access"] = stringSet(
			"primary-plan-state", "primary-plan-metadata", "primary-plan-lock", "primary-apply", "primary-recovery", "primary-recovery-metadata",
			"replica-plan-state", "replica-plan-metadata", "replica-recovery", "replica-recovery-metadata",
		)
		exactResourceAddressKeys[module+".google_storage_bucket_iam_member.replication"] = stringSet("source", "destination")
		exactResourceAddressKeys[module+".google_project_iam_member.replication_events"] = stringSet("transfer", "storage")
		for resourceType, names := range map[string][]string{
			"google_storage_project_service_account":          {"primary", "replica"},
			"google_storage_transfer_project_service_account": {"replication"},
		} {
			for _, name := range names {
				approvedResourceAddressFamilies["data|"+resourceType+"|"+module+".data."+resourceType+"."+name] = true
			}
		}
	}
}

func addRootTrustAddressKeys() {
	stateServices := []string{
		"cloudkms.googleapis.com", "cloudresourcemanager.googleapis.com", "iam.googleapis.com", "logging.googleapis.com",
		"pubsub.googleapis.com", "serviceusage.googleapis.com", "storage.googleapis.com", "storagetransfer.googleapis.com",
	}
	stateProjectServiceKeys := []string{}
	for _, project := range []string{"root_state", "recovery"} {
		for _, service := range stateServices {
			stateProjectServiceKeys = append(stateProjectServiceKeys, project+":"+service)
		}
	}
	for project, services := range map[string][]string{
		"root_state": {"iamcredentials.googleapis.com"},
		"recovery":   {"iamcredentials.googleapis.com", "sts.googleapis.com"},
	} {
		for _, service := range services {
			stateProjectServiceKeys = append(stateProjectServiceKeys, project+":"+service)
		}
	}
	exactResourceAddressKeys["google_project_service.state"] = stringSet(stateProjectServiceKeys...)

	administrationRoles := map[string][]string{
		"identity": {"roles/iam.workloadIdentityPoolAdmin", "roles/privilegedaccessmanager.admin", "roles/resourcemanager.projectIamAdmin", "roles/serviceusage.serviceUsageAdmin"},
		"audit":    {"roles/cloudkms.admin", "roles/resourcemanager.projectIamAdmin", "roles/serviceusage.serviceUsageAdmin"},
	}
	var administrationKeys []string
	for project, roles := range administrationRoles {
		for _, role := range roles {
			administrationKeys = append(administrationKeys, project+":"+role)
		}
	}
	exactResourceAddressKeys["google_project_iam_member.apply_administration"] = stringSet(administrationKeys...)

	readRoles := map[string][]string{
		"identity": {"roles/browser", "roles/iam.securityReviewer", "roles/iam.serviceAccountViewer", "roles/iam.workloadIdentityPoolViewer", "roles/privilegedaccessmanager.viewer", "roles/serviceusage.serviceUsageViewer"},
		"state":    {"roles/browser", "roles/cloudkms.viewer", "roles/iam.roleViewer", "roles/iam.securityReviewer", "roles/iam.serviceAccountViewer", "roles/privilegedaccessmanager.viewer", "roles/serviceusage.serviceUsageViewer", "roles/storagetransfer.viewer"},
		"recovery": {"roles/browser", "roles/cloudkms.viewer", "roles/iam.roleViewer", "roles/iam.securityReviewer", "roles/iam.serviceAccountViewer", "roles/iam.workloadIdentityPoolViewer", "roles/privilegedaccessmanager.viewer", "roles/serviceusage.serviceUsageViewer", "roles/storagetransfer.viewer"},
		"audit":    {"roles/browser", "roles/cloudkms.viewer", "roles/iam.securityReviewer", "roles/serviceusage.serviceUsageViewer"},
		"signing":  {"roles/browser", "roles/cloudkms.publicKeyViewer", "roles/cloudkms.viewer", "roles/iam.roleViewer", "roles/iam.securityReviewer", "roles/privilegedaccessmanager.viewer", "roles/serviceusage.serviceUsageViewer"},
	}
	var readKeys []string
	for project, roles := range readRoles {
		for _, role := range roles {
			readKeys = append(readKeys, project+":"+role)
		}
	}
	exactResourceAddressKeys["google_project_iam_member.plan_read"] = stringSet(readKeys...)
}

func init() {
	addStateBackendAddressFamilies()
	addRootTrustAddressKeys()
}

var allowedActionSequences = map[string]bool{
	"create":        true,
	"create,delete": true,
	"delete":        true,
	"delete,create": true,
	"no-op":         true,
	"read":          true,
	"update":        true,
}

var primitiveRoles = map[string]bool{
	"roles/editor": true,
	"roles/owner":  true,
	"roles/viewer": true,
}

var approvedRoles = map[string]bool{
	"roles/browser":                              true,
	"roles/cloudkms.admin":                       true,
	"roles/cloudkms.cryptoKeyEncrypterDecrypter": true,
	"roles/cloudkms.publicKeyViewer":             true,
	"roles/cloudkms.signerVerifier":              true,
	"roles/cloudkms.viewer":                      true,
	"roles/iam.securityAdmin":                    true,
	"roles/iam.organizationRoleAdmin":            true,
	"roles/iam.securityReviewer":                 true,
	"roles/iam.roleAdmin":                        true,
	"roles/iam.roleViewer":                       true,
	"roles/iam.serviceAccountAdmin":              true,
	"roles/iam.serviceAccountTokenCreator":       true,
	"roles/iam.serviceAccountUser":               true,
	"roles/iam.serviceAccountViewer":             true,
	"roles/iam.workforcePoolAdmin":               true,
	"roles/iam.workforcePoolViewer":              true,
	"roles/iam.workloadIdentityPoolAdmin":        true,
	"roles/iam.workloadIdentityPoolViewer":       true,
	"roles/iam.workloadIdentityUser":             true,
	"roles/logging.admin":                        true,
	"roles/logging.bucketWriter":                 true,
	"roles/logging.configWriter":                 true,
	"roles/logging.viewAccessor":                 true,
	"roles/privilegedaccessmanager.admin":        true,
	"roles/privilegedaccessmanager.viewer":       true,
	"roles/resourcemanager.projectIamAdmin":      true,
	"roles/secretmanager.secretAccessor":         true,
	"roles/serviceusage.serviceUsageAdmin":       true,
	"roles/serviceusage.serviceUsageViewer":      true,
	"roles/storage.admin":                        true,
	"roles/storage.legacyBucketReader":           true,
	"roles/storage.objectAdmin":                  true,
	"roles/storage.objectCreator":                true,
	"roles/storage.objectViewer":                 true,
	"roles/storagetransfer.user":                 true,
	"roles/storagetransfer.viewer":               true,
}

type replicationRoleContract struct {
	roleID      string
	permissions []string
}

var replicationRoleContracts = map[string]replicationRoleContract{
	"source_bucket": {
		roleID: "bootstrapStateReplicationSource",
		permissions: []string{
			"storage.buckets.get",
			"storage.buckets.update",
			"storage.objects.get",
		},
	},
	"destination_bucket": {
		roleID: "bootstrapStateReplicationDestination",
		permissions: []string{
			"storage.buckets.get",
			"storage.objects.create",
			"storage.objects.get",
		},
	},
	"transfer_events": {
		roleID: "bootstrapStateReplicationTransferEvents",
		permissions: []string{
			"pubsub.subscriptions.consume",
			"pubsub.subscriptions.create",
			"pubsub.topics.create",
		},
	},
	"storage_events": {
		roleID: "bootstrapStateReplicationStorageEvents",
		permissions: []string{
			"pubsub.subscriptions.consume",
			"pubsub.subscriptions.create",
			"pubsub.topics.publish",
		},
	},
}

var recoveryPlanReadRoleContract = replicationRoleContract{
	roleID: "bootstrapRecoveryPlanRead",
	permissions: []string{
		"storage.buckets.get",
		"storage.buckets.getIamPolicy",
	},
}

var recoveryPlanObjectReadRoleContract = replicationRoleContract{
	roleID:      "bootstrapRecoveryPlanObjectRead",
	permissions: []string{"storage.objects.get"},
}

var recoverySigningMetadataRoleContract = replicationRoleContract{
	roleID: "bootstrapRecoverySigningMetadata",
	permissions: []string{
		"cloudkms.cryptoKeys.get",
		"cloudkms.cryptoKeyVersions.get",
	},
}

var auditPlanReadRoleContract = replicationRoleContract{
	roleID: "bootstrapAuditPlanRead",
	permissions: []string{
		"iam.roles.get",
		"logging.buckets.get",
		"logging.cmekSettings.get",
		"logging.views.getIamPolicy",
	},
}

var organizationPlanReadRoleContract = replicationRoleContract{
	roleID: "bootstrapOrganizationPlanRead",
	permissions: []string{
		"iam.roles.get",
		"logging.sinks.get",
		"resourcemanager.organizations.get",
		"resourcemanager.organizations.getIamPolicy",
	},
}

var recoverySinkReadRoleContract = replicationRoleContract{
	roleID: "bootstrapRecoverySinkRead",
	permissions: []string{
		"logging.sinks.get",
		"resourcemanager.organizations.getIamPolicy",
	},
}

var organizationIAMApplyRoleContract = replicationRoleContract{
	roleID: "bootstrapOrganizationIamApply",
	permissions: []string{
		"resourcemanager.organizations.getIamPolicy",
		"resourcemanager.organizations.setIamPolicy",
	},
}

var statePlanLockRoleContract = replicationRoleContract{
	roleID: "bootstrapStatePlanLock",
	permissions: []string{
		"storage.objects.create",
		"storage.objects.delete",
		"storage.objects.get",
		"storage.objects.update",
	},
}

var recoveryStateExportRoleContracts = map[string]replicationRoleContract{
	"source_metadata": {
		roleID: "bootstrapRecoveryExportSourceMetadata",
		permissions: []string{
			"storage.buckets.get",
			"storage.buckets.update",
		},
	},
	"source_object": {
		roleID:      "bootstrapRecoveryExportSourceObject",
		permissions: []string{"storage.objects.get"},
	},
	"transfer_events": {
		roleID: "bootstrapRecoveryExportTransferEvents",
		permissions: []string{
			"pubsub.subscriptions.consume",
			"pubsub.subscriptions.create",
			"pubsub.topics.create",
		},
	},
	"storage_events": {
		roleID: "bootstrapRecoveryExportStorageEvents",
		permissions: []string{
			"pubsub.subscriptions.consume",
			"pubsub.subscriptions.create",
			"pubsub.topics.publish",
		},
	},
	"destination_metadata": {
		roleID:      "bootstrapRecoveryExportDestinationMetadata",
		permissions: []string{"storage.buckets.get"},
	},
	"destination_object": {
		roleID: "bootstrapRecoveryExportDestinationObject",
		permissions: []string{
			"storage.objects.create",
			"storage.objects.get",
		},
	},
}

var recoveryStateExportKeys = []string{"root-trust", "recovery-plane"}

var signingKeyNames = []string{"audit-anchor", "bootstrap-handoff", "connected-observation-evidence", "github-config-plan-evidence", "infrastructure-export", "recovery-evidence", "supply-chain-provenance"}

var recoverySigningWindowNames = []string{"audit-anchor", "bootstrap-handoff", "recovery-evidence"}

var replicationPrefixes = map[string]string{
	"module.root_state":     "root-trust/default.tfstate",
	"module.recovery_state": "recovery-plane/default.tfstate",
}

var stateBackendAccessRoles = map[string]string{
	"primary-plan-state":        "roles/storage.objectViewer",
	"primary-plan-metadata":     "roles/storage.legacyBucketReader",
	"primary-plan-lock":         "custom/bootstrapStatePlanLock",
	"primary-apply":             "roles/storage.objectAdmin",
	"primary-recovery":          "roles/storage.objectViewer",
	"primary-recovery-metadata": "roles/storage.legacyBucketReader",
	"replica-plan-state":        "roles/storage.objectViewer",
	"replica-plan-metadata":     "roles/storage.legacyBucketReader",
	"replica-recovery":          "roles/storage.objectViewer",
	"replica-recovery-metadata": "roles/storage.legacyBucketReader",
}

var recoveryAdministrationRoles = map[string]bool{
	"roles/cloudkms.admin":                  true,
	"roles/iam.roleAdmin":                   true,
	"roles/iam.serviceAccountAdmin":         true,
	"roles/logging.admin":                   true,
	"roles/resourcemanager.projectIamAdmin": true,
	"roles/serviceusage.serviceUsageAdmin":  true,
	"roles/storage.admin":                   true,
	"roles/storagetransfer.user":            true,
}

var (
	billingAccountPattern             = regexp.MustCompile(`^[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{6}$`)
	googleProjectIDPattern            = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	googleShortIDPattern              = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	kmsResourceIDPattern              = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
	numericIDPattern                  = regexp.MustCompile(`^[0-9]+$`)
	bootstrapApplyPrincipalPattern    = regexp.MustCompile(`^serviceAccount:bootstrap-apply@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	bootstrapPlanPrincipalPattern     = regexp.MustCompile(`^serviceAccount:bootstrap-plan@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	bootstrapRecoveryPrincipalPattern = regexp.MustCompile(`^serviceAccount:bootstrap-recovery@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	canonicalEmailPattern             = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	emailPrincipalPattern             = regexp.MustCompile(`^(user|group):[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	groupEmailPrincipalPattern        = regexp.MustCompile(`^group:[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	serviceAccountIAMPattern          = regexp.MustCompile(`^serviceAccount:[a-z][a-z0-9-]{1,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	federatedIAMPrincipalPattern      = regexp.MustCompile(`^(principal://iam\.googleapis\.com/(projects/[0-9]+/locations/global/workloadIdentityPools/[a-z0-9-]+|locations/global/workforcePools/[a-z0-9-]+)/subject/[^/*\s]+|principalSet://iam\.googleapis\.com/(projects/[0-9]+/locations/global/workloadIdentityPools/[a-z0-9-]+|locations/global/workforcePools/[a-z0-9-]+)/(group|attribute\.[A-Za-z0-9_]+)/[^/*\s]+)$`)
	auditSinkWriterPrincipalPattern   = regexp.MustCompile(`^serviceAccount:service-org-[0-9]+@gcp-sa-logging\.iam\.gserviceaccount\.com$`)
	signingVersionPattern             = regexp.MustCompile(`^v[0-9]{8}$`)
	storageServiceAgentEmailPattern   = regexp.MustCompile(`^service-[0-9]+@gs-project-accounts\.iam\.gserviceaccount\.com$`)
	storageServiceAgentPattern        = regexp.MustCompile(`^serviceAccount:service-[0-9]+@gs-project-accounts\.iam\.gserviceaccount\.com$`)
	transferServiceAgentPattern       = regexp.MustCompile(`^serviceAccount:project-[0-9]+@storage-transfer-service\.iam\.gserviceaccount\.com$`)
)

// Summary is safe to publish; it contains no provider values.
type Summary struct {
	Creates    int      `json:"creates"`
	Updates    int      `json:"updates"`
	Deletes    int      `json:"deletes"`
	Replaces   int      `json:"replaces"`
	Reads      int      `json:"reads"`
	Violations []string `json:"violations,omitempty"`
}

type document struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []resourceChange `json:"resource_changes"`
	PlannedValues    plannedValues    `json:"planned_values"`
	OutputChanges    map[string]struct {
		Actions      []string `json:"actions"`
		Before       any      `json:"before"`
		After        any      `json:"after"`
		AfterUnknown any      `json:"after_unknown"`
	} `json:"output_changes"`
	Configuration map[string]any `json:"configuration"`
	Variables     map[string]struct {
		Value any `json:"value"`
	} `json:"variables"`
}

type plannedValues struct {
	RootModule *plannedModule `json:"root_module"`
}

type plannedModule struct {
	Address      string            `json:"address"`
	Resources    []plannedResource `json:"resources"`
	ChildModules []plannedModule   `json:"child_modules"`
}

type plannedResource struct {
	Address       string         `json:"address"`
	Mode          string         `json:"mode"`
	Type          string         `json:"type"`
	Name          string         `json:"name"`
	Index         any            `json:"index"`
	ProviderName  string         `json:"provider_name"`
	SchemaVersion float64        `json:"schema_version"`
	Values        map[string]any `json:"values"`
}

type resourceChange struct {
	Address string `json:"address"`
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Change  struct {
		Actions      []string `json:"actions"`
		Before       any      `json:"before"`
		After        any      `json:"after"`
		AfterUnknown any      `json:"after_unknown"`
	} `json:"change"`
	signingContract           *signingContract
	auditLock                 auditLockContract
	signingVersionCreateProof bool
	initialSigningCreateProof bool
	plannedValue              *plannedResource
}

type auditLockContract struct {
	declared bool
	locked   bool
}

type signingContract struct {
	explicit bool
	keys     map[string]signingKeyContract
	versions map[string]bool
}

type signingKeyContract struct {
	activeVersionRef string
	versions         map[string]signingWindowContract
}

type signingWindowContract struct {
	activationWindowStart string
	rotationDeadline      string
}

// AnalyzeFile reads and classifies a tofu show -json document.
func AnalyzeFile(path string) (Summary, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Summary{}, err
	}
	return Analyze(b)
}

// AnalyzeFileForRoot reads and classifies a tofu show -json document and also
// proves that it contains the complete declared composition. Authorization
// callers must use this root-aware entry point; AnalyzeFile intentionally
// remains available for resource-level diagnostics and evidence binding.
func AnalyzeFileForRoot(path, root string) (Summary, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Summary{}, err
	}
	return AnalyzeForRoot(b, root)
}

// AnalyzeForRoot applies the resource-level policy and then requires the full
// root-trust or recovery-plane instance inventory, including no-op instances.
func AnalyzeForRoot(data []byte, root string) (Summary, error) {
	if root != "root-trust" && root != "recovery-plane" {
		return Summary{}, fmt.Errorf("unsupported Ring-0 composition %q", root)
	}
	result, err := Analyze(data)
	if err != nil {
		return result, err
	}
	var parsed document
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Summary{}, fmt.Errorf("parse OpenTofu plan JSON: %w", err)
	}
	if !exactGoogleProviderConfiguration(parsed.Configuration) {
		result.Violations = append(result.Violations, "strict root plan must embed exactly the approved Google provider configuration")
	}
	contract, present, contractError := signingContractFromVariables(parsed.Variables)
	if root == "root-trust" {
		if !present || contractError != nil {
			result.Violations = append(result.Violations, "--root root-trust plan must contain the exact compiled bootstrap signing-version declaration")
		}
	}
	ciEvidenceEnabled := false
	nixCacheActivated := false
	nixCacheAccessorCount := 0
	if bootstrapVariable, ok := parsed.Variables["bootstrap"]; ok {
		if bootstrap, ok := bootstrapVariable.Value.(map[string]any); ok {
			if ciEvidence, ok := bootstrap["github_ci_evidence"].(map[string]any); ok {
				ciEvidenceEnabled, _ = ciEvidence["activation_enabled"].(bool)
			}
			if signing, ok := bootstrap["signing"].(map[string]any); ok {
				if nixCache, ok := signing["nix_cache"].(map[string]any); ok {
					nixCacheActivated, _ = nixCache["activation_enabled"].(bool)
					nixCacheAccessorCount = len(stringSetFromValue(nixCache["accessor_principals"]))
				}
			}
		}
	}
	validateCompositionCompleteness(parsed.ResourceChanges, root, contract, ciEvidenceEnabled, nixCacheActivated, nixCacheAccessorCount, &result.Violations)
	if root == "root-trust" && present && contractError == nil {
		validateSigningDeclarationOutput(parsed.OutputChanges, contract, &result.Violations)
		validateRootTrustVariableGraph(parsed, contract, &result.Violations)
	}
	if root == "recovery-plane" {
		validateRecoveryPlaneVariableGraph(parsed, &result.Violations)
	}
	sort.Strings(result.Violations)
	if len(result.Violations) != 0 {
		return result, fmt.Errorf("plan violates Ring-0 policy: %s", strings.Join(result.Violations, "; "))
	}
	return result, nil
}

func validateRecoveryPlaneVariableGraph(parsed document, violations *[]string) {
	variable, present := parsed.Variables["recovery"]
	recovery, recoveryOK := variable.Value.(map[string]any)
	if !present || !recoveryOK {
		*violations = append(*violations, "--root recovery-plane plan must contain the exact compiled recovery declaration")
		return
	}
	projectID, projectOK := recovery["project_id"].(string)
	location, locationOK := recovery["location"].(string)
	keyRingName, keyRingOK := recovery["key_ring_name"].(string)
	exportKeyName, exportKeyOK := recovery["export_key_name"].(string)
	exportBucket, exportBucketOK := recovery["export_bucket_name"].(string)
	evidenceBucket, evidenceBucketOK := recovery["evidence_bucket_name"].(string)
	backends, backendsOK := recovery["source_state_backends"].(map[string]any)
	rootBackend, rootBackendOK := backends["root-trust"].(map[string]any)
	recoveryBackend, recoveryBackendOK := backends["recovery-plane"].(map[string]any)
	rootProject := stringValue(rootBackend["project_id"])
	if !projectOK || !locationOK || !keyRingOK || !exportKeyOK || !exportBucketOK || !evidenceBucketOK ||
		!backendsOK || !rootBackendOK || !recoveryBackendOK || !googleProjectIDPattern.MatchString(projectID) ||
		location != "us-east4" || keyRingName != "bootstrap-recovery" || !kmsResourceIDPattern.MatchString(exportKeyName) || exportKeyName == "recovery-evidence" ||
		exportBucket != projectID+"-recovery-exports" || evidenceBucket != projectID+"-recovery-evidence" ||
		!exactObjectKeys(backends, recoveryStateExportKeys) || !googleProjectIDPattern.MatchString(rootProject) || rootProject == projectID ||
		recoveryBackend["project_id"] != projectID || rootBackend["prefix"] != "root-trust" || recoveryBackend["prefix"] != "recovery-plane" ||
		!validBucketName(stringValue(rootBackend["bucket"])) || !validBucketName(stringValue(recoveryBackend["bucket"])) ||
		rootBackend["bucket"] == recoveryBackend["bucket"] {
		*violations = append(*violations, "compiled recovery declaration must use the exact isolated project, region, buckets, keys, and two source backends")
		return
	}

	planPrincipal := serviceAccountPrincipal("bootstrap-plan", rootProject)
	exporterPrincipal := serviceAccountPrincipal("bootstrap-apply", rootProject)
	recoveryPrincipal := serviceAccountPrincipal("bootstrap-recovery", projectID)
	if recovery["plan_principal"] != planPrincipal || recovery["exporter_principal"] != exporterPrincipal || recovery["recovery_principal"] != recoveryPrincipal {
		*violations = append(*violations, "recovery plan, exporter, and verifier principals must exactly equal their compiled isolated service accounts")
	}

	keyRing := resourceAfter(parsed.ResourceChanges, "module.recovery_exports.google_kms_key_ring.recovery")
	expectedKeyRing := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, location, keyRingName)
	if keyRing == nil || keyRing["project"] != projectID || keyRing["location"] != location || keyRing["name"] != keyRingName {
		*violations = append(*violations, "recovery KMS key ring must exactly equal the compiled project, region, and name")
	}
	for key, expectedName := range map[string]string{"exports": exportKeyName, "evidence": "recovery-evidence"} {
		cryptoKey := resourceAfter(parsed.ResourceChanges, indexedResourceAddress("module.recovery_exports.google_kms_crypto_key.recovery", key))
		bucket := resourceAfter(parsed.ResourceChanges, indexedResourceAddress("module.recovery_exports.google_storage_bucket.recovery", key))
		expectedBucket := exportBucket
		if key == "evidence" {
			expectedBucket = evidenceBucket
		}
		if cryptoKey == nil || cryptoKey["name"] != expectedName || cryptoKey["key_ring"] != expectedKeyRing {
			*violations = append(*violations, "recovery "+key+" CMEK must exactly equal its compiled key name and key ring")
		}
		if bucket == nil || bucket["project"] != projectID || bucket["name"] != expectedBucket || bucket["location"] != strings.ToUpper(location) {
			*violations = append(*violations, "recovery "+key+" bucket must exactly equal its compiled project, name, and region")
		}
	}

	sourceProjectBases := stringSet(
		"module.recovery_exports.data.google_storage_project_service_account.state_export_source",
		"module.recovery_exports.data.google_storage_transfer_project_service_account.state_export",
		"module.recovery_exports.google_service_account.state_export",
		"module.recovery_exports.google_project_iam_custom_role.state_export_source_metadata",
		"module.recovery_exports.google_project_iam_custom_role.state_export_source_object",
		"module.recovery_exports.google_project_iam_custom_role.state_export_transfer_events",
		"module.recovery_exports.google_project_iam_custom_role.state_export_storage_events",
		"module.recovery_exports.google_project_iam_member.state_export_transfer_events",
		"module.recovery_exports.google_project_iam_member.state_export_storage_events",
		"module.recovery_exports.google_storage_transfer_job.state_export",
	)
	for _, resource := range parsed.ResourceChanges {
		after, _ := resource.Change.After.(map[string]any)
		base := resourceAddressBase(resource.Address)
		if project, ok := after["project"].(string); ok && strings.HasPrefix(resource.Address, "module.recovery_exports.") {
			expectedProject := projectID
			if sourceProjectBases[base] {
				instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
				backend, backendOK := backends[instance].(map[string]any)
				if !indexed || !backendOK {
					*violations = append(*violations, resource.Address+" must identify one compiled source backend")
					continue
				}
				expectedProject = stringValue(backend["project_id"])
			}
			if project != expectedProject {
				*violations = append(*violations, resource.Address+" must target its exact compiled recovery or source-backend project")
			}
		}
		member := stringValue(after["member"])
		switch {
		case bootstrapPlanPrincipalPattern.MatchString(member) && member != planPrincipal:
			*violations = append(*violations, resource.Address+" substitutes a same-shaped recovery plan identity")
		case bootstrapApplyPrincipalPattern.MatchString(member) && member != exporterPrincipal:
			*violations = append(*violations, resource.Address+" substitutes a same-shaped recovery exporter identity")
		case bootstrapRecoveryPrincipalPattern.MatchString(member) && member != recoveryPrincipal:
			*violations = append(*violations, resource.Address+" substitutes a same-shaped recovery verifier identity")
		}
	}

	publicMetadata, publicOK := recovery["public_trust_metadata"].(map[string]any)
	publicObject := fixedRecoveryJSON(parsed.ResourceChanges, "module.recovery_exports.google_storage_bucket_object.public_trust_metadata")
	if !publicOK || publicObject == nil || !sameJSONValue(publicObject, publicMetadata) {
		*violations = append(*violations, "published recovery public trust metadata must exactly equal the compiled declaration")
	}
	metadataBackends, metadataBackendsOK := publicMetadata["state_backends"].(map[string]any)
	allBuckets := []string{exportBucket, evidenceBucket}
	for _, key := range recoveryStateExportKeys {
		backend, backendOK := metadataBackends[key].(map[string]any)
		if !backendOK {
			metadataBackendsOK = false
			continue
		}
		allBuckets = append(allBuckets, stringValue(backend["bucket"]), stringValue(backend["replica_bucket"]))
	}
	if !metadataBackendsOK || !exactObjectKeys(metadataBackends, recoveryStateExportKeys) ||
		len(allBuckets) != 6 || len(stringSet(allBuckets...)) != 6 {
		*violations = append(*violations, "recovery export, evidence, primary-state, and replica-state buckets must all be distinct")
	}
	restoreDigest := stringValue(recovery["restore_manifest_digest"])
	minimumGenerations, generationsOK := recovery["minimum_retained_state_generations"].(float64)
	expectedSources := map[string]any{}
	expectedExports := map[string]any{}
	for _, key := range recoveryStateExportKeys {
		backend, _ := backends[key].(map[string]any)
		objectName := stringValue(backend["prefix"]) + "/default.tfstate"
		expectedSources[key] = map[string]any{"bucket": backend["bucket"], "object": objectName}
		expectedExports[key] = map[string]any{"bucket": exportBucket, "object": objectName}
	}
	expectedInventory := map[string]any{
		"schema_version":                     float64(1),
		"source_state_objects":               expectedSources,
		"export_state_objects":               expectedExports,
		"runtime_selection_required":         []any{"generation", "sha256"},
		"minimum_retained_state_generations": minimumGenerations,
		"restore_manifest_digest":            restoreDigest,
		"excludes":                           []any{"kms-private-key-material", "service-account-keys", "credentials"},
	}
	inventory := fixedRecoveryJSON(parsed.ResourceChanges, "module.recovery_exports.google_storage_bucket_object.restore_inventory")
	if !generationsOK || minimumGenerations != 3 || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(restoreDigest) ||
		inventory == nil || !sameJSONValue(inventory, expectedInventory) {
		*violations = append(*violations, "recovery restore inventory must exactly equal the compiled backends, generation floor, and manifest digest")
	}
}

func validateSigningDeclarationOutput(outputs map[string]struct {
	Actions      []string `json:"actions"`
	Before       any      `json:"before"`
	After        any      `json:"after"`
	AfterUnknown any      `json:"after_unknown"`
}, contract *signingContract, violations *[]string,
) {
	output, present := outputs["signing_version_declarations"]
	if !present || contract == nil {
		*violations = append(*violations, "root-trust plan must contain the append-only signing_version_declarations output")
		return
	}
	expected := map[string]any{}
	for _, keyName := range signingKeyNames {
		versions := map[string]any{}
		for versionRef, window := range contract.keys[keyName].versions {
			versions[versionRef] = map[string]any{
				"activation_window_start": window.activationWindowStart,
				"rotation_deadline":       window.rotationDeadline,
			}
		}
		expected[keyName] = versions
	}
	if !sameJSONValue(output.After, expected) || containsUnknown(output.AfterUnknown) {
		*violations = append(*violations, "signing_version_declarations after value must exactly equal every compiled key/version/window")
		return
	}
	actions := strings.Join(output.Actions, ",")
	if actions == "create" {
		if !plannedUnset(output.Before) {
			*violations = append(*violations, "initial signing_version_declarations output must have no prior value")
		}
		return
	}
	if actions != "no-op" && actions != "update" {
		*violations = append(*violations, "signing_version_declarations output may only be created, updated append-only, or remain no-op")
		return
	}
	before, beforeOK := output.Before.(map[string]any)
	after, _ := output.After.(map[string]any)
	if !beforeOK || !signingDeclarationsAppendOnly(before, after) {
		*violations = append(*violations, "signing_version_declarations must preserve every prior key, version, and exact window while appending only new versions")
	}
}

func signingDeclarationsAppendOnly(before, after map[string]any) bool {
	if len(before) != len(signingKeyNames) || len(after) != len(signingKeyNames) {
		return false
	}
	for _, keyName := range signingKeyNames {
		priorVersions, priorOK := before[keyName].(map[string]any)
		currentVersions, currentOK := after[keyName].(map[string]any)
		if !priorOK || !currentOK || len(priorVersions) > len(currentVersions) {
			return false
		}
		for versionRef, priorWindow := range priorVersions {
			if !sameJSONValue(priorWindow, currentVersions[versionRef]) {
				return false
			}
		}
	}
	return true
}

func sameJSONValue(left, right any) bool {
	leftJSON, leftError := json.Marshal(left)
	rightJSON, rightError := json.Marshal(right)
	return leftError == nil && rightError == nil && string(leftJSON) == string(rightJSON)
}

func indexPlannedResources(values plannedValues) (map[string]plannedResource, []string) {
	index := map[string]plannedResource{}
	var violations []string
	if values.RootModule == nil {
		return index, violations
	}
	var visit func(plannedModule)
	visit = func(module plannedModule) {
		for _, resource := range module.Resources {
			if resource.Address == "" {
				violations = append(violations, "planned_values contains a resource without an address")
				continue
			}
			if _, exists := index[resource.Address]; exists {
				violations = append(violations, resource.Address+" appears more than once in planned_values")
				continue
			}
			index[resource.Address] = resource
		}
		for _, child := range module.ChildModules {
			visit(child)
		}
	}
	visit(*values.RootModule)
	return index, violations
}

// Analyze classifies a tofu show -json document and detects Ring-0 violations.
func Analyze(data []byte) (Summary, error) {
	var parsed document
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Summary{}, fmt.Errorf("parse OpenTofu plan JSON: %w", err)
	}
	if parsed.ResourceChanges == nil {
		return Summary{}, errors.New("parse OpenTofu plan JSON: resource_changes must be an array")
	}
	if parsed.FormatVersion != "1.2" || parsed.TerraformVersion != "1.12.6" {
		return Summary{}, errors.New("parse OpenTofu plan JSON: unsupported or incomplete plan format metadata")
	}
	contract, present, contractError := signingContractFromVariables(parsed.Variables)
	var result Summary
	if contractError != nil {
		result.Violations = append(result.Violations, "compiled bootstrap signing declarations are malformed: "+contractError.Error())
	}
	if !present {
		contract = defaultSigningContract()
	}
	plannedResources, plannedViolations := indexPlannedResources(parsed.PlannedValues)
	result.Violations = append(result.Violations, plannedViolations...)
	validateConfigurationSafety(parsed.Configuration, &result.Violations)
	auditLock, auditLockError := auditLockContractFromVariables(parsed.Variables, contract)
	if auditLockError != nil {
		result.Violations = append(result.Violations, "compiled audit lock declaration is malformed: "+auditLockError.Error())
	}
	versionInventoryProof := contractError == nil && present && exactSigningVersionInventory(parsed.ResourceChanges, contract)
	initialSigningProof := versionInventoryProof && exactInitialSigningCreateProof(parsed, contract)
	activeCreateKeys := activeSigningVersionCreates(parsed.ResourceChanges, contract)
	for index := range parsed.ResourceChanges {
		resource := parsed.ResourceChanges[index]
		resource.signingContract = contract
		resource.auditLock = auditLock
		resource.signingVersionCreateProof = versionInventoryProof && strings.Join(resource.Change.Actions, ",") == "create" &&
			resourceAddressBase(resource.Address) == "module.signing_root.google_kms_crypto_key_version.signing"
		resource.initialSigningCreateProof = initialSigningProof && strings.Join(resource.Change.Actions, ",") == "create" &&
			initialSigningIAMAddressUsesCreatedActiveVersion(resource.Address, activeCreateKeys)
		if planned, ok := plannedResources[resource.Address]; ok {
			plannedCopy := planned
			resource.plannedValue = &plannedCopy
		}
		parsed.ResourceChanges[index] = resource
		if resource.Address == "" || resource.Type == "" {
			result.Violations = append(result.Violations, "plan contains a resource change without a complete address/type")
		}
		if resource.Mode != "managed" && resource.Mode != "data" {
			result.Violations = append(result.Violations, fmt.Sprintf("%s has unsupported resource mode %q", resource.Address, resource.Mode))
		}
		if !allowedActionSequences[strings.Join(resource.Change.Actions, ",")] {
			result.Violations = append(result.Violations, fmt.Sprintf("%s has unsupported action sequence %v", resource.Address, resource.Change.Actions))
		}
		actions := map[string]bool{}
		for _, action := range resource.Change.Actions {
			actions[action] = true
		}
		switch {
		case actions["delete"] && actions["create"]:
			result.Replaces++
		case actions["delete"]:
			result.Deletes++
		case actions["create"]:
			result.Creates++
		case actions["update"]:
			result.Updates++
		case actions["read"]:
			result.Reads++
		}
		if prohibitedResourceType(resource.Type) {
			result.Violations = append(result.Violations, fmt.Sprintf("%s uses prohibited Ring-0 resource type %s", resource.Address, resource.Type))
		} else if !approvedResourceTypes[resource.Type] {
			result.Violations = append(result.Violations, fmt.Sprintf("%s uses resource type %s outside the Ring-0 allowlist", resource.Address, resource.Type))
		} else if !approvedResourceAddress(resource) {
			result.Violations = append(result.Violations, fmt.Sprintf("%s is outside the exact Ring-0 resource-address allowlist for %s", resource.Address, resource.Type))
		}
		inspect(resource.Change.After, resource.Address, &result.Violations)
		inspectUnknown(resource.Change.AfterUnknown, resource.Address, resource, &result.Violations)
		inspectResourceInvariants(resource, &result.Violations)
	}
	validateRecoveryAdministration(parsed.ResourceChanges, &result.Violations)
	validatePlannedProjectGraph(parsed.ResourceChanges, &result.Violations)
	validateOrganizationCustomRoleGraph(parsed.ResourceChanges, &result.Violations)
	validateAuditSinkWriterGraph(parsed.ResourceChanges, &result.Violations)
	validateSigningAdministratorKeyRingGraph(parsed.ResourceChanges, &result.Violations)
	validateKMSParentAndBucketGraph(parsed.ResourceChanges, &result.Violations)
	validateSigningVersionGraph(parsed.ResourceChanges, contract, &result.Violations)
	validateFederationClaimGraph(parsed.ResourceChanges, &result.Violations)
	validateRecoveryMetadataGraph(parsed.ResourceChanges, &result.Violations)
	if result.Deletes > 0 || result.Replaces > 0 {
		result.Violations = append(result.Violations, "v1 protected plans must not delete or replace resources")
	}
	sort.Strings(result.Violations)
	if len(result.Violations) != 0 {
		return result, fmt.Errorf("plan violates Ring-0 policy: %s", strings.Join(result.Violations, "; "))
	}
	return result, nil
}

func validateOrganizationCustomRoleGraph(resources []resourceChange, violations *[]string) {
	contracts := []struct {
		roleAddress    string
		bindingAddress string
		roleID         string
	}{
		{"google_organization_iam_custom_role.plan_read", "google_organization_iam_member.plan_read", organizationPlanReadRoleContract.roleID},
		{"google_organization_iam_custom_role.recovery_sink_read", "google_organization_iam_member.recovery_sink_read", recoverySinkReadRoleContract.roleID},
		{"google_organization_iam_custom_role.apply_iam", "google_organization_iam_member.apply_iam", organizationIAMApplyRoleContract.roleID},
	}
	sharedOrganization := ""
	for _, contract := range contracts {
		roleResource := resourceByAddress(resources, contract.roleAddress)
		bindingResource := resourceByAddress(resources, contract.bindingAddress)
		if roleResource == nil || bindingResource == nil {
			continue
		}
		roleAfter, _ := roleResource.Change.After.(map[string]any)
		bindingAfter, _ := bindingResource.Change.After.(map[string]any)
		roleOrganization, _ := roleAfter["org_id"].(string)
		bindingOrganization, _ := bindingAfter["org_id"].(string)
		expectedRole := fmt.Sprintf("organizations/%s/roles/%s", roleOrganization, contract.roleID)
		if !numericIDPattern.MatchString(roleOrganization) || roleOrganization != bindingOrganization || bindingAfter["role"] != expectedRole {
			*violations = append(*violations, contract.bindingAddress+" must bind its matching custom role in the same exact organization")
		}
		if sharedOrganization == "" {
			sharedOrganization = roleOrganization
		} else if roleOrganization != sharedOrganization {
			*violations = append(*violations, "organization configuration-read custom roles must share one exact organization")
		}
	}
}

func validateConfigurationSafety(configuration map[string]any, violations *[]string) {
	if len(configuration) == 0 {
		return
	}
	providers, hasProviders := configuration["provider_config"].(map[string]any)
	if hasProviders {
		provider, providerOK := providers["google"].(map[string]any)
		fullName, _ := provider["full_name"].(string)
		if !providerOK || len(providers) != 1 || provider["name"] != "google" ||
			(!strings.HasSuffix(fullName, "/hashicorp/google") && fullName != "hashicorp/google") || !plannedUnset(provider["alias"]) {
			*violations = append(*violations, "plan configuration must use exactly the unaliased HashiCorp Google provider")
		}
		if expressions, present := provider["expressions"].(map[string]any); present {
			for key := range expressions {
				if key != "project" && key != "region" {
					*violations = append(*violations, "Google provider configuration may set only the compiled project and region")
				}
			}
		}
	}
	validateConfigurationNode(configuration["root_module"], violations)
}

func exactGoogleProviderConfiguration(configuration map[string]any) bool {
	providers, ok := configuration["provider_config"].(map[string]any)
	provider, providerOK := providers["google"].(map[string]any)
	fullName, _ := provider["full_name"].(string)
	if !ok || !providerOK || len(providers) != 1 || provider["name"] != "google" ||
		(!strings.HasSuffix(fullName, "/hashicorp/google") && fullName != "hashicorp/google") || !plannedUnset(provider["alias"]) {
		return false
	}
	if expressions, present := provider["expressions"].(map[string]any); present {
		for key := range expressions {
			if key != "project" && key != "region" {
				return false
			}
		}
	}
	return true
}

func validateConfigurationNode(value any, violations *[]string) {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if key == "provisioners" {
				if values, ok := child.([]any); !ok || len(values) != 0 {
					*violations = append(*violations, "plan configuration must not contain provisioners")
				}
				continue
			}
			if key == "provider_config_key" {
				if providerKey, _ := child.(string); providerKey != "" && providerKey != "google" {
					*violations = append(*violations, "every configured resource must use the approved Google provider configuration")
				}
				continue
			}
			validateConfigurationNode(child, violations)
		}
	case []any:
		for _, child := range current {
			validateConfigurationNode(child, violations)
		}
	}
}

func validateAuditSinkWriterGraph(resources []resourceChange, violations *[]string) {
	const sinkBase = "module.audit_root.google_logging_organization_sink.audit"
	const writerBase = "module.audit_root.google_project_iam_member.sink_writer"
	pairedSinks := map[string][]string{
		"primary":  {"admin-activity", "data-access", "security-events"},
		"recovery": {"admin-activity-recovery", "data-access-recovery", "security-events-recovery"},
	}
	sharedExpectedIdentity := ""
	for bucketKey, sinkKeys := range pairedSinks {
		writerResource := resourceByAddress(resources, indexedResourceAddress(writerBase, bucketKey))
		if writerResource == nil {
			continue
		}
		writerAfter, _ := writerResource.Change.After.(map[string]any)
		member, memberKnown := writerAfter["member"].(string)
		expectedIdentity := ""
		validOrganizationParent := true
		allKnownAndEqual := memberKnown && member != ""
		allInitialCreateUnknown := strings.Join(writerResource.Change.Actions, ",") == "create" &&
			(!memberKnown || member == "") && topLevelUnknown(writerResource.Change.AfterUnknown, "member")
		for _, sinkKey := range sinkKeys {
			sinkResource := resourceByAddress(resources, indexedResourceAddress(sinkBase, sinkKey))
			if sinkResource == nil {
				allKnownAndEqual = false
				allInitialCreateUnknown = false
				continue
			}
			sinkAfter, _ := sinkResource.Change.After.(map[string]any)
			orgID, orgKnown := sinkAfter["org_id"].(string)
			candidateIdentity := fmt.Sprintf("serviceAccount:service-org-%s@gcp-sa-logging.iam.gserviceaccount.com", orgID)
			if !orgKnown || !numericIDPattern.MatchString(orgID) {
				validOrganizationParent = false
			} else if expectedIdentity == "" {
				expectedIdentity = candidateIdentity
			} else if candidateIdentity != expectedIdentity {
				validOrganizationParent = false
			}
			writerIdentity, writerKnown := sinkAfter["writer_identity"].(string)
			allKnownAndEqual = allKnownAndEqual && writerKnown && writerIdentity != "" && writerIdentity == member && writerIdentity == candidateIdentity
			allInitialCreateUnknown = allInitialCreateUnknown && strings.Join(sinkResource.Change.Actions, ",") == "create" &&
				(!writerKnown || writerIdentity == "") && topLevelUnknown(sinkResource.Change.AfterUnknown, "writer_identity")
		}
		if !validOrganizationParent || expectedIdentity == "" ||
			(sharedExpectedIdentity != "" && expectedIdentity != sharedExpectedIdentity) {
			*violations = append(*violations, indexedResourceAddress(writerBase, bucketKey)+" must use the one shared Logging service agent for the exact organization across all six sinks")
			continue
		}
		sharedExpectedIdentity = expectedIdentity
		allKnownAndEqual = allKnownAndEqual && member == expectedIdentity
		if allKnownAndEqual {
			continue
		}
		// On the first create, the provider assigns writer_identity. The exact
		// six sink keys and two bucket-scoped grants bind the generated IAM
		// member; this exception is not accepted on updates or no-ops.
		if allInitialCreateUnknown {
			continue
		}
		*violations = append(*violations, indexedResourceAddress(writerBase, bucketKey)+" member must exactly equal all destination bucket sinks' planned writer_identity")
	}
}

func resourceByAddress(resources []resourceChange, address string) *resourceChange {
	for index := range resources {
		if resources[index].Address == address {
			return &resources[index]
		}
	}
	return nil
}

func validateSigningAdministratorKeyRingGraph(resources []resourceChange, violations *[]string) {
	keyRing := resourceByAddress(resources, "module.signing_root.google_kms_key_ring.signing")
	if keyRing == nil {
		return
	}
	keyRingAfter, _ := keyRing.Change.After.(map[string]any)
	keyRingID, keyRingKnown := keyRingAfter["id"].(string)
	for _, resource := range resources {
		if resourceAddressBase(resource.Address) != "module.signing_root.google_kms_key_ring_iam_member.administrator" {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		bindingID, bindingKnown := after["key_ring_id"].(string)
		if keyRingKnown && keyRingID != "" && bindingKnown && bindingID == keyRingID && canonicalSigningKeyRing(bindingID) {
			continue
		}
		// The key-ring ID is provider-computed on initial creation. Exact paired
		// create addresses are accepted only with both leaves unknown and the
		// separately verified saved-plan source snapshot.
		if strings.Join(keyRing.Change.Actions, ",") == "create" && strings.Join(resource.Change.Actions, ",") == "create" &&
			(!keyRingKnown || keyRingID == "") && (!bindingKnown || bindingID == "") &&
			topLevelUnknown(keyRing.Change.AfterUnknown, "id") && topLevelUnknown(resource.Change.AfterUnknown, "key_ring_id") {
			continue
		}
		*violations = append(*violations, resource.Address+" must target the exact planned bootstrap-signing key ring")
	}
}

func validateKMSParentAndBucketGraph(resources []resourceChange, violations *[]string) {
	type keyPair struct {
		keyAddress  string
		ringAddress string
	}
	pairs := []keyPair{
		{"module.root_state.google_kms_crypto_key.state", "module.root_state.google_kms_key_ring.state"},
		{"module.root_state.google_kms_crypto_key.replica", "module.root_state.google_kms_key_ring.replica"},
		{"module.recovery_state.google_kms_crypto_key.state", "module.recovery_state.google_kms_key_ring.state"},
		{"module.recovery_state.google_kms_crypto_key.replica", "module.recovery_state.google_kms_key_ring.replica"},
	}
	for _, key := range []string{"primary", "recovery"} {
		pairs = append(pairs, keyPair{
			indexedResourceAddress("module.audit_root.google_kms_crypto_key.audit", key),
			indexedResourceAddress("module.audit_root.google_kms_key_ring.audit", key),
		})
	}
	for _, key := range []string{"exports", "evidence"} {
		pairs = append(pairs, keyPair{indexedResourceAddress("module.recovery_exports.google_kms_crypto_key.recovery", key), "module.recovery_exports.google_kms_key_ring.recovery"})
	}
	for _, key := range signingKeyNames {
		pairs = append(pairs, keyPair{indexedResourceAddress("module.signing_root.google_kms_crypto_key.signing", key), "module.signing_root.google_kms_key_ring.signing"})
	}
	for _, pair := range pairs {
		keyResource := resourceByAddress(resources, pair.keyAddress)
		ringResource := resourceByAddress(resources, pair.ringAddress)
		if keyResource == nil || ringResource == nil {
			continue
		}
		keyAfter, _ := keyResource.Change.After.(map[string]any)
		ringAfter, _ := ringResource.Change.After.(map[string]any)
		expectedRing := canonicalKMSKeyRingFromAfter(ringAfter)
		actualRing, actualKnown := keyAfter["key_ring"].(string)
		if expectedRing != "" && actualKnown && actualRing == expectedRing {
			continue
		}
		if strings.Join(keyResource.Change.Actions, ",") == "create" && strings.Join(ringResource.Change.Actions, ",") == "create" &&
			(!actualKnown || actualRing == "") && topLevelUnknown(keyResource.Change.AfterUnknown, "key_ring") {
			continue
		}
		*violations = append(*violations, pair.keyAddress+" must target its exact matching planned KMS key ring")
	}

	type bucketKeyPair struct {
		bucketAddress string
		keyAddress    string
		logging       bool
	}
	buckets := []bucketKeyPair{
		{indexedResourceAddress("module.root_state.google_storage_bucket.state", "primary"), "module.root_state.google_kms_crypto_key.state", false},
		{indexedResourceAddress("module.root_state.google_storage_bucket.state", "replica"), "module.root_state.google_kms_crypto_key.replica", false},
		{indexedResourceAddress("module.recovery_state.google_storage_bucket.state", "primary"), "module.recovery_state.google_kms_crypto_key.state", false},
		{indexedResourceAddress("module.recovery_state.google_storage_bucket.state", "replica"), "module.recovery_state.google_kms_crypto_key.replica", false},
	}
	for _, key := range []string{"exports", "evidence"} {
		buckets = append(buckets, bucketKeyPair{indexedResourceAddress("module.recovery_exports.google_storage_bucket.recovery", key), indexedResourceAddress("module.recovery_exports.google_kms_crypto_key.recovery", key), false})
	}
	for _, key := range []string{"primary", "recovery"} {
		buckets = append(buckets, bucketKeyPair{indexedResourceAddress("module.audit_root.google_logging_project_bucket_config.audit", key), indexedResourceAddress("module.audit_root.google_kms_crypto_key.audit", key), true})
	}
	for _, pair := range buckets {
		bucketResource := resourceByAddress(resources, pair.bucketAddress)
		keyResource := resourceByAddress(resources, pair.keyAddress)
		if bucketResource == nil || keyResource == nil {
			continue
		}
		bucketAfter, _ := bucketResource.Change.After.(map[string]any)
		keyAfter, _ := keyResource.Change.After.(map[string]any)
		expectedKey := canonicalKMSCryptoKeyFromAfter(keyAfter)
		var actualKey string
		if pair.logging {
			actualKey = nestedString(bucketAfter["cmek_settings"], "kms_key_name")
		} else {
			actualKey = nestedString(bucketAfter["encryption"], "default_kms_key_name")
		}
		if expectedKey != "" && actualKey == expectedKey {
			continue
		}
		unknown := nestedUnknown(bucketResource.Change.AfterUnknown, "encryption", "default_kms_key_name")
		if pair.logging {
			unknown = nestedUnknown(bucketResource.Change.AfterUnknown, "cmek_settings", "kms_key_name")
		}
		if strings.Join(bucketResource.Change.Actions, ",") == "create" && strings.Join(keyResource.Change.Actions, ",") == "create" && actualKey == "" && unknown {
			continue
		}
		*violations = append(*violations, pair.bucketAddress+" CMEK must equal its exact matching planned CryptoKey")
	}
}

func canonicalKMSKeyRingFromAfter(after map[string]any) string {
	project, _ := after["project"].(string)
	location, _ := after["location"].(string)
	name, _ := after["name"].(string)
	if !googleProjectIDPattern.MatchString(project) || location == "" || name == "" {
		return ""
	}
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", project, location, name)
}

func canonicalKMSCryptoKeyFromAfter(after map[string]any) string {
	keyRing, _ := after["key_ring"].(string)
	name, _ := after["name"].(string)
	if keyRing == "" || name == "" {
		return ""
	}
	return keyRing + "/cryptoKeys/" + name
}

// exactInitialSigningCreateProof recognizes the one unavoidable initial-create
// IAM envelope when a selected active CryptoKeyVersion has no server-assigned
// name yet. OpenTofu JSON references alone do NOT prove the CEL operators or
// literals: semantically unsafe expressions can serialize to the same reference
// list. Authorization therefore also requires the saved-plan archive's embedded
// source tree to byte-match the reviewed source. This function only narrows the
// JSON envelope after that independent source binding.
func exactInitialSigningCreateProof(parsed document, contract *signingContract) bool {
	if contract == nil || !contract.explicit {
		return false
	}
	module := configurationChildModule(parsed.Configuration, "signing_root")
	if module == nil {
		return false
	}
	signer := configurationResource(module, "google_kms_crypto_key_iam_member.signer", "google_kms_crypto_key_iam_member")
	recovery := configurationResource(module, "google_kms_crypto_key_iam_member.recovery_metadata", "google_kms_crypto_key_iam_member")
	return exactSignerConfigurationReferences(signer) && exactRecoveryMetadataConfigurationReferences(recovery)
}

func exactSigningVersionInventory(resources []resourceChange, contract *signingContract) bool {
	if contract == nil || len(contract.versions) == 0 {
		return false
	}
	want := contract.versions
	got := map[string]bool{}
	for _, resource := range resources {
		if resource.Mode != "managed" || resource.Type != "google_kms_crypto_key_version" {
			continue
		}
		actions := strings.Join(resource.Change.Actions, ",")
		if !want[resource.Address] || got[resource.Address] || (actions != "create" && actions != "read" && actions != "no-op") {
			return false
		}
		got[resource.Address] = true
	}
	return sameStringSet(got, want)
}

func signingContractFromVariables(variables map[string]struct {
	Value any `json:"value"`
},
) (*signingContract, bool, error) {
	variable, present := variables["bootstrap"]
	if !present {
		return nil, false, nil
	}
	bootstrap, ok := variable.Value.(map[string]any)
	if !ok {
		return nil, true, errors.New("bootstrap must be an object")
	}
	signing, _ := bootstrap["signing"].(map[string]any)
	keys, _ := signing["keys"].(map[string]any)
	if len(keys) != len(signingKeyNames) {
		return nil, true, fmt.Errorf("signing.keys must contain exactly %v", signingKeyNames)
	}
	contract := &signingContract{explicit: true, keys: map[string]signingKeyContract{}, versions: map[string]bool{}}
	for _, keyName := range signingKeyNames {
		key, ok := keys[keyName].(map[string]any)
		if !ok {
			return nil, true, fmt.Errorf("signing key %s must be an object", keyName)
		}
		active, _ := key["active_version_ref"].(string)
		versions, _ := key["versions"].(map[string]any)
		if !signingVersionPattern.MatchString(active) || key["rotation_days"] != float64(90) || len(versions) == 0 {
			return nil, true, fmt.Errorf("signing key %s must select a declared vYYYYMMDD version and rotate every 90 days", keyName)
		}
		parsedVersions := map[string]signingWindowContract{}
		ordered := make([]string, 0, len(versions))
		for versionRef, raw := range versions {
			declaration, ok := raw.(map[string]any)
			startText, startOK := declaration["activation_window_start"].(string)
			deadlineText, deadlineOK := declaration["rotation_deadline"].(string)
			start, startError := time.Parse(time.RFC3339, startText)
			deadline, deadlineError := time.Parse(time.RFC3339, deadlineText)
			if !ok || !startOK || !deadlineOK || !signingVersionPattern.MatchString(versionRef) || startError != nil || deadlineError != nil ||
				startText != start.UTC().Format("2006-01-02T15:04:05Z") || start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 ||
				versionRef != "v"+start.UTC().Format("20060102") || deadline.Sub(start) != 90*24*time.Hour ||
				deadlineText != deadline.UTC().Format("2006-01-02T15:04:05Z") {
				return nil, true, fmt.Errorf("signing key %s version %s must declare its exact 90-day UTC window", keyName, versionRef)
			}
			parsedVersions[versionRef] = signingWindowContract{activationWindowStart: startText, rotationDeadline: deadlineText}
			ordered = append(ordered, versionRef)
			contract.versions[indexedResourceAddress("module.signing_root.google_kms_crypto_key_version.signing", keyName+":"+versionRef)] = true
		}
		if _, ok := parsedVersions[active]; !ok {
			return nil, true, fmt.Errorf("signing key %s active version %s is not declared", keyName, active)
		}
		sort.Slice(ordered, func(i, j int) bool {
			return parsedVersions[ordered[i]].activationWindowStart < parsedVersions[ordered[j]].activationWindowStart
		})
		for index := 1; index < len(ordered); index++ {
			previousDeadline, _ := time.Parse(time.RFC3339, parsedVersions[ordered[index-1]].rotationDeadline)
			currentStart, _ := time.Parse(time.RFC3339, parsedVersions[ordered[index]].activationWindowStart)
			if !currentStart.Before(previousDeadline) {
				return nil, true, fmt.Errorf("signing key %s consecutive version windows must overlap", keyName)
			}
			if previousDeadline.Sub(currentStart) > 24*time.Hour {
				return nil, true, fmt.Errorf("signing key %s version windows may overlap by at most 24 hours", keyName)
			}
		}
		contract.keys[keyName] = signingKeyContract{activeVersionRef: active, versions: parsedVersions}
	}
	return contract, true, nil
}

func defaultSigningContract() *signingContract {
	contract := &signingContract{keys: map[string]signingKeyContract{}, versions: map[string]bool{}}
	window := signingWindowContract{activationWindowStart: "2026-08-29T00:00:00Z", rotationDeadline: "2026-11-27T00:00:00Z"}
	for _, keyName := range signingKeyNames {
		contract.keys[keyName] = signingKeyContract{activeVersionRef: "v20260829", versions: map[string]signingWindowContract{"v20260829": window}}
		contract.versions[indexedResourceAddress("module.signing_root.google_kms_crypto_key_version.signing", keyName+":v20260829")] = true
	}
	return contract
}

func auditLockContractFromVariables(variables map[string]struct {
	Value any `json:"value"`
}, signing *signingContract,
) (auditLockContract, error) {
	bootstrapVariable, present := variables["bootstrap"]
	if !present {
		return auditLockContract{}, nil
	}
	bootstrap, _ := bootstrapVariable.Value.(map[string]any)
	audit, present := bootstrap["audit"].(map[string]any)
	if !present {
		return auditLockContract{}, nil
	}
	locked, ok := audit["lock_after_qualification"].(bool)
	if !ok {
		return auditLockContract{declared: true}, errors.New("audit.lock_after_qualification must be boolean")
	}
	evidence := audit["qualification_evidence"]
	if !locked {
		if !plannedUnset(evidence) {
			return auditLockContract{declared: true}, errors.New("qualification evidence must be null until locking is declared")
		}
		return auditLockContract{declared: true}, nil
	}
	object, ok := evidence.(map[string]any)
	if !ok || !exactObjectKeys(object, []string{"artifact_sha256", "signature_sha256", "signing_key_ref", "qualified_source_sha", "qualified_at"}) {
		return auditLockContract{declared: true, locked: true}, errors.New("locked audit retention requires the exact qualification-evidence object")
	}
	sha256Pattern := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	gitSHA, _ := object["qualified_source_sha"].(string)
	qualifiedAt, _ := object["qualified_at"].(string)
	qualifiedTime, qualifiedError := time.Parse(time.RFC3339, qualifiedAt)
	activeAuditRef := ""
	if declaration, found := signingKeyDeclaration(signing, "audit-anchor"); found {
		activeAuditRef = declaration.activeVersionRef
	}
	if !sha256Pattern.MatchString(stringValue(object["artifact_sha256"])) ||
		!sha256Pattern.MatchString(stringValue(object["signature_sha256"])) ||
		!regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(gitSHA) || qualifiedError != nil ||
		qualifiedAt != qualifiedTime.UTC().Format("2006-01-02T15:04:05Z") ||
		object["signing_key_ref"] != "audit-anchor:"+activeAuditRef {
		return auditLockContract{declared: true, locked: true}, errors.New("qualification evidence must bind exact digests, source, UTC time, and active audit-anchor")
	}
	return auditLockContract{declared: true, locked: true}, nil
}

func activeSigningVersionCreates(resources []resourceChange, contract *signingContract) map[string]bool {
	result := map[string]bool{}
	if contract == nil {
		return result
	}
	for _, resource := range resources {
		keyName, versionRef, ok := declaredSigningVersionAddress(resource.Address, contract)
		if ok && contract.keys[keyName].activeVersionRef == versionRef && strings.Join(resource.Change.Actions, ",") == "create" {
			result[keyName] = true
		}
	}
	return result
}

func initialSigningIAMAddressUsesCreatedActiveVersion(address string, active map[string]bool) bool {
	if address == "module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata" {
		return active["recovery-evidence"]
	}
	const base = "module.signing_root.google_kms_crypto_key_iam_member.signer"
	instance, indexed, _ := terraformAddressStringIndex(address, base)
	parts := strings.SplitN(instance, ":", 2)
	return indexed && len(parts) == 2 && active[parts[0]]
}

func configurationChildModule(configuration map[string]any, name string) map[string]any {
	root, _ := configuration["root_module"].(map[string]any)
	calls, _ := root["module_calls"].(map[string]any)
	call, _ := calls[name].(map[string]any)
	module, _ := call["module"].(map[string]any)
	return module
}

func configurationResource(module map[string]any, address, resourceType string) map[string]any {
	resources, _ := module["resources"].([]any)
	var match map[string]any
	for _, value := range resources {
		resource, _ := value.(map[string]any)
		if resource["address"] != address {
			continue
		}
		if match != nil || resource["mode"] != "managed" || resource["type"] != resourceType {
			return nil
		}
		match = resource
	}
	return match
}

func exactSignerConfigurationReferences(resource map[string]any) bool {
	condition, ok := configurationCondition(resource)
	if !ok || len(condition) != 2 {
		return false
	}
	return exactExpressionReferences(condition["expression"], []string{
		"google_kms_crypto_key_version.signing",
		"each.value.active_version_key",
		"each.value",
		"each.value.activation_window_start",
		"each.value",
		"each.value.rotation_deadline",
		"each.value",
	}) && exactExpressionReferences(condition["title"], []string{
		"each.value.key_name",
		"each.value",
		"each.value.active_version_ref",
		"each.value",
	})
}

func exactRecoveryMetadataConfigurationReferences(resource map[string]any) bool {
	condition, ok := configurationCondition(resource)
	if !ok || len(condition) != 3 {
		return false
	}
	description, _ := condition["description"].(map[string]any)
	title, _ := condition["title"].(map[string]any)
	return len(description) == 1 && description["constant_value"] == "Permit connected verification to inspect only the recovery-evidence key and its source-selected active version." &&
		len(title) == 1 && title["constant_value"] == "read-recovery-evidence-active-key-version-only" &&
		exactExpressionReferences(condition["expression"], []string{
			`google_kms_crypto_key.signing["recovery-evidence"].id`,
			`google_kms_crypto_key.signing["recovery-evidence"]`,
			"google_kms_crypto_key.signing",
			"google_kms_crypto_key_version.signing",
			`var.keys["recovery-evidence"].active_version_ref`,
			`var.keys["recovery-evidence"]`,
			"var.keys",
		})
}

func configurationCondition(resource map[string]any) (map[string]any, bool) {
	expressions, _ := resource["expressions"].(map[string]any)
	conditions, _ := expressions["condition"].([]any)
	if len(conditions) != 1 {
		return nil, false
	}
	condition, ok := conditions[0].(map[string]any)
	return condition, ok
}

func exactExpressionReferences(value any, expected []string) bool {
	expression, _ := value.(map[string]any)
	references, _ := expression["references"].([]any)
	if len(expression) != 1 || len(references) != len(expected) {
		return false
	}
	for index, reference := range references {
		if reference != expected[index] {
			return false
		}
	}
	return true
}

var rootTrustDynamicFamilyCounts = map[string]int{
	"module.audit_root.google_project_iam_member.reader":               6,
	"module.audit_root.google_project_iam_member.administrator":        2,
	"module.signing_root.google_kms_key_ring_iam_member.administrator": 2,
	"module.signing_root.google_kms_crypto_key_iam_member.signer":      7,
	"module.break_glass.google_project_service.pam":                    4,
}

func validateCompositionCompleteness(resources []resourceChange, root string, signing *signingContract, ciEvidenceEnabled, nixCacheActivated bool, nixCacheAccessorCount int, violations *[]string) {
	wantRecovery := root == "recovery-plane"
	if len(resources) == 0 {
		*violations = append(*violations, fmt.Sprintf("--root %s plan must contain the configured Ring-0 resources, including no-op instances", root))
	}
	seenAddresses := map[string]int{}
	seenFamilies := map[string][]resourceChange{}
	for _, resource := range resources {
		base := resourceAddressBase(resource.Address)
		seenAddresses[resource.Address]++
		seenFamilies[base] = append(seenFamilies[base], resource)
		isRecovery := strings.HasPrefix(base, "module.recovery_exports.")
		if isRecovery != wantRecovery {
			*violations = append(*violations, fmt.Sprintf("%s belongs to the wrong composition for --root %s", resource.Address, root))
		}
	}
	for address, count := range seenAddresses {
		if count != 1 {
			*violations = append(*violations, address+" must occur exactly once in the planned composition")
		}
	}

	for family := range approvedResourceAddressFamilies {
		parts := strings.SplitN(family, "|", 3)
		if len(parts) != 3 {
			continue
		}
		base := parts[2]
		isRecovery := strings.HasPrefix(base, "module.recovery_exports.")
		if isRecovery != wantRecovery {
			continue
		}
		if !ciEvidenceEnabled && (base == "module.github_federation.google_iam_workload_identity_pool.ci_evidence" ||
			base == "module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence" ||
			base == "module.github_federation.google_service_account_iam_member.ci_evidence") {
			continue
		}
		if base == "module.signing_root.google_secret_manager_secret_version.nix_cache_signing" {
			expected := 0
			if nixCacheActivated {
				expected = 1
			}
			if len(seenFamilies[base]) != expected {
				*violations = append(*violations, fmt.Sprintf("--root %s plan must contain exactly %d activation-qualified Nix cache signing secret versions", root, expected))
			}
			continue
		}
		if base == "module.signing_root.google_secret_manager_secret_iam_member.nix_cache_accessor" {
			expected := 0
			if nixCacheActivated {
				expected = nixCacheAccessorCount
			}
			if len(seenFamilies[base]) != expected {
				*violations = append(*violations, fmt.Sprintf("--root %s plan must contain exactly %d activation-qualified Nix cache signing accessors", root, expected))
			}
			continue
		}
		if base == "module.github_federation.google_iam_workload_identity_pool.github_config" ||
			base == "module.github_federation.google_iam_workload_identity_pool_provider.github_config" ||
			base == "module.github_federation.google_service_account_iam_member.github_config" ||
			base == "module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_drift" ||
			base == "module.github_federation.google_service_account_iam_member.infrastructure_drift" {
			continue
		}
		if base == "module.signing_root.google_kms_crypto_key_version.signing" {
			if signing == nil {
				*violations = append(*violations, "--root root-trust plan cannot derive the exact signing-version inventory")
				continue
			}
			for address := range signing.versions {
				if seenAddresses[address] != 1 {
					*violations = append(*violations, fmt.Sprintf("--root %s plan must contain exact declared signing version %s, including when it is no-op", root, address))
				}
			}
			if len(seenFamilies[base]) != len(signing.versions) {
				*violations = append(*violations, fmt.Sprintf("--root %s plan signing-version inventory must exactly equal the compiled append-only declarations", root))
			}
			continue
		}
		if keys, indexed := exactResourceAddressKeys[base]; indexed {
			for key := range keys {
				address := indexedResourceAddress(base, key)
				if seenAddresses[address] != 1 {
					*violations = append(*violations, fmt.Sprintf("--root %s plan must contain exact configured instance %s, including when it is no-op", root, address))
				}
			}
			continue
		}
		if _, dynamic := dynamicResourceAddressKeys[base]; dynamic {
			expected := rootTrustDynamicFamilyCounts[base]
			if wantRecovery || expected == 0 || len(seenFamilies[base]) != expected {
				*violations = append(*violations, fmt.Sprintf("--root %s plan must contain exactly %d configured instances of %s, including no-op instances", root, expected, base))
			}
			continue
		}
		if seenAddresses[base] != 1 {
			*violations = append(*violations, fmt.Sprintf("--root %s plan must contain configured resource %s, including when it is no-op", root, base))
		}
	}
	if !wantRecovery {
		validateRootTrustDynamicCoverage(resources, seenFamilies, violations)
	}
}

func resourceAddressBase(address string) string {
	if index := strings.IndexByte(address, '['); index >= 0 {
		return address[:index]
	}
	return address
}

func indexedResourceAddress(base, key string) string {
	encoded, _ := json.Marshal(key)
	return base + "[" + string(encoded) + "]"
}

func validateRootTrustDynamicCoverage(resources []resourceChange, families map[string][]resourceChange, violations *[]string) {
	projects := map[string]string{}
	projectAddresses := map[string]string{
		"google_project.identity":                    "identity",
		`google_project.state["root_state"]`:         "root_state",
		`google_project.state["recovery"]`:           "recovery",
		"module.audit_root.google_project.audit":     "audit",
		"module.signing_root.google_project.signing": "signing",
	}
	for _, resource := range resources {
		logical := projectAddresses[resource.Address]
		if logical == "" {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		projects[logical], _ = after["project_id"].(string)
	}

	validatePAMServiceCoverage(families["module.break_glass.google_project_service.pam"], projects, violations)
	validateAuditReaderCoverage(families["module.audit_root.google_project_iam_member.reader"], projects, violations)
	validateAuditAdministratorCoverage(families["module.audit_root.google_project_iam_member.administrator"], violations)
	validateSigningAdministratorCoverage(families["module.signing_root.google_kms_key_ring_iam_member.administrator"], violations)
	validateSigningPrincipalCoverage(resources, families["module.signing_root.google_kms_crypto_key_iam_member.signer"], violations)
}

func validatePAMServiceCoverage(resources []resourceChange, projects map[string]string, violations *[]string) {
	want := stringSet(projects["identity"], projects["root_state"], projects["recovery"], projects["signing"])
	delete(want, "")
	got := map[string]bool{}
	for _, resource := range resources {
		const base = "module.break_glass.google_project_service.pam"
		instance, _, _ := terraformAddressStringIndex(resource.Address, base)
		got[instance] = true
	}
	if !sameStringSet(got, want) {
		*violations = append(*violations, "break-glass PAM service instances must exactly cover the four planned entitlement projects")
	}
}

func validateAuditReaderCoverage(resources []resourceChange, projects map[string]string, violations *[]string) {
	byProject := map[string]map[string]bool{}
	for _, resource := range resources {
		after, _ := resource.Change.After.(map[string]any)
		project, _ := after["project"].(string)
		member, _ := after["member"].(string)
		if byProject[project] == nil {
			byProject[project] = map[string]bool{}
		}
		byProject[project][member] = true
	}
	primary := byProject[projects["audit"]]
	recovery := byProject[projects["recovery"]]
	valid := len(byProject) == 2 && len(primary) == 3 && sameStringSet(primary, recovery)
	groupCount := 0
	recoveryCount := 0
	for member := range primary {
		if groupEmailPrincipalPattern.MatchString(member) {
			groupCount++
		}
		if bootstrapRecoveryPrincipalPattern.MatchString(member) {
			recoveryCount++
		}
	}
	if !valid || groupCount != 2 || recoveryCount != 1 {
		*violations = append(*violations, "audit reader instances must exactly replicate two declared human groups plus the recovery identity across both exact audit-bucket views")
	}
}

func validateAuditAdministratorCoverage(resources []resourceChange, violations *[]string) {
	byRole := map[string]map[string]bool{}
	for _, resource := range resources {
		after, _ := resource.Change.After.(map[string]any)
		role, _ := after["role"].(string)
		member, _ := after["member"].(string)
		if byRole[role] == nil {
			byRole[role] = map[string]bool{}
		}
		byRole[role][member] = true
	}
	writers := byRole["roles/logging.configWriter"]
	apply := false
	for member := range writers {
		apply = apply || bootstrapApplyPrincipalPattern.MatchString(member)
	}
	if len(byRole) != 1 || len(writers) != 2 || !apply {
		*violations = append(*violations, "audit administrator instances must grant only logging configuration authority to the declared root administrator and bootstrap-apply identity")
	}
}

func validateSigningAdministratorCoverage(resources []resourceChange, violations *[]string) {
	members := map[string]bool{}
	for _, resource := range resources {
		after, _ := resource.Change.After.(map[string]any)
		member, _ := after["member"].(string)
		members[member] = true
	}
	valid := len(members) == 2
	for member := range members {
		valid = valid && groupEmailPrincipalPattern.MatchString(member) && !bootstrapApplyPrincipalPattern.MatchString(member)
	}
	if !valid {
		*violations = append(*violations, "signing key-ring administrator instances must contain only the two declared independent administrators")
	}
}

func validateSigningPrincipalCoverage(allResources, resources []resourceChange, violations *[]string) {
	byKey := map[string]map[string]bool{}
	for _, resource := range resources {
		const base = "module.signing_root.google_kms_crypto_key_iam_member.signer"
		instance, _, _ := terraformAddressStringIndex(resource.Address, base)
		parts := strings.SplitN(instance, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if byKey[parts[0]] == nil {
			byKey[parts[0]] = map[string]bool{}
		}
		byKey[parts[0]][parts[1]] = true
	}
	buildkiteMember := ""
	for _, resource := range allResources {
		if resource.Address != "module.buildkite_federation.google_service_account.buildkite" {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		buildkiteMember, _ = after["member"].(string)
	}
	recoveryIdentity := false
	for member := range byKey["recovery-evidence"] {
		recoveryIdentity = recoveryIdentity || bootstrapRecoveryPrincipalPattern.MatchString(member)
	}
	valid := len(byKey) == 4 && len(byKey["audit-anchor"]) == 2 && len(byKey["bootstrap-handoff"]) == 2 &&
		len(byKey["connected-observation-evidence"]) == 0 && len(byKey["github-config-plan-evidence"]) == 1 && len(byKey["infrastructure-export"]) == 0 &&
		len(byKey["recovery-evidence"]) == 2 && buildkiteMember != "" && byKey["audit-anchor"][buildkiteMember] &&
		byKey["bootstrap-handoff"][buildkiteMember] && recoveryIdentity
	if !valid {
		*violations = append(*violations, "signer instances must exactly cover approved pipeline/recovery/governance identities while connected-observation-evidence and infrastructure-export remain IAM-disabled pending qualification")
	}
}

func sameStringSet(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if !right[value] {
			return false
		}
	}
	return true
}

// validateRootTrustVariableGraph binds the strict authorization path to the
// compiler output, rather than accepting merely well-shaped replacement IDs or
// principals. Generic Analyze intentionally remains useful for isolated
// resource diagnostics.
func validateRootTrustVariableGraph(parsed document, signing *signingContract, violations *[]string) {
	bootstrapVariable, ok := parsed.Variables["bootstrap"]
	bootstrap, bootstrapOK := bootstrapVariable.Value.(map[string]any)
	projectsObject, projectsOK := bootstrap["projects"].(map[string]any)
	organizationID, organizationOK := bootstrap["organization_id"].(string)
	billingAccount, billingOK := bootstrap["billing_account"].(string)
	if !ok || !bootstrapOK || !projectsOK || !organizationOK || !billingOK || !numericIDPattern.MatchString(organizationID) || !billingAccountPattern.MatchString(billingAccount) {
		*violations = append(*violations, "compiled bootstrap organization, billing account, and project graph must be explicit and canonical")
		return
	}
	projectAddresses := map[string]string{
		"identity":   "google_project.identity",
		"root_state": `google_project.state["root_state"]`,
		"recovery":   `google_project.state["recovery"]`,
		"audit":      "module.audit_root.google_project.audit",
		"signing":    "module.signing_root.google_project.signing",
	}
	compiledProjects := map[string]string{}
	for logical, address := range projectAddresses {
		declaration, declarationOK := projectsObject[logical].(map[string]any)
		projectID, idOK := declaration["id"].(string)
		projectName, nameOK := declaration["name"].(string)
		after := resourceAfter(parsed.ResourceChanges, address)
		if !declarationOK || !idOK || !nameOK || !googleProjectIDPattern.MatchString(projectID) || after == nil ||
			after["project_id"] != projectID || after["name"] != projectName || after["org_id"] != organizationID || after["billing_account"] != billingAccount {
			*violations = append(*violations, address+" must exactly equal its compiled project name, ID, organization, and billing account")
		}
		compiledProjects[logical] = projectID
	}

	for _, resource := range parsed.ResourceChanges {
		after, _ := resource.Change.After.(map[string]any)
		if (resource.Type == "google_organization_iam_member" || resource.Type == "google_organization_iam_custom_role") && after["org_id"] != organizationID {
			*violations = append(*violations, resource.Address+" must target the compiled bootstrap organization")
		}
		if resource.Type == "google_logging_organization_sink" && after["org_id"] != organizationID {
			*violations = append(*violations, resource.Address+" must aggregate the compiled bootstrap organization")
		}
		if resource.Address == "module.workforce_identity.google_iam_workforce_pool.workforce" && after["parent"] != "organizations/"+organizationID {
			*violations = append(*violations, resource.Address+" must use the compiled bootstrap organization parent")
		}
	}

	validateCompiledStateBackendGraph(parsed.ResourceChanges, bootstrap, violations)
	validateCompiledWorkforceGraph(parsed.ResourceChanges, bootstrap, organizationID, violations)
	validateCompiledAuditGraph(parsed.ResourceChanges, bootstrap, compiledProjects, organizationID, violations)
	principals := validateCompiledFederationGraph(parsed.ResourceChanges, bootstrap, compiledProjects, violations)
	validateCompiledPrincipalGraph(parsed.ResourceChanges, bootstrap, signing, principals, violations)
}

func validateCompiledStateBackendGraph(resources []resourceChange, bootstrap map[string]any, violations *[]string) {
	backends, backendsOK := bootstrap["state_backends"].(map[string]any)
	contracts := []struct {
		name   string
		module string
	}{
		{name: "root_trust", module: "module.root_state"},
		{name: "recovery_plane", module: "module.recovery_state"},
	}
	if !backendsOK || !exactObjectKeys(backends, []string{"root_trust", "recovery_plane"}) {
		*violations = append(*violations, "compiled state_backends must contain exactly root_trust and recovery_plane")
		return
	}
	for _, contract := range contracts {
		declaration, declarationOK := backends[contract.name].(map[string]any)
		primaryBucket := resourceAfter(resources, indexedResourceAddress(contract.module+".google_storage_bucket.state", "primary"))
		replicaBucket := resourceAfter(resources, indexedResourceAddress(contract.module+".google_storage_bucket.state", "replica"))
		primaryKey := resourceAfter(resources, contract.module+".google_kms_crypto_key.state")
		replicaKey := resourceAfter(resources, contract.module+".google_kms_crypto_key.replica")
		expectedPrefix := strings.ReplaceAll(contract.name, "_", "-")
		if !declarationOK || declaration["prefix"] != expectedPrefix || primaryBucket == nil || replicaBucket == nil ||
			primaryKey == nil || replicaKey == nil || primaryBucket["name"] != declaration["bucket_name"] ||
			replicaBucket["name"] != declaration["replica_bucket_name"] || primaryKey["name"] != declaration["key_name"] ||
			replicaKey["name"] != declaration["replica_key_name"] {
			*violations = append(*violations, contract.module+" bucket, replica, CMEKs, and prefix must exactly equal the compiled backend declaration")
		}
	}
}

func validateCompiledWorkforceGraph(resources []resourceChange, bootstrap map[string]any, organizationID string, violations *[]string) {
	declaration, declarationOK := bootstrap["workforce"].(map[string]any)
	pool := resourceAfter(resources, "module.workforce_identity.google_iam_workforce_pool.workforce")
	provider := resourceAfter(resources, "module.workforce_identity.google_iam_workforce_pool_provider.oidc")
	oidc, oidcOK := singleObject(provider["oidc"])
	webSSO, webSSOOK := singleObject(oidc["web_sso_config"])
	if !declarationOK || pool == nil || provider == nil || !oidcOK || !webSSOOK ||
		pool["workforce_pool_id"] != declaration["pool_id"] || pool["parent"] != "organizations/"+organizationID ||
		provider["workforce_pool_id"] != declaration["pool_id"] || provider["provider_id"] != declaration["provider_id"] ||
		provider["attribute_condition"] != declaration["attribute_condition"] ||
		!sameJSONValue(provider["attribute_mapping"], declaration["attribute_mapping"]) ||
		oidc["issuer_uri"] != declaration["issuer_uri"] || oidc["client_id"] != declaration["client_id"] ||
		!sameJSONValue(webSSO["additional_scopes"], declaration["additional_scopes"]) {
		*violations = append(*violations, "workforce pool and provider must exactly equal the compiled organization, IDs, issuer, client, administrator condition, mapping, and scopes")
	}
}

type bootstrapPrincipals struct {
	plan      string
	apply     string
	recovery  string
	buildkite string
}

func validateCompiledAuditGraph(resources []resourceChange, bootstrap map[string]any, projects map[string]string, organizationID string, violations *[]string) {
	audit, _ := bootstrap["audit"].(map[string]any)
	buckets, _ := audit["buckets"].(map[string]any)
	for _, key := range []string{"primary", "recovery"} {
		declaration, _ := buckets[key].(map[string]any)
		after := resourceAfter(resources, indexedResourceAddress("module.audit_root.google_logging_project_bucket_config.audit", key))
		logical := "audit"
		if key == "recovery" {
			logical = "recovery"
		}
		if after == nil || after["project"] != projects[logical] || after["bucket_id"] != declaration["bucket_id"] ||
			after["location"] != declaration["location"] || after["retention_days"] != audit["retention_days"] {
			*violations = append(*violations, "audit bucket "+key+" must exactly equal its compiled project, ID, region, and retention")
		}
		cryptoKey := resourceAfter(resources, indexedResourceAddress("module.audit_root.google_kms_crypto_key.audit", key))
		if cryptoKey == nil || cryptoKey["name"] != declaration["key_name"] {
			*violations = append(*violations, "audit "+key+" CMEK must exactly equal its compiled key name")
		}
	}
	sinks, _ := audit["sinks"].(map[string]any)
	for sinkKey, raw := range sinks {
		declaration, _ := raw.(map[string]any)
		bucketKey, _ := declaration["bucket_id"].(string)
		bucket, _ := buckets[bucketKey].(map[string]any)
		logical := "audit"
		if bucketKey == "recovery" {
			logical = "recovery"
		}
		after := resourceAfter(resources, indexedResourceAddress("module.audit_root.google_logging_organization_sink.audit", sinkKey))
		expectedDestination := fmt.Sprintf("logging.googleapis.com/projects/%s/locations/%s/buckets/%s", projects[logical], stringValue(bucket["location"]), stringValue(bucket["bucket_id"]))
		resource := resourceByAddress(resources, indexedResourceAddress("module.audit_root.google_logging_organization_sink.audit", sinkKey))
		destinationMatches := after != nil && after["destination"] == expectedDestination
		if resource != nil && strings.Join(resource.Change.Actions, ",") == "create" &&
			plannedUnset(after["destination"]) && topLevelUnknown(resource.Change.AfterUnknown, "destination") {
			// The provider computes this exact protected-bucket reference only
			// on initial create; the sink invariant also constrains its region
			// and bucket ID.
			destinationMatches = true
		}
		if after == nil || after["name"] != declaration["name"] || after["filter"] != declaration["filter"] ||
			after["org_id"] != organizationID || !destinationMatches {
			*violations = append(*violations, "audit sink "+sinkKey+" must exactly equal its compiled organization, filter, and protected bucket destination")
		}
	}
}

func validateCompiledFederationGraph(resources []resourceChange, bootstrap map[string]any, projects map[string]string, violations *[]string) bootstrapPrincipals {
	github, _ := bootstrap["github"].(map[string]any)
	privateQualified := validateBootstrapVisibilityTransition(github, violations)
	serviceAccountIDs, _ := github["service_account_ids"].(map[string]any)
	principals := bootstrapPrincipals{
		plan:     serviceAccountPrincipal(stringValue(serviceAccountIDs["plan"]), projects["root_state"]),
		apply:    serviceAccountPrincipal(stringValue(serviceAccountIDs["apply"]), projects["root_state"]),
		recovery: serviceAccountPrincipal(stringValue(serviceAccountIDs["recovery"]), projects["recovery"]),
	}
	poolIDs, _ := github["pool_ids"].(map[string]any)
	providerIDs, _ := github["provider_ids"].(map[string]any)
	audiences, _ := github["audiences"].(map[string]any)
	workflowRefs, _ := github["workflow_refs"].(map[string]any)
	for _, instance := range []string{"plan", "apply", "recovery"} {
		poolAddress := indexedResourceAddress("module.github_federation.google_iam_workload_identity_pool.github", instance)
		providerAddress := indexedResourceAddress("module.github_federation.google_iam_workload_identity_pool_provider.github", instance)
		serviceAddress := indexedResourceAddress("module.github_federation.google_service_account.github", instance)
		bindingAddress := indexedResourceAddress("module.github_federation.google_service_account_iam_member.github", instance)
		pool := resourceAfter(resources, poolAddress)
		provider := resourceAfter(resources, providerAddress)
		service := resourceAfter(resources, serviceAddress)
		binding := resourceAfter(resources, bindingAddress)
		serviceProject := projects["root_state"]
		poolProject := projects["identity"]
		if instance == "recovery" {
			serviceProject = projects["recovery"]
			poolProject = projects["recovery"]
		}
		poolID := stringValue(poolIDs[instance])
		providerID := stringValue(providerIDs[instance])
		accountID := stringValue(serviceAccountIDs[instance])
		if pool == nil || pool["project"] != poolProject || pool["workload_identity_pool_id"] != poolID || pool["disabled"] != !privateQualified {
			*violations = append(*violations, poolAddress+" must exactly equal its compiled separated pool project and pool ID")
		}
		if service == nil || service["project"] != serviceProject || service["account_id"] != accountID {
			*violations = append(*violations, serviceAddress+" must exactly equal its compiled service-account project and ID")
		}
		environment := map[string]string{"plan": "trusted-build", "apply": "infrastructure-apply", "recovery": "infrastructure-apply"}[instance]
		validateCompiledBootstrapProvider(providerAddress, provider, github, poolProject, poolID, providerID,
			stringValue(audiences[instance]), environment, stringValue(workflowRefs[instance]), instance, privateQualified, violations)
		validateCompiledFederationBinding(bindingAddress, binding, pool, accountID, serviceProject, "repository_id", stringValue(github["repository_id"]), violations)
	}
	validateCompiledFederationActivation(bootstrap, violations)
	validateCompiledGithubConfigGraph(resources, bootstrap, projects, violations)
	validateCompiledInfrastructureFederationGraph(resources, bootstrap, projects, violations)
	validateCompiledCIEvidenceGraph(resources, bootstrap, projects, violations)

	buildkite, _ := bootstrap["buildkite"].(map[string]any)
	principals.buildkite = serviceAccountPrincipal(stringValue(buildkite["service_account_id"]), projects["root_state"])
	validateCompiledSingleFederation(resources, "buildkite", buildkite, projects["identity"], projects["root_state"], map[string]string{
		"sub": stringValue(buildkite["pipeline_id"]), "organization_slug": stringValue(buildkite["organization_slug"]),
		"pipeline_slug": stringValue(buildkite["pipeline_slug"]), "pipeline_id": stringValue(buildkite["pipeline_id"]),
		"build_branch": stringValue(buildkite["build_branch"]), "step_key": stringValue(buildkite["step_key"]),
	}, "pipeline_id", stringValue(buildkite["pipeline_id"]), violations)
	gitops, _ := bootstrap["gitops"].(map[string]any)
	validateCompiledSingleFederation(resources, "gitops", gitops, projects["identity"], projects["recovery"], map[string]string{
		"sub": stringValue(gitops["subject"]), "repository": stringValue(gitops["repository"]), "ref": stringValue(gitops["ref"]),
	}, "repository", stringValue(gitops["repository"]), violations)
	return principals
}

func validateBootstrapVisibilityTransition(github map[string]any, violations *[]string) bool {
	transition, ok := github["visibility_transition"].(map[string]any)
	state := stringValue(transition["state"])
	activationEnabled, activationOK := transition["activation_enabled"].(bool)
	digestPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	valid := ok && activationOK && transition["source_visibility"] == "public" && transition["final_visibility"] == "private" &&
		transition["executor_repository_enabled"] == false && plannedUnset(transition["executor_repository_id"]) &&
		exactStringSet(transition["required_reviewer_gates"], []string{"security", "platform"})
	qualified := false
	switch state {
	case "AWAITING_PRIVATE_VISIBILITY":
		valid = valid && !activationEnabled && plannedUnset(transition["visibility_evidence_digest"]) &&
			plannedUnset(transition["reviewer_evidence_digest"]) &&
			exactStringSet(transition["blockers"], []string{"private-visibility-not-evidenced", "independent-review-not-evidenced"})
	case "PRIVATE_QUALIFIED":
		qualified = true
		visibilityDigest := stringValue(transition["visibility_evidence_digest"])
		reviewerDigest := stringValue(transition["reviewer_evidence_digest"])
		valid = valid && activationEnabled && digestPattern.MatchString(visibilityDigest) &&
			visibilityDigest != strings.Repeat("0", 64) && digestPattern.MatchString(reviewerDigest) &&
			reviewerDigest != strings.Repeat("0", 64) && exactStringSet(transition["blockers"], []string{})
	default:
		valid = false
	}
	if !valid {
		*violations = append(*violations, "compiled bootstrap visibility transition must remain exact-repository, no-executor, private-only, and independently reviewed")
		return false
	}
	return qualified
}

func validateCompiledFederationActivation(bootstrap map[string]any, violations *[]string) {
	activation, ok := bootstrap["github_activation"].(map[string]any)
	active := stringSetFromList(activation["active_subject_ids"])
	gated := stringSetFromList(activation["gated_subject_ids"])
	blockers := stringSetFromList(activation["blockers"])
	blockedActive := stringSet(
		"bootstrap-protected-plan", "bootstrap-protected-apply", "bootstrap-recovery-verification",
		"infrastructure-live-development-plan", "infrastructure-live-development-apply",
		"infrastructure-live-staging-plan", "infrastructure-live-staging-apply",
		"infrastructure-live-production-plan", "infrastructure-live-production-apply",
		"infrastructure-live-restricted-plan", "infrastructure-live-restricted-apply",
	)
	blockedGated := stringSet(
		"github-config-drift-plan", "github-config-protected-plan", "github-config-protected-apply",
		"infrastructure-drift-plan", "infrastructure-ci-evidence-verifier",
	)
	allSubjects := map[string]bool{}
	for subject := range blockedActive {
		allSubjects[subject] = true
	}
	for subject := range blockedGated {
		allSubjects[subject] = true
	}
	founderActive := map[string]bool{}
	for subject := range blockedActive {
		founderActive[subject] = true
	}
	founderActive["github-config-protected-plan"] = true
	founderActive["github-config-protected-apply"] = true
	founderGated := stringSet("github-config-drift-plan", "infrastructure-drift-plan", "infrastructure-ci-evidence-verifier")
	state := stringValue(activation["state"])
	valid := ok
	githubConfigActivationEnabled := false
	connectedActivationEnabled := false
	switch state {
	case "BLOCKED":
		_, exceptionPresent := activation["exception_ref"]
		valid = valid && !exceptionPresent && sameStringSet(active, blockedActive) && sameStringSet(gated, blockedGated) &&
			sameStringSet(blockers, stringSet(
				"github-config-control-plane-federation-not-connected-qualified",
				"infrastructure-drift-federation-not-connected-qualified",
				"ci-evidence-federation-not-connected-qualified",
			))
	case "FOUNDER_BOOTSTRAPPED":
		githubConfigActivationEnabled = true
		valid = valid && activation["exception_ref"] == "FBE-0001" && sameStringSet(active, founderActive) && sameStringSet(gated, founderGated) &&
			sameStringSet(blockers, stringSet("independent-review-not-connected-qualified", "production-authority-disabled"))
	case "CONNECTED_QUALIFIED":
		githubConfigActivationEnabled = true
		connectedActivationEnabled = true
		_, exceptionPresent := activation["exception_ref"]
		valid = valid && !exceptionPresent && sameStringSet(active, allSubjects) && len(gated) == 0 && len(blockers) == 0
	default:
		valid = false
	}
	githubConfig, _ := bootstrap["github_config"].(map[string]any)
	infrastructure, _ := bootstrap["github_infrastructure"].(map[string]any)
	drift, _ := infrastructure["drift"].(map[string]any)
	ciEvidence, _ := bootstrap["github_ci_evidence"].(map[string]any)
	valid = valid && githubConfig["activation_enabled"] == githubConfigActivationEnabled &&
		drift["activation_enabled"] == connectedActivationEnabled && ciEvidence["activation_enabled"] == connectedActivationEnabled
	if !valid {
		*violations = append(*violations, "compiled federation activation and conditional provider graphs must equal the exact BLOCKED, FOUNDER_BOOTSTRAPPED/FBE-0001 foundation-only, or CONNECTED_QUALIFIED lifecycle profile")
	}
}

func validateCompiledGithubConfigGraph(resources []resourceChange, bootstrap map[string]any, projects map[string]string, violations *[]string) {
	declaration, ok := bootstrap["github_config"].(map[string]any)
	identities, identitiesOK := declaration["identities"].(map[string]any)
	enabled, enabledOK := declaration["activation_enabled"].(bool)
	activation, activationOK := bootstrap["github_activation"].(map[string]any)
	activeSubjects := stringSetFromList(activation["active_subject_ids"])
	expectedSubjects := map[string]map[string]bool{
		"plan":  stringSet("github-config-drift-plan", "github-config-protected-plan"),
		"apply": stringSet("github-config-protected-apply"),
	}
	valid := ok && identitiesOK && enabledOK && activationOK && declaration["pool_id"] == "github-config" &&
		declaration["issuer_uri"] == "https://token.actions.githubusercontent.com" &&
		declaration["repository_owner_id"] == "316676129" && declaration["repository_id"] == "1350986053" &&
		declaration["immutable_repository"] == "mindclade@316676129/github-config@1350986053" &&
		declaration["repository_full_name"] == "mindclade/github-config" && declaration["branch_ref"] == "refs/heads/main" &&
		sameStringSet(stringSetFromMap(identities), stringSet("plan", "apply"))
	poolAddress := indexedResourceAddress("module.github_federation.google_iam_workload_identity_pool.github_config", "pool")
	pool := resourceAfter(resources, poolAddress)
	if enabled && (pool == nil || pool["project"] != projects["identity"] || pool["workload_identity_pool_id"] != declaration["pool_id"]) {
		*violations = append(*violations, poolAddress+" must exactly equal the compiled identity project and github-config pool ID")
	}
	for _, identityKey := range []string{"plan", "apply"} {
		identity, _ := identities[identityKey].(map[string]any)
		accountID := "github-config-" + identityKey
		subjects, _ := identity["subjects"].([]any)
		seenSubjects := map[string]bool{}
		for _, raw := range subjects {
			subject, _ := raw.(map[string]any)
			seenSubjects[stringValue(subject["id"])] = true
			valid = valid && subject["audience"] == "sts.googleapis.com"
		}
		valid = valid && identity["provider_id"] == accountID && identity["service_account_id"] == accountID &&
			sameStringSet(seenSubjects, expectedSubjects[identityKey])
		activeIdentitySubjects := map[string]bool{}
		for subject := range expectedSubjects[identityKey] {
			if activeSubjects[subject] {
				activeIdentitySubjects[subject] = true
			}
		}
		identityEnabled := enabled && len(activeIdentitySubjects) > 0
		address := indexedResourceAddress("module.github_federation.google_service_account.github_config", identityKey)
		service := resourceAfter(resources, address)
		if service == nil || service["project"] != projects["identity"] || service["account_id"] != accountID {
			*violations = append(*violations, address+" must preserve the exact roleless github-config account")
		}
		providerAddress := indexedResourceAddress("module.github_federation.google_iam_workload_identity_pool_provider.github_config", identityKey)
		bindingAddress := indexedResourceAddress("module.github_federation.google_service_account_iam_member.github_config", identityKey)
		if identityEnabled {
			provider := resourceAfter(resources, providerAddress)
			if provider == nil || provider["project"] != projects["identity"] || provider["workload_identity_pool_id"] != declaration["pool_id"] || provider["workload_identity_pool_provider_id"] != identity["provider_id"] ||
				provider["attribute_condition"] != githubConfigProviderConditionForSubjects(identityKey, activeSubjects) {
				*violations = append(*violations, providerAddress+" must exactly equal its compiled identity project, pool, and provider ID")
			}
			validateCompiledFederationBinding(bindingAddress, resourceAfter(resources, bindingAddress), pool, accountID, projects["identity"], "github_config_identity", identityKey, violations)
		} else if resourceAfter(resources, providerAddress) != nil || resourceAfter(resources, bindingAddress) != nil {
			*violations = append(*violations, providerAddress+" and its binding must be absent while all identity subjects are lifecycle-gated")
		}
	}
	if !enabled {
		for _, resource := range resources {
			base := resourceAddressBase(resource.Address)
			if base == "module.github_federation.google_iam_workload_identity_pool.github_config" ||
				base == "module.github_federation.google_iam_workload_identity_pool_provider.github_config" ||
				base == "module.github_federation.google_service_account_iam_member.github_config" {
				*violations = append(*violations, resource.Address+" must be absent while github-config federation activation is BLOCKED")
			}
		}
	}
	if !valid {
		*violations = append(*violations, "compiled github-config federation must retain its exact immutable repository and three lifecycle-controlled catalog subjects")
	}
}

func validateCompiledBootstrapProvider(address string, provider, github map[string]any, project, poolID, providerID, audience, environment, workflowRef, instance string, privateQualified bool, violations *[]string) {
	expectedMapping := map[string]string{
		"google.subject":                  githubRepositorySubjectMapping("bootstrap-" + instance),
		"attribute.repository_id":         "assertion.repository_id",
		"attribute.repository_owner_id":   "assertion.repository_owner_id",
		"attribute.ref":                   "assertion.ref",
		"attribute.workflow_ref":          "assertion.workflow_ref",
		"attribute.workflow_sha":          "assertion.workflow_sha",
		"attribute.environment":           "assertion.environment",
		"attribute.event_name":            "assertion.event_name",
		"attribute.repository_visibility": "assertion.repository_visibility",
		"attribute.runner_environment":    "assertion.runner_environment",
	}
	oidc, _ := singleObject(provider["oidc"])
	if provider == nil || provider["project"] != project || provider["workload_identity_pool_id"] != poolID ||
		provider["workload_identity_pool_provider_id"] != providerID || !exactStringMap(provider["attribute_mapping"], expectedMapping) ||
		provider["disabled"] != !privateQualified ||
		provider["attribute_condition"] != bootstrapProviderCondition(github, environment, workflowRef) ||
		oidc["issuer_uri"] != github["issuer_uri"] || !exactStringSet(oidc["allowed_audiences"], []string{audience}) {
		*violations = append(*violations, address+" must exactly bind its immutable custom repository subject, source SHA, workflow, protected environment, runner class, and approved audience")
	}
}

func bootstrapProviderCondition(github map[string]any, environment, workflowRef string) string {
	repository := stringValue(github["repository_full_name"])
	repositoryParts := strings.Split(repository, "/")
	immutableRepository := ""
	if len(repositoryParts) == 2 {
		immutableRepository = fmt.Sprintf("%s@%s/%s@%s", repositoryParts[0], stringValue(github["repository_owner_id"]), repositoryParts[1], stringValue(github["repository_id"]))
	}
	return strings.Join([]string{
		fmt.Sprintf("assertion.sub == 'repo:%s:environment:%s:workflow_ref:%s:workflow_sha:' + assertion.workflow_sha", immutableRepository, environment, workflowRef),
		fmt.Sprintf("assertion.repository == '%s'", repository),
		"assertion.repository_owner == 'mindclade'",
		fmt.Sprintf("assertion.repository_id == '%s'", stringValue(github["repository_id"])),
		fmt.Sprintf("assertion.repository_owner_id == '%s'", stringValue(github["repository_owner_id"])),
		"assertion.repository_visibility == 'private'",
		fmt.Sprintf("assertion.ref == '%s'", stringValue(github["branch_ref"])),
		fmt.Sprintf("assertion.workflow_ref == '%s'", workflowRef),
		"assertion.workflow_sha == assertion.sha",
		"assertion.event_name == 'workflow_dispatch'",
		fmt.Sprintf("assertion.environment == '%s'", environment),
		"assertion.runner_environment == 'self-hosted'",
	}, " && ")
}

func validateCompiledInfrastructureFederationGraph(resources []resourceChange, bootstrap map[string]any, projects map[string]string, violations *[]string) {
	const prefix = "module.github_federation."
	declaration, declarationOK := bootstrap["github_infrastructure"].(map[string]any)
	identities, identitiesOK := declaration["identities"].(map[string]any)
	expectedIdentities := stringSet(
		"development-plan", "development-apply", "staging-plan", "staging-apply",
		"production-plan", "production-apply", "restricted-plan", "restricted-apply",
	)
	if !declarationOK || !identitiesOK || !sameStringSet(stringSetFromMap(identities), expectedIdentities) {
		*violations = append(*violations, "root-trust variables must declare exactly the eight infrastructure-live federation identities")
		return
	}
	drift, driftOK := declaration["drift"].(map[string]any)
	driftEnabled, driftEnabledOK := drift["activation_enabled"].(bool)
	driftValid := driftOK && driftEnabledOK && drift["subject_id"] == "infrastructure-drift-plan" &&
		drift["provider_id"] == "infrastructure-plan" && drift["service_account_id"] == "infrastructure-plan" &&
		drift["workflow_ref"] == "mindclade/infrastructure-live/.github/workflows/drift-detection.yml@refs/heads/main" &&
		drift["environment"] == "trusted-build" && drift["audience"] == "sts.googleapis.com"
	driftServiceAddress := indexedResourceAddress(prefix+"google_service_account.infrastructure_drift", "drift")
	driftService := resourceAfter(resources, driftServiceAddress)
	if !driftValid || driftService == nil || driftService["project"] != projects["identity"] || driftService["account_id"] != "infrastructure-plan" {
		*violations = append(*violations, driftServiceAddress+" must preserve the exact roleless lifecycle-controlled infrastructure drift identity")
	}
	poolAddress := indexedResourceAddress(prefix+"google_iam_workload_identity_pool.infrastructure_live", "pool")
	pool := resourceAfter(resources, poolAddress)
	if pool == nil || pool["project"] != projects["identity"] || pool["workload_identity_pool_id"] != declaration["pool_id"] {
		*violations = append(*violations, poolAddress+" must exactly equal the compiled identity project and infrastructure-live pool ID")
	}
	if driftEnabled {
		providerAddress := indexedResourceAddress(prefix+"google_iam_workload_identity_pool_provider.infrastructure_drift", "drift")
		bindingAddress := indexedResourceAddress(prefix+"google_service_account_iam_member.infrastructure_drift", "drift")
		provider := resourceAfter(resources, providerAddress)
		if provider == nil || provider["project"] != projects["identity"] || provider["workload_identity_pool_id"] != declaration["pool_id"] || provider["workload_identity_pool_provider_id"] != drift["provider_id"] {
			*violations = append(*violations, providerAddress+" must exactly equal its compiled identity project, pool, and provider ID")
		}
		validateCompiledFederationBinding(bindingAddress, resourceAfter(resources, bindingAddress), pool, stringValue(drift["service_account_id"]), projects["identity"], "infrastructure_identity", "drift-plan", violations)
	} else {
		for _, resource := range resources {
			base := resourceAddressBase(resource.Address)
			if base == prefix+"google_iam_workload_identity_pool_provider.infrastructure_drift" ||
				base == prefix+"google_service_account_iam_member.infrastructure_drift" {
				*violations = append(*violations, resource.Address+" must be absent while infrastructure drift federation activation is BLOCKED")
			}
		}
	}
	expectedMapping := map[string]string{
		"attribute.repository_id":       "assertion.repository_id",
		"attribute.repository_owner_id": "assertion.repository_owner_id",
		"attribute.workflow_ref":        "assertion.workflow_ref",
		"attribute.workflow_sha":        "assertion.workflow_sha",
		"attribute.environment":         "assertion.environment",
	}
	seenAudiences := map[string]bool{}
	for identityKey := range expectedIdentities {
		identity, _ := identities[identityKey].(map[string]any)
		providerAddress := indexedResourceAddress(prefix+"google_iam_workload_identity_pool_provider.infrastructure_live", identityKey)
		serviceAddress := indexedResourceAddress(prefix+"google_service_account.infrastructure_live", identityKey)
		bindingAddress := indexedResourceAddress(prefix+"google_service_account_iam_member.infrastructure_live", identityKey)
		provider := resourceAfter(resources, providerAddress)
		service := resourceAfter(resources, serviceAddress)
		binding := resourceAfter(resources, bindingAddress)
		accountID := stringValue(identity["service_account_id"])
		audience := stringValue(identity["audience"])
		providerID := stringValue(identity["provider_id"])
		environment := stringValue(identity["environment"])
		mapping := map[string]string{}
		for key, value := range expectedMapping {
			mapping[key] = value
		}
		mapping["google.subject"] = githubRepositorySubjectMapping("infrastructure-live-" + identityKey)
		mapping["attribute.infrastructure_identity"] = "'" + identityKey + "'"
		oidc, _ := singleObject(provider["oidc"])
		expectedCondition := infrastructureProviderCondition(declaration, environment)
		if provider == nil || provider["project"] != projects["identity"] || provider["workload_identity_pool_id"] != declaration["pool_id"] ||
			provider["workload_identity_pool_provider_id"] != providerID || !exactStringMap(provider["attribute_mapping"], mapping) ||
			provider["attribute_condition"] != expectedCondition || oidc["issuer_uri"] != declaration["issuer_uri"] ||
			!exactStringSet(oidc["allowed_audiences"], []string{audience}) {
			*violations = append(*violations, providerAddress+" must exactly bind its immutable repository subject, source SHA, environment, provider, and singleton audience")
		}
		if service == nil || service["project"] != projects["identity"] || service["account_id"] != accountID {
			*violations = append(*violations, serviceAddress+" must create only its compiled roleless identity-project service account")
		}
		validateCompiledFederationBinding(bindingAddress, binding, pool, accountID, projects["identity"], "infrastructure_identity", identityKey, violations)
		if audience == "" || seenAudiences[audience] {
			*violations = append(*violations, providerAddress+" must use one unique nonempty infrastructure-live audience")
		}
		seenAudiences[audience] = true
	}
}

func infrastructureProviderCondition(declaration map[string]any, environment string) string {
	immutableRepository := stringValue(declaration["immutable_repository"])
	workflowRef := stringValue(declaration["workflow_ref"])
	return strings.Join([]string{
		fmt.Sprintf("assertion.sub == 'repo:%s:environment:%s:workflow_ref:%s:workflow_sha:' + assertion.workflow_sha", immutableRepository, environment, workflowRef),
		fmt.Sprintf("assertion.repository == '%s'", stringValue(declaration["repository_full_name"])),
		"assertion.repository_owner == 'mindclade'",
		fmt.Sprintf("assertion.repository_owner_id == '%s'", stringValue(declaration["repository_owner_id"])),
		fmt.Sprintf("assertion.repository_id == '%s'", stringValue(declaration["repository_id"])),
		"assertion.repository_visibility == 'public'",
		fmt.Sprintf("assertion.ref == '%s'", stringValue(declaration["branch_ref"])),
		fmt.Sprintf("assertion.workflow_ref == '%s'", workflowRef),
		"assertion.workflow_sha == assertion.sha",
		"assertion.event_name == 'workflow_dispatch'",
		fmt.Sprintf("assertion.environment == '%s'", environment),
		"assertion.runner_environment == 'github-hosted'",
	}, " && ")
}

func stringSetFromMap(values map[string]any) map[string]bool {
	result := map[string]bool{}
	for key := range values {
		result[key] = true
	}
	return result
}

func stringSetFromList(value any) map[string]bool {
	result := map[string]bool{}
	items, _ := value.([]any)
	for _, item := range items {
		text, _ := item.(string)
		if text != "" {
			result[text] = true
		}
	}
	return result
}

func validateCompiledCIEvidenceGraph(resources []resourceChange, bootstrap map[string]any, projects map[string]string, violations *[]string) {
	declaration, declarationOK := bootstrap["github_ci_evidence"].(map[string]any)
	enabled, enabledOK := declaration["activation_enabled"].(bool)
	const prefix = "module.github_federation."
	ciEvidenceBase := func(resource resourceChange) bool {
		base := resourceAddressBase(resource.Address)
		return base == prefix+"google_iam_workload_identity_pool.ci_evidence" ||
			base == prefix+"google_iam_workload_identity_pool_provider.ci_evidence" ||
			base == prefix+"google_service_account.ci_evidence" ||
			base == prefix+"google_service_account_iam_member.ci_evidence"
	}
	if !declarationOK || !enabledOK {
		*violations = append(*violations, "root-trust variables must declare the lifecycle-controlled CI-evidence federation")
		return
	}
	if !enabled {
		for _, resource := range resources {
			base := resourceAddressBase(resource.Address)
			if ciEvidenceBase(resource) && base != prefix+"google_service_account.ci_evidence" {
				*violations = append(*violations, resource.Address+" must be absent while CI-evidence federation activation is disabled")
			}
		}
		for _, role := range []string{"writer", "verifier"} {
			roleDeclaration, _ := declaration[role].(map[string]any)
			address := indexedResourceAddress(prefix+"google_service_account.ci_evidence", role)
			service := resourceAfter(resources, address)
			if service == nil || service["project"] != projects["identity"] || service["account_id"] != roleDeclaration["service_account_id"] {
				*violations = append(*violations, address+" must preserve the exact roleless source-stub account while CI-evidence federation is disabled")
			}
		}
		return
	}

	poolAddress := indexedResourceAddress(prefix+"google_iam_workload_identity_pool.ci_evidence", "archive")
	pool := resourceAfter(resources, poolAddress)
	if pool == nil || pool["project"] != projects["identity"] || pool["workload_identity_pool_id"] != declaration["pool_id"] {
		*violations = append(*violations, poolAddress+" must exactly equal the compiled identity project and dedicated pool ID")
	}
	issuer, _ := bootstrap["github"].(map[string]any)
	for _, role := range []string{"writer", "verifier"} {
		roleDeclaration, _ := declaration[role].(map[string]any)
		providerAddress := indexedResourceAddress(prefix+"google_iam_workload_identity_pool_provider.ci_evidence", role)
		serviceAddress := indexedResourceAddress(prefix+"google_service_account.ci_evidence", role)
		bindingAddress := indexedResourceAddress(prefix+"google_service_account_iam_member.ci_evidence", role)
		provider := resourceAfter(resources, providerAddress)
		service := resourceAfter(resources, serviceAddress)
		binding := resourceAfter(resources, bindingAddress)
		accountID := stringValue(roleDeclaration["service_account_id"])
		if provider == nil || provider["project"] != projects["identity"] || provider["workload_identity_pool_id"] != declaration["pool_id"] ||
			provider["workload_identity_pool_provider_id"] != roleDeclaration["provider_id"] {
			*violations = append(*violations, providerAddress+" must exactly equal its compiled identity project, pool, and provider ID")
		} else {
			oidc, _ := singleObject(provider["oidc"])
			condition := stringValue(provider["attribute_condition"])
			expectedWorkflow := stringValue(roleDeclaration["workflow_sha"])
			if role == "writer" {
				expectedWorkflow = stringValue(roleDeclaration["job_workflow_ref"])
			}
			if oidc["issuer_uri"] != issuer["issuer_uri"] || !plannedUnset(oidc["allowed_audiences"]) ||
				!strings.Contains(condition, "'"+expectedWorkflow+"'") {
				*violations = append(*violations, providerAddress+" must use its compiled issuer, Google's canonical provider audience, and immutable workflow binding")
			}
		}
		if service == nil || service["project"] != projects["identity"] || service["account_id"] != accountID {
			*violations = append(*violations, serviceAddress+" must create only its compiled keyless identity-project service account")
		}
		validateCompiledFederationBinding(bindingAddress, binding, pool, accountID, projects["identity"], "evidence_role", role, violations)
	}
}

func serviceAccountPrincipal(accountID, projectID string) string {
	if accountID == "" || projectID == "" {
		return ""
	}
	return "serviceAccount:" + accountID + "@" + projectID + ".iam.gserviceaccount.com"
}

func validateCompiledSingleFederation(resources []resourceChange, name string, declaration map[string]any, identityProject, serviceProject string, claims map[string]string, attribute, attributeValue string, violations *[]string) {
	poolAddress := "module." + name + "_federation.google_iam_workload_identity_pool." + name
	providerAddress := "module." + name + "_federation.google_iam_workload_identity_pool_provider." + name
	serviceAddress := "module." + name + "_federation.google_service_account." + name
	bindingAddress := "module." + name + "_federation.google_service_account_iam_member." + name
	pool := resourceAfter(resources, poolAddress)
	provider := resourceAfter(resources, providerAddress)
	service := resourceAfter(resources, serviceAddress)
	binding := resourceAfter(resources, bindingAddress)
	poolID := stringValue(declaration["pool_id"])
	accountID := stringValue(declaration["service_account_id"])
	if pool == nil || pool["project"] != identityProject || pool["workload_identity_pool_id"] != poolID {
		*violations = append(*violations, poolAddress+" must exactly equal its compiled identity project and pool ID")
	}
	if service == nil || service["project"] != serviceProject || service["account_id"] != accountID {
		*violations = append(*violations, serviceAddress+" must exactly equal its compiled service-account project and ID")
	}
	validateCompiledWorkloadProvider(providerAddress, provider, identityProject, poolID, stringValue(declaration["provider_id"]),
		stringValue(declaration["issuer_uri"]), stringValue(declaration["audience"]), claims, violations)
	validateCompiledFederationBinding(bindingAddress, binding, pool, accountID, serviceProject, attribute, attributeValue, violations)
}

func validateCompiledWorkloadProvider(address string, after map[string]any, project, poolID, providerID, issuer, audience string, claims map[string]string, violations *[]string) {
	oidc, _ := singleObject(after["oidc"])
	actualClaims, claimOK := parseExactClaimConjunction(stringValue(after["attribute_condition"]))
	if after == nil || after["project"] != project || after["workload_identity_pool_id"] != poolID ||
		after["workload_identity_pool_provider_id"] != providerID || oidc["issuer_uri"] != issuer ||
		!exactStringSet(oidc["allowed_audiences"], []string{audience}) || !claimOK || !sameStringMap(actualClaims, claims) {
		*violations = append(*violations, address+" must exactly equal all compiled issuer, audience, pool, provider, subject, and immutable claim values")
	}
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func validateCompiledFederationBinding(address string, after, pool map[string]any, accountID, serviceProject, attribute, claim string, violations *[]string) {
	expectedServiceAccount := fmt.Sprintf("projects/%s/serviceAccounts/%s@%s.iam.gserviceaccount.com", serviceProject, accountID, serviceProject)
	member, _ := after["member"].(string)
	poolName, _ := pool["name"].(string)
	expectedMember := "principalSet://iam.googleapis.com/" + poolName + "/attribute." + attribute + "/" + claim
	memberUnknown := member == "" // The resource-level pass separately restricts the computed leaf.
	if after == nil || after["service_account_id"] != expectedServiceAccount || (!memberUnknown && (poolName == "" || member != expectedMember)) {
		*violations = append(*violations, address+" must exactly bind its compiled service account to its matching planned pool and claim literal")
	}
}

func validateCompiledPrincipalGraph(resources []resourceChange, bootstrap map[string]any, signing *signingContract, principals bootstrapPrincipals, violations *[]string) {
	expectedRootAdministrator, _ := bootstrap["root_administrator_principal"].(string)
	expectedRecoveryAdministrator, _ := bootstrap["recovery_administrator_principal"].(string)
	actualRecoveryAdministrators := map[string]bool{}
	rootOrganizationBindings := map[string]string{}
	for _, resource := range resources {
		after, _ := resource.Change.After.(map[string]any)
		member, _ := after["member"].(string)
		switch resourceAddressBase(resource.Address) {
		case "google_organization_iam_member.apply_iam",
			"google_organization_iam_member.apply_logging_config_writer",
			"google_organization_iam_member.apply_organization_role_admin",
			"google_organization_iam_member.apply_workforce_admin":
			rootOrganizationBindings[resourceAddressBase(resource.Address)] = member
		}
		if resourceAddressBase(resource.Address) == "google_project_iam_member.recovery_administration" {
			actualRecoveryAdministrators[member] = true
		}
		switch {
		case bootstrapPlanPrincipalPattern.MatchString(member) && member != principals.plan:
			*violations = append(*violations, resource.Address+" substitutes a same-shaped bootstrap-plan identity outside the compiled project")
		case bootstrapApplyPrincipalPattern.MatchString(member) && member != principals.apply:
			*violations = append(*violations, resource.Address+" substitutes a same-shaped bootstrap-apply identity outside the compiled project")
		case bootstrapRecoveryPrincipalPattern.MatchString(member) && member != principals.recovery:
			*violations = append(*violations, resource.Address+" substitutes a same-shaped bootstrap-recovery identity outside the compiled project")
		}
	}
	expectedRootOrganizationAddresses := []string{
		"google_organization_iam_member.apply_iam",
		"google_organization_iam_member.apply_logging_config_writer",
		"google_organization_iam_member.apply_organization_role_admin",
		"google_organization_iam_member.apply_workforce_admin",
	}
	rootOrganizationBindingsValid := groupEmailPrincipalPattern.MatchString(expectedRootAdministrator) && len(rootOrganizationBindings) == len(expectedRootOrganizationAddresses)
	for _, address := range expectedRootOrganizationAddresses {
		rootOrganizationBindingsValid = rootOrganizationBindingsValid && rootOrganizationBindings[address] == expectedRootAdministrator
	}
	if !rootOrganizationBindingsValid {
		*violations = append(*violations, "organization administration bindings must exactly equal the compiled independent root-administrator group and never the bootstrap-apply identity")
	}
	if !groupEmailPrincipalPattern.MatchString(expectedRecoveryAdministrator) ||
		!sameStringSet(actualRecoveryAdministrators, stringSet(expectedRecoveryAdministrator)) {
		*violations = append(*violations, "recovery-administration bindings must exactly equal the single compiled recovery-administrator group")
	}

	audit, _ := bootstrap["audit"].(map[string]any)
	expectedReaders := stringSetFromValue(audit["reader_principals"])
	expectedReaders[principals.recovery] = true
	actualReaders := map[string]bool{}
	actualAdmins := map[string]bool{}
	for _, resource := range resources {
		after, _ := resource.Change.After.(map[string]any)
		base := resourceAddressBase(resource.Address)
		member, _ := after["member"].(string)
		if base == "module.audit_root.google_project_iam_member.reader" {
			actualReaders[member] = true
		}
		if base == "module.audit_root.google_project_iam_member.administrator" {
			actualAdmins[member] = true
		}
	}
	if !sameStringSet(actualReaders, expectedReaders) {
		*violations = append(*violations, "audit reader bindings must exactly equal the compiled human reader groups plus recovery identity")
	}
	expectedAdmins := stringSetFromValue(audit["administrator_principals"])
	expectedAdmins[principals.apply] = true
	if !sameStringSet(actualAdmins, expectedAdmins) {
		*violations = append(*violations, "audit administrator bindings must exactly equal the compiled administrators plus apply identity")
	}

	signingObject, _ := bootstrap["signing"].(map[string]any)
	validateCompiledNixCacheSigningGraph(resources, bootstrap, signingObject, violations)
	expectedSigningAdmins := stringSetFromValue(signingObject["administrators"])
	actualSigningAdmins := map[string]bool{}
	actualSigners := map[string]map[string]bool{}
	for _, resource := range resources {
		after, _ := resource.Change.After.(map[string]any)
		base := resourceAddressBase(resource.Address)
		member, _ := after["member"].(string)
		if base == "module.signing_root.google_kms_key_ring_iam_member.administrator" {
			actualSigningAdmins[member] = true
		}
		if base == "module.signing_root.google_kms_crypto_key_iam_member.signer" {
			instance, _, _ := terraformAddressStringIndex(resource.Address, base)
			parts := strings.SplitN(instance, ":", 2)
			if len(parts) == 2 {
				if actualSigners[parts[0]] == nil {
					actualSigners[parts[0]] = map[string]bool{}
				}
				actualSigners[parts[0]][member] = true
			}
		}
	}
	if !sameStringSet(actualSigningAdmins, expectedSigningAdmins) {
		*violations = append(*violations, "signing key-ring administrators must exactly equal the compiled administrators plus apply identity")
	}
	keys, _ := signingObject["keys"].(map[string]any)
	for _, keyName := range signingKeyNames {
		key, _ := keys[keyName].(map[string]any)
		expected := stringSetFromValue(key["signer_principals"])
		switch keyName {
		case "audit-anchor", "bootstrap-handoff":
			expected[principals.buildkite] = true
		case "recovery-evidence":
			expected[principals.recovery] = true
		case "connected-observation-evidence", "infrastructure-export", "supply-chain-provenance":
			// The source declares its future signers, while this key stays
			// IAM-disabled until connected infrastructure qualification.
			expected = map[string]bool{}
		}
		if !sameStringSet(actualSigners[keyName], expected) {
			*violations = append(*violations, "signer bindings for "+keyName+" must exactly equal the compiled signers plus its approved pipeline/recovery identity")
		}
	}
	_ = signing // The parsed signing contract independently validates version declarations.

	validateCompiledPAMPrincipals(resources, bootstrap, violations)
}

func validateCompiledNixCacheSigningGraph(resources []resourceChange, bootstrap, signing map[string]any, violations *[]string) {
	nixCache, ok := signing["nix_cache"].(map[string]any)
	projects, projectsOK := bootstrap["projects"].(map[string]any)
	signingProject, signingProjectOK := projects["signing"].(map[string]any)
	projectID := stringValue(signingProject["id"])
	activated, activationOK := nixCache["activation_enabled"].(bool)
	if !ok || !projectsOK || !signingProjectOK || !activationOK || projectID == "" {
		*violations = append(*violations, "compiled Nix cache signing root must bind one explicit signing project and activation state")
		return
	}
	validContract := nixCache["secret_id"] == "nix-cache-signing-key" && nixCache["algorithm"] == "ED25519" &&
		nixCache["secret_storage"] == "SECRET_MANAGER_WRITE_ONLY" &&
		exactStringSet(nixCache["required_reviewer_gates"], []string{"security", "platform"})
	switch stringValue(nixCache["state"]) {
	case "DISABLED":
		validContract = validContract && !activated && plannedUnset(nixCache["secret_version_write_only"]) &&
			exactStringSet(nixCache["public_keys"], []string{}) && plannedUnset(nixCache["public_key_digest"]) &&
			exactStringSet(nixCache["accessor_principals"], []string{}) && plannedUnset(nixCache["reviewer_evidence_digest"]) &&
			exactStringSet(nixCache["blockers"], []string{"cache-public-key-not-committed", "secret-version-not-created", "independent-review-not-evidenced"})
	case "ACTIVATED":
		version, versionOK := nixCache["secret_version_write_only"].(float64)
		publicKeys, publicKeysOK := nixCache["public_keys"].([]any)
		canonicalPublicKeys := make([]string, 0, len(publicKeys))
		publicKeyPattern := regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*-v[1-9][0-9]*:[A-Za-z0-9+/]{43}=$`)
		for _, value := range publicKeys {
			publicKey, publicKeyOK := value.(string)
			if !publicKeyOK || !publicKeyPattern.MatchString(publicKey) {
				publicKeysOK = false
				continue
			}
			canonicalPublicKeys = append(canonicalPublicKeys, publicKey)
		}
		encodedPublicKeys, _ := json.Marshal(canonicalPublicKeys)
		expectedDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(encodedPublicKeys))
		accessors := stringSetFromValue(nixCache["accessor_principals"])
		validAccessors := len(accessors) > 0
		for accessor := range accessors {
			validAccessors = validAccessors && serviceAccountIAMPattern.MatchString(accessor)
		}
		reviewerDigest := stringValue(nixCache["reviewer_evidence_digest"])
		validContract = validContract && activated && versionOK && version >= 1 && math.Trunc(version) == version &&
			publicKeysOK && len(canonicalPublicKeys) > 0 && nixCache["public_key_digest"] == expectedDigest && validAccessors &&
			regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(reviewerDigest) && reviewerDigest != strings.Repeat("0", 64) &&
			exactStringSet(nixCache["blockers"], []string{})
	default:
		validContract = false
	}
	if !validContract {
		*violations = append(*violations, "compiled Nix cache signing root must preserve its exact fail-closed or reviewer-qualified write-only contract")
	}

	const secretAddress = "module.signing_root.google_secret_manager_secret.nix_cache_signing"
	secret := resourceAfter(resources, secretAddress)
	replication := firstObject(secret["replication"])
	userManaged := firstObject(replication["user_managed"])
	replicas, replicasOK := userManaged["replicas"].([]any)
	replica := map[string]any{}
	if replicasOK && len(replicas) == 1 {
		replica, _ = replicas[0].(map[string]any)
	}
	if secret == nil || secret["project"] != projectID || secret["secret_id"] != nixCache["secret_id"] ||
		secret["deletion_protection"] != true || !replicasOK || len(replicas) != 1 || replica["location"] != signing["location"] {
		*violations = append(*violations, secretAddress+" must preserve the deletion-protected, region-bound Nix signing secret container in the compiled signing project")
	}

	versionAddress := indexedResourceAddress("module.signing_root.google_secret_manager_secret_version.nix_cache_signing", "active")
	version := resourceAfter(resources, versionAddress)
	if activated {
		if version == nil || version["deletion_policy"] != "DISABLE" || version["secret_data_wo_version"] != nixCache["secret_version_write_only"] ||
			!plannedUnset(version["secret_data"]) || !plannedUnset(version["secret_data_wo"]) {
			*violations = append(*violations, versionAddress+" must use only the compiled write-only version and retain disabled versions without exposing secret bytes")
		}
	} else if version != nil {
		*violations = append(*violations, versionAddress+" must be absent while Nix cache signing activation is disabled")
	}

	expectedAccessors := stringSetFromValue(nixCache["accessor_principals"])
	actualAccessors := map[string]bool{}
	for _, resource := range resources {
		const base = "module.signing_root.google_secret_manager_secret_iam_member.nix_cache_accessor"
		if resourceAddressBase(resource.Address) != base {
			continue
		}
		principal, indexed, valid := terraformAddressStringIndex(resource.Address, base)
		after, _ := resource.Change.After.(map[string]any)
		if !indexed || !valid || after["member"] != principal || after["project"] != projectID ||
			after["secret_id"] != nixCache["secret_id"] || after["role"] != "roles/secretmanager.secretAccessor" {
			*violations = append(*violations, resource.Address+" must bind only its compiled Nix cache signer to the exact signing secret")
			continue
		}
		actualAccessors[principal] = true
	}
	if !activated {
		expectedAccessors = map[string]bool{}
	}
	if !sameStringSet(actualAccessors, expectedAccessors) {
		*violations = append(*violations, "Nix cache signing accessors must exactly equal the activation-qualified compiled service accounts")
	}
}

func stringSetFromValue(value any) map[string]bool {
	result := map[string]bool{}
	switch values := value.(type) {
	case []any:
		for _, raw := range values {
			if entry, ok := raw.(string); ok && entry != "" {
				result[entry] = true
			}
		}
	case []string:
		for _, entry := range values {
			if entry != "" {
				result[entry] = true
			}
		}
	}
	return result
}

func validateCompiledPAMPrincipals(resources []resourceChange, bootstrap map[string]any, violations *[]string) {
	breakGlass, _ := bootstrap["break_glass"].(map[string]any)
	expectedRequesters := stringSetFromValue(breakGlass["requester_principals"])
	expectedApprovers := stringSetFromValue(breakGlass["approver_principals"])
	expectedRecipients := stringSetFromValue(breakGlass["notification_recipients"])
	for _, resource := range resources {
		if resourceAddressBase(resource.Address) != "module.break_glass.google_privileged_access_manager_entitlement.break_glass" {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		eligible, _ := singleObject(after["eligible_users"])
		requesters, _ := explicitUserSet(eligible["principals"])
		workflow, _ := singleObject(after["approval_workflow"])
		manual, _ := singleObject(workflow["manual_approvals"])
		steps, _ := manual["steps"].([]any)
		approvers := map[string]bool{}
		for _, rawStep := range steps {
			step, _ := rawStep.(map[string]any)
			approverObject, _ := singleObject(step["approvers"])
			principals, _ := explicitUserSet(approverObject["principals"])
			for principal := range principals {
				approvers[principal] = true
			}
		}
		notifications, _ := singleObject(after["additional_notification_targets"])
		adminRecipients := stringSetFromValue(notifications["admin_email_recipients"])
		requesterRecipients := stringSetFromValue(notifications["requester_email_recipients"])
		if !sameStringSet(requesters, expectedRequesters) || !sameStringSet(approvers, expectedApprovers) ||
			!sameStringSet(adminRecipients, expectedRecipients) || !sameStringSet(requesterRecipients, expectedRecipients) {
			*violations = append(*violations, resource.Address+" requesters, approvers, and notification recipients must exactly equal the compiled break-glass principals")
		}
	}
}

func validatePlannedProjectGraph(resources []resourceChange, violations *[]string) {
	projectAddresses := map[string]string{
		"google_project.identity":                    "identity",
		`google_project.state["root_state"]`:         "root_state",
		`google_project.state["recovery"]`:           "recovery",
		"module.audit_root.google_project.audit":     "audit",
		"module.signing_root.google_project.signing": "signing",
	}
	projects := map[string]string{}
	seenIDs := map[string]string{}
	for _, resource := range resources {
		logical, ok := projectAddresses[resource.Address]
		if !ok || resource.Type != "google_project" {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		projectID, _ := after["project_id"].(string)
		projects[logical] = projectID
		if prior := seenIDs[projectID]; projectID != "" && prior != "" {
			*violations = append(*violations, fmt.Sprintf("%s and %s must use distinct compiler-declared project IDs", prior, resource.Address))
		}
		seenIDs[projectID] = resource.Address
	}

	for _, resource := range resources {
		after, _ := resource.Change.After.(map[string]any)
		switch resource.Type {
		case "google_project_service":
			validateProjectServiceProject(resource, after, projects, violations)
		case "google_project_iam_member":
			validateProjectIAMProject(resource, after, projects, violations)
		case "google_project_iam_custom_role":
			if resource.Address == "module.signing_root.google_project_iam_custom_role.recovery_metadata" {
				requirePlannedProject(resource, after, "project", "signing", projects, violations)
			} else if resourceAddressBase(resource.Address) == "module.audit_root.google_project_iam_custom_role.plan_read" {
				instance, indexed, _ := terraformAddressStringIndex(resource.Address, resourceAddressBase(resource.Address))
				logical := map[string]string{"primary": "audit", "recovery": "recovery"}[instance]
				if indexed && logical != "" {
					requirePlannedProject(resource, after, "project", logical, projects, violations)
				}
			}
		case "google_kms_crypto_key_iam_member":
			if resource.Address == "module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata" {
				if resource.initialSigningCreateProof && exactInitialRecoveryMetadataEnvelope(resource, after) {
					roleProject, _, _ := splitCustomRole(stringValue(after["role"]))
					if projects["signing"] != "" && roleProject != projects["signing"] {
						*violations = append(*violations, resource.Address+" must target the planned signing project")
					}
					continue
				}
				cryptoKey, _ := after["crypto_key_id"].(string)
				parts := strings.Split(cryptoKey, "/")
				if projects["signing"] == "" || len(parts) != 8 || parts[1] != projects["signing"] {
					*violations = append(*violations, resource.Address+" must target the planned signing project")
				}
			}
		case "google_logging_project_bucket_config":
			validateAuditBucketProject(resource, after, projects, violations)
		case "google_logging_organization_sink":
			validateAuditSinkProject(resource, after, projects, violations)
		case "google_privileged_access_manager_entitlement":
			validatePAMProject(resource, after, projects, violations)
		case "google_iam_workload_identity_pool", "google_iam_workload_identity_pool_provider", "google_service_account", "google_service_account_iam_member":
			validateIdentityProject(resource, after, projects, violations)
		}
		validateStateBackendProject(resource, after, projects, violations)
		validateKMSProject(resource, after, projects, violations)
	}
}

func validateStateBackendProject(resource resourceChange, after map[string]any, projects map[string]string, violations *[]string) {
	var module, primaryLogical, replicaLogical string
	if strings.HasPrefix(resource.Address, "module.root_state.") {
		module, primaryLogical, replicaLogical = "module.root_state", "root_state", "recovery"
	} else if strings.HasPrefix(resource.Address, "module.recovery_state.") {
		module, primaryLogical, replicaLogical = "module.recovery_state", "recovery", "root_state"
	} else {
		return
	}
	logical := primaryLogical
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	instance, _, _ := terraformAddressStringIndex(resource.Address, base)
	if stateBackendReplicaScoped(base, instance) {
		logical = replicaLogical
	}
	if projects[logical] == "" {
		return
	}
	switch resource.Type {
	case "google_kms_key_ring", "google_storage_bucket", "google_storage_project_service_account", "google_storage_transfer_project_service_account", "google_project_iam_custom_role", "google_project_iam_member", "google_storage_transfer_job":
		if project, ok := after["project"].(string); ok {
			if project != projects[logical] || topLevelUnknown(resource.Change.AfterUnknown, "project") {
				*violations = append(*violations, resource.Address+" must target its planned state-backend project")
			}
		}
	case "google_kms_crypto_key":
		validateResourceProjectPath(resource, after, "key_ring", projects[logical], violations)
	case "google_kms_crypto_key_iam_member":
		validateResourceProjectPath(resource, after, "crypto_key_id", projects[logical], violations)
	case "google_storage_bucket_iam_member":
		role, _ := after["role"].(string)
		if strings.HasPrefix(role, "projects/") {
			roleProject, _, ok := splitCustomRole(role)
			expectedLogical := primaryLogical
			if base == module+".google_storage_bucket_iam_member.replication" && instance == "destination" {
				expectedLogical = replicaLogical
			}
			if !ok || roleProject != projects[expectedLogical] {
				*violations = append(*violations, resource.Address+" custom role must belong to its planned state project")
			}
		}
	}
}

func stateBackendReplicaScoped(base, instance string) bool {
	suffix := strings.TrimPrefix(base, "module.root_state.")
	suffix = strings.TrimPrefix(suffix, "module.recovery_state.")
	switch suffix {
	case "google_kms_key_ring.replica", "google_kms_crypto_key.replica", "google_kms_crypto_key_iam_member.replica_service_agent":
		return true
	case "google_project_iam_custom_role.replication":
		return instance == "destination_bucket"
	case "data.google_storage_project_service_account.replica":
		return true
	case "google_storage_bucket.state":
		return instance == "replica"
	case "google_storage_bucket_iam_member.backend_access":
		return strings.HasPrefix(instance, "replica-")
	}
	return false
}

func validateKMSProject(resource resourceChange, after map[string]any, projects map[string]string, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	instance, _, _ := terraformAddressStringIndex(resource.Address, base)
	logical := ""
	switch base {
	case "module.audit_root.google_kms_key_ring.audit", "module.audit_root.google_kms_crypto_key.audit", "module.audit_root.google_kms_crypto_key_iam_member.logging":
		logical = map[string]string{"primary": "audit", "recovery": "recovery"}[instance]
	case "module.signing_root.google_kms_key_ring.signing", "module.signing_root.google_kms_crypto_key.signing":
		logical = "signing"
	}
	if logical == "" || projects[logical] == "" {
		return
	}
	switch resource.Type {
	case "google_kms_key_ring":
		requirePlannedProject(resource, after, "project", logical, projects, violations)
	case "google_kms_crypto_key":
		validateResourceProjectPath(resource, after, "key_ring", projects[logical], violations)
	case "google_kms_crypto_key_iam_member":
		validateResourceProjectPath(resource, after, "crypto_key_id", projects[logical], violations)
	}
}

func validateResourceProjectPath(resource resourceChange, after map[string]any, field, expectedProject string, violations *[]string) {
	value, _ := after[field].(string)
	if value == "" && topLevelUnknown(resource.Change.AfterUnknown, field) {
		return
	}
	parts := strings.Split(value, "/")
	if len(parts) < 2 || parts[0] != "projects" || parts[1] != expectedProject {
		*violations = append(*violations, fmt.Sprintf("%s.%s must remain in its planned project", resource.Address, field))
	}
}

func validateIdentityProject(resource resourceChange, after map[string]any, projects map[string]string, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	switch resource.Type {
	case "google_iam_workload_identity_pool", "google_iam_workload_identity_pool_provider":
		if strings.HasPrefix(base, "module.github_federation.") || strings.HasPrefix(base, "module.buildkite_federation.") || strings.HasPrefix(base, "module.gitops_federation.") {
			logical := "identity"
			if base == "module.github_federation.google_iam_workload_identity_pool.github" ||
				base == "module.github_federation.google_iam_workload_identity_pool_provider.github" {
				instance, _, _ := terraformAddressStringIndex(resource.Address, base)
				if instance == "recovery" {
					logical = "recovery"
				}
			}
			requirePlannedProject(resource, after, "project", logical, projects, violations)
		}
	case "google_service_account":
		logical := ""
		switch base {
		case "module.github_federation.google_service_account.github":
			instance, _, _ := terraformAddressStringIndex(resource.Address, base)
			logical = map[string]string{"plan": "root_state", "apply": "root_state", "recovery": "recovery"}[instance]
		case "module.github_federation.google_service_account.ci_evidence":
			logical = "identity"
		case "module.github_federation.google_service_account.github_config":
			logical = "identity"
		case "module.github_federation.google_service_account.infrastructure_live":
			logical = "identity"
		case "module.github_federation.google_service_account.infrastructure_drift":
			logical = "identity"
		case "module.buildkite_federation.google_service_account.buildkite":
			logical = "root_state"
		case "module.gitops_federation.google_service_account.gitops":
			logical = "recovery"
		}
		if logical != "" {
			requirePlannedProject(resource, after, "project", logical, projects, violations)
		}
	case "google_service_account_iam_member":
		logical := ""
		switch base {
		case "module.github_federation.google_service_account_iam_member.github":
			instance, _, _ := terraformAddressStringIndex(resource.Address, base)
			logical = map[string]string{"plan": "root_state", "apply": "root_state", "recovery": "recovery"}[instance]
		case "module.github_federation.google_service_account_iam_member.ci_evidence":
			logical = "identity"
		case "module.github_federation.google_service_account_iam_member.github_config":
			logical = "identity"
		case "module.github_federation.google_service_account_iam_member.infrastructure_live":
			logical = "identity"
		case "module.github_federation.google_service_account_iam_member.infrastructure_drift":
			logical = "identity"
		case "module.buildkite_federation.google_service_account_iam_member.buildkite":
			logical = "root_state"
		case "module.gitops_federation.google_service_account_iam_member.gitops":
			logical = "recovery"
		}
		if logical == "" {
			return
		}
		serviceAccountID, _ := after["service_account_id"].(string)
		parts := strings.Split(serviceAccountID, "/")
		if projects[logical] == "" || len(parts) != 4 || parts[1] != projects[logical] {
			*violations = append(*violations, resource.Address+" must bind the service account in its planned project")
		}
	}
}

func requirePlannedProject(resource resourceChange, after map[string]any, field, logical string, projects map[string]string, violations *[]string) {
	expected := projects[logical]
	actual, _ := after[field].(string)
	if expected == "" || actual != expected || topLevelUnknown(resource.Change.AfterUnknown, field) {
		*violations = append(*violations, fmt.Sprintf("%s.%s must equal the planned %s project ID", resource.Address, field, logical))
	}
}

func validateProjectServiceProject(resource resourceChange, after map[string]any, projects map[string]string, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	switch base {
	case "google_project_service.identity":
		requirePlannedProject(resource, after, "project", "identity", projects, violations)
	case "google_project_service.state":
		parts := strings.SplitN(instance, ":", 2)
		if !indexed || len(parts) != 2 || (parts[0] != "root_state" && parts[0] != "recovery") {
			return
		}
		requirePlannedProject(resource, after, "project", parts[0], projects, violations)
	case "module.audit_root.google_project_service.required":
		requirePlannedProject(resource, after, "project", "audit", projects, violations)
	case "module.signing_root.google_project_service.required":
		requirePlannedProject(resource, after, "project", "signing", projects, violations)
	case "module.break_glass.google_project_service.pam":
		expected := map[string]bool{
			projects["identity"]:   true,
			projects["root_state"]: true,
			projects["recovery"]:   true,
			projects["signing"]:    true,
		}
		project, _ := after["project"].(string)
		if !indexed || !expected[instance] || project != instance || instance == "" {
			*violations = append(*violations, resource.Address+" must enable PAM only in one of the four planned entitlement target projects")
		}
	}
}

func validateProjectIAMProject(resource resourceChange, after map[string]any, projects map[string]string, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	switch base {
	case "google_project_iam_member.apply_administration", "google_project_iam_member.plan_read":
		parts := strings.SplitN(instance, ":", 2)
		if indexed && len(parts) == 2 {
			logical := map[string]string{"state": "root_state"}[parts[0]]
			if logical == "" {
				logical = parts[0]
			}
			requirePlannedProject(resource, after, "project", logical, projects, violations)
		}
	case "module.audit_root.google_project_iam_member.sink_writer":
		sinkProjects := map[string]string{
			"primary": "audit", "recovery": "recovery",
		}
		if logical := sinkProjects[instance]; indexed && logical != "" {
			requirePlannedProject(resource, after, "project", logical, projects, violations)
		}
	case "module.audit_root.google_project_iam_member.reader":
		parts := strings.SplitN(instance, ":", 2)
		logical := map[string]string{"primary": "audit", "recovery": "recovery"}[parts[0]]
		if !indexed || len(parts) != 2 || logical == "" {
			*violations = append(*violations, resource.Address+" audit reader must identify a planned primary or recovery audit bucket")
		} else {
			requirePlannedProject(resource, after, "project", logical, projects, violations)
		}
	case "module.audit_root.google_project_iam_member.administrator":
		requirePlannedProject(resource, after, "project", "audit", projects, violations)
	case "module.audit_root.google_project_iam_member.plan_read":
		logical := map[string]string{"primary": "audit", "recovery": "recovery"}[instance]
		if indexed && logical != "" {
			requirePlannedProject(resource, after, "project", logical, projects, violations)
		}
	}
}

func validateAuditBucketProject(resource resourceChange, after map[string]any, projects map[string]string, violations *[]string) {
	const base = "module.audit_root.google_logging_project_bucket_config.audit"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	logical := map[string]string{"primary": "audit", "recovery": "recovery"}[instance]
	if indexed && logical != "" {
		requirePlannedProject(resource, after, "project", logical, projects, violations)
	}
}

func validateAuditSinkProject(resource resourceChange, after map[string]any, projects map[string]string, violations *[]string) {
	const base = "module.audit_root.google_logging_organization_sink.audit"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	if !indexed {
		return
	}
	logical := "audit"
	bucketID := "bootstrap-audit-primary"
	location := "us-central1"
	if strings.HasSuffix(instance, "-recovery") {
		logical = "recovery"
		bucketID = "bootstrap-audit-recovery"
		location = "us-east4"
	}
	destination, _ := after["destination"].(string)
	if destination == "" && topLevelUnknown(resource.Change.AfterUnknown, "destination") {
		return
	}
	expected := fmt.Sprintf("logging.googleapis.com/projects/%s/locations/%s/buckets/%s", projects[logical], location, bucketID)
	if projects[logical] == "" || destination != expected {
		*violations = append(*violations, resource.Address+" destination must equal its planned protected audit bucket")
	}
}

func validatePAMProject(resource resourceChange, after map[string]any, projects map[string]string, violations *[]string) {
	const base = "module.break_glass.google_privileged_access_manager_entitlement.break_glass"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	logical := map[string]string{
		"identity-root-administration": "identity",
		"root-trust-administration":    "root_state",
		"recovery-root-administration": "recovery",
		"signing-root-administration":  "signing",
	}[instance]
	if !indexed || logical == "" {
		return
	}
	expected := projects[logical]
	parent, _ := after["parent"].(string)
	if expected == "" || parent != "projects/"+expected || topLevelUnknown(resource.Change.AfterUnknown, "parent") {
		*violations = append(*violations, resource.Address+" must target its exact planned root project")
	}
}

func approvedResourceAddress(resource resourceChange) bool {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	key := resource.Mode + "|" + resource.Type + "|" + base
	if !approvedResourceAddressFamilies[key] {
		return false
	}
	index, indexed, valid := terraformAddressStringIndex(resource.Address, base)
	if !valid {
		return false
	}
	if base == "module.signing_root.google_kms_crypto_key_version.signing" {
		return indexed && resource.signingContract != nil && resource.signingContract.versions[resource.Address]
	}
	if expected, ok := exactResourceAddressKeys[base]; ok {
		return indexed && expected[index]
	}
	if kind, ok := dynamicResourceAddressKeys[base]; ok {
		return indexed && validDynamicAddressIndex(kind, index)
	}
	return !indexed
}

func terraformAddressStringIndex(address, base string) (string, bool, bool) {
	if address == base {
		return "", false, true
	}
	if !strings.HasPrefix(address, base+"[") || !strings.HasSuffix(address, "]") {
		return "", false, false
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(address, base+"["), "]")
	var index string
	if json.Unmarshal([]byte(raw), &index) != nil || index == "" {
		return "", false, false
	}
	return index, true, true
}

func validDynamicAddressIndex(kind, index string) bool {
	switch kind {
	case "project":
		return googleProjectIDPattern.MatchString(index)
	case "principal":
		return explicitPrincipal(index)
	case "project-principal":
		parts := strings.SplitN(index, ":", 2)
		return len(parts) == 2 && googleProjectIDPattern.MatchString(parts[0]) && explicitPrincipal(parts[1])
	case "audit-bucket-principal":
		parts := strings.SplitN(index, ":", 2)
		return len(parts) == 2 && (parts[0] == "primary" || parts[0] == "recovery") &&
			(groupEmailPrincipalPattern.MatchString(parts[1]) || bootstrapRecoveryPrincipalPattern.MatchString(parts[1]))
	case "role-principal":
		parts := strings.SplitN(index, ":", 2)
		return len(parts) == 2 && parts[0] == "roles/logging.configWriter" && explicitPrincipal(parts[1])
	case "signing-key-principal":
		parts := strings.SplitN(index, ":", 2)
		return len(parts) == 2 && stringSet(signingKeyNames...)[parts[0]] && explicitPrincipal(parts[1])
	}
	return false
}

func explicitPrincipal(principal string) bool {
	if strings.ContainsAny(principal, "* \t\r\n") || principal == "allUsers" || principal == "allAuthenticatedUsers" {
		return false
	}
	return emailPrincipalPattern.MatchString(principal) || serviceAccountIAMPattern.MatchString(principal) || federatedIAMPrincipalPattern.MatchString(principal)
}

func prohibitedResourceType(resourceType string) bool {
	if prohibitedResourceTypes[resourceType] {
		return true
	}
	for _, prefix := range prohibitedResourcePrefixes {
		if strings.HasPrefix(resourceType, prefix) {
			return true
		}
	}
	return false
}

func inspect(value any, path string, violations *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lower := strings.ToLower(key)
			if sensitiveField(lower) && concreteScalar(child) {
				*violations = append(*violations, fmt.Sprintf("%s contains static credential field %s", path, key))
			}
			inspect(child, path+"."+key, violations)
		}
	case []any:
		for _, child := range typed {
			inspect(child, path, violations)
		}
	case string:
		if primitiveRoles[typed] {
			*violations = append(*violations, fmt.Sprintf("%s grants prohibited primitive role %s", path, typed))
		} else if strings.HasPrefix(typed, "roles/") && !approvedRoles[typed] {
			*violations = append(*violations, fmt.Sprintf("%s grants role %s outside the Ring-0 allowlist", path, typed))
		}
		if typed == "*" || typed == "allUsers" || typed == "allAuthenticatedUsers" || strings.HasSuffix(typed, "/*") {
			*violations = append(*violations, fmt.Sprintf("%s contains wildcard/public principal %s", path, typed))
		}
	}
}

func inspectUnknown(value any, path string, resource resourceChange, violations *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			lower := strings.ToLower(key)
			requiresApproval := securityRelevantField(lower) ||
				(resource.Type == "google_storage_transfer_job" && transferOutputField(lower))
			if requiresApproval && containsUnknown(child) && !allowedUnknownSecurityValue(resource, lower) {
				*violations = append(*violations, childPath+" contains an unknown security-relevant planned value")
			}
			inspectUnknown(child, childPath, resource, violations)
		}
	case []any:
		for index, child := range typed {
			inspectUnknown(child, fmt.Sprintf("%s[%d]", path, index), resource, violations)
		}
	}
}

func inspectResourceInvariants(resource resourceChange, violations *[]string) {
	after, ok := resource.Change.After.(map[string]any)
	if !ok {
		if resource.Type == "google_project_iam_custom_role" || resource.Type == "google_organization_iam_custom_role" ||
			resource.Type == "google_kms_crypto_key_version" ||
			resource.Type == "google_service_account" ||
			resource.Type == "google_storage_transfer_job" ||
			resource.Type == "google_storage_transfer_project_service_account" {
			*violations = append(*violations, resource.Address+" must expose explicit Ring-0 contract values")
		}
		return
	}
	if resource.Mode == "managed" && preventDeletionPolicyTypes[resource.Type] {
		requireEqual(after, "deletion_policy", "PREVENT", resource.Address, violations)
	}
	if strings.HasSuffix(resource.Type, "_iam_member") {
		role, _ := after["role"].(string)
		if role != "" && !approvedBinding(resource.Type, resource.Address, role) {
			*violations = append(*violations, fmt.Sprintf("%s grants role %s outside its approved Ring-0 scope", resource.Address, role))
		}
		validateExpectedServiceAgentMember(resource, after, violations)
		validateStateBackendAccessContract(resource, after, violations)
		validateReplicationBucketAccessContract(resource, after, violations)
		validateRecoveryPlanReadAccessContract(resource, after, violations)
		validateRecoveryStateExportIAMBinding(resource, after, violations)
		validateRecoverySigningMetadataBinding(resource, after, violations)
		validateIndexedIAMAddressContract(resource, after, violations)
	}
	switch resource.Type {
	case "google_project":
		validateProjectContract(resource, after, violations)
	case "google_project_service":
		validateProjectServiceContract(resource, after, violations)
	case "google_project_iam_custom_role", "google_organization_iam_custom_role":
		validateReplicationCustomRole(resource, after, violations)
	case "google_privileged_access_manager_entitlement":
		validatePAMEntitlement(resource, after, violations)
	case "google_kms_key_ring":
		validateKMSKeyRingContract(resource, after, violations)
	case "google_storage_bucket":
		requireEqual(after, "uniform_bucket_level_access", true, resource.Address, violations)
		requireEqual(after, "public_access_prevention", "enforced", resource.Address, violations)
		requireEqual(after, "force_destroy", false, resource.Address, violations)
		if !nestedBoolean(after["versioning"], "enabled") {
			*violations = append(*violations, resource.Address+" must enable bucket versioning")
		}
		if nestedString(after["encryption"], "default_kms_key_name") == "" &&
			(!approvedUnknownBucketCMEK(resource) || !nestedUnknown(resource.Change.AfterUnknown, "encryption", "default_kms_key_name")) {
			*violations = append(*violations, resource.Address+" must use a default CMEK")
		}
		if nestedNumber(after["soft_delete_policy"], "retention_duration_seconds") < 2592000 {
			*violations = append(*violations, resource.Address+" must retain soft-deleted objects for at least 30 days")
		}
		validateStorageBucketContract(resource, after, violations)
	case "google_kms_crypto_key":
		template := firstObject(after["version_template"])
		purpose, _ := after["purpose"].(string)
		algorithm, _ := template["algorithm"].(string)
		expectedPurpose := "ENCRYPT_DECRYPT"
		expectedAlgorithm := "GOOGLE_SYMMETRIC_ENCRYPTION"
		if strings.HasPrefix(resourceAddressBase(resource.Address), "module.signing_root.google_kms_crypto_key.signing") {
			expectedPurpose = "ASYMMETRIC_SIGN"
			expectedAlgorithm = "EC_SIGN_P256_SHA256"
		}
		if protection, _ := template["protection_level"].(string); protection != "HSM" {
			*violations = append(*violations, resource.Address+" must create HSM-protected key versions")
		}
		if purpose != expectedPurpose || algorithm != expectedAlgorithm {
			*violations = append(*violations, fmt.Sprintf("%s must use address-specific KMS purpose %s and algorithm %s", resource.Address, expectedPurpose, expectedAlgorithm))
		}
		if expectedPurpose == "ENCRYPT_DECRYPT" {
			requireEqual(after, "rotation_period", "7776000s", resource.Address, violations)
		} else if !plannedUnset(after["rotation_period"]) {
			*violations = append(*violations, resource.Address+" signing key must use explicit version declarations rather than automatic key rotation")
		}
		requireEqual(after, "destroy_scheduled_duration", "2592000s", resource.Address, violations)
		validateSigningCryptoKey(resource, after, violations)
	case "google_kms_crypto_key_version":
		if resource.Mode == "managed" {
			validateSigningCryptoKeyVersion(resource, after, violations)
		} else {
			validateActiveSigningVersionData(resource, after, violations)
		}
	case "google_iam_workload_identity_pool_provider", "google_iam_workforce_pool_provider":
		if resourceAddressBase(resource.Address) == "module.github_federation.google_iam_workload_identity_pool_provider.github" {
			if _, ok := after["disabled"].(bool); !ok {
				*violations = append(*violations, resource.Address+" must set disabled to one explicit transition-derived boolean")
			}
		} else {
			requireEqual(after, "disabled", false, resource.Address, violations)
		}
		condition, _ := after["attribute_condition"].(string)
		ciEvidenceProvider := resourceAddressBase(resource.Address) == "module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence"
		if unsafeCondition(condition) && !ciEvidenceProvider {
			*violations = append(*violations, resource.Address+" must use a fail-closed attribute condition")
		}
		mapping, _ := after["attribute_mapping"].(map[string]any)
		if subject, _ := mapping["google.subject"].(string); strings.TrimSpace(subject) == "" {
			*violations = append(*violations, resource.Address+" must explicitly map google.subject")
		}
		if resource.Type == "google_iam_workload_identity_pool_provider" {
			oidc := firstObject(after["oidc"])
			issuer, _ := oidc["issuer_uri"].(string)
			audiences, _ := oidc["allowed_audiences"].([]any)
			ciEvidenceProvider := resourceAddressBase(resource.Address) == "module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence"
			validAudienceContract := len(audiences) == 1
			if ciEvidenceProvider {
				// Empty allowed_audiences is the Google-defined fail-closed default:
				// only this provider's canonical resource audiences are accepted.
				validAudienceContract = len(audiences) == 0
			}
			if !strings.HasPrefix(issuer, "https://") || !validAudienceContract {
				*violations = append(*violations, resource.Address+" must use an HTTPS OIDC issuer and its approved audience contract")
			}
		}
		validateIdentityProviderContract(resource, after, violations)
		if resource.Type == "google_iam_workforce_pool_provider" {
			validateWorkforceSecretRevision(resource, after, violations)
		}
	case "google_iam_workload_identity_pool", "google_iam_workforce_pool":
		if resourceAddressBase(resource.Address) == "module.github_federation.google_iam_workload_identity_pool.github" {
			if _, ok := after["disabled"].(bool); !ok {
				*violations = append(*violations, resource.Address+" must set disabled to one explicit transition-derived boolean")
			}
		} else {
			requireEqual(after, "disabled", false, resource.Address, violations)
		}
		validateIdentityPoolContract(resource, after, violations)
	case "google_secret_manager_secret":
		if resourceAddressBase(resource.Address) == "module.signing_root.google_secret_manager_secret.nix_cache_signing" {
			requireEqual(after, "secret_id", "nix-cache-signing-key", resource.Address, violations)
			requireEqual(after, "deletion_protection", true, resource.Address, violations)
		}
	case "google_secret_manager_secret_version":
		if resourceAddressBase(resource.Address) == "module.signing_root.google_secret_manager_secret_version.nix_cache_signing" {
			requireEqual(after, "deletion_policy", "DISABLE", resource.Address, violations)
			if !plannedUnset(after["secret_data"]) || !plannedUnset(after["secret_data_wo"]) {
				*violations = append(*violations, resource.Address+" must never expose Secret Manager payload bytes in a plan")
			}
		}
	case "google_logging_project_bucket_config":
		validateAuditLogBucket(resource, after, violations)
	case "google_logging_organization_sink":
		validateAuditOrganizationSink(resource, after, violations)
	case "google_organization_iam_audit_config":
		validateStorageDataAccessAuditConfig(resource, after, violations)
	case "google_storage_bucket_object":
		content, ok := after["content"].(string)
		var embedded any
		if !ok || json.Unmarshal([]byte(content), &embedded) != nil {
			*violations = append(*violations, resource.Address+" content must be explicit JSON")
		} else {
			inspect(embedded, resource.Address+".content", violations)
		}
		validateFixedRecoveryObject(resource, after, violations)
	case "google_storage_transfer_job":
		validateReplicationTransferJob(resource, after, violations)
	case "google_storage_transfer_project_service_account":
		validateTransferServiceAccountData(resource, after, violations)
	case "google_storage_project_service_account":
		validateRecoveryStateExportStorageServiceAccountData(resource, after, violations)
	case "google_service_account":
		validateFederatedServiceAccount(resource, after, violations)
		validateRecoveryStateExportServiceAccount(resource, after, violations)
	}
}

func validateStorageDataAccessAuditConfig(resource resourceChange, after map[string]any, violations *[]string) {
	if resource.Address != "google_organization_iam_audit_config.storage_data_access" ||
		!numericIDPattern.MatchString(stringValue(after["org_id"])) || after["service"] != "storage.googleapis.com" ||
		topLevelUnknown(resource.Change.AfterUnknown, "org_id") || topLevelUnknown(resource.Change.AfterUnknown, "service") {
		*violations = append(*violations, resource.Address+" must enable Data Access auditing only for Cloud Storage in the exact organization")
		return
	}
	configs, ok := after["audit_log_config"].([]any)
	if !ok || len(configs) != 2 || nestedUnknown(resource.Change.AfterUnknown, "audit_log_config") {
		*violations = append(*violations, resource.Address+" must declare exactly DATA_READ and DATA_WRITE audit log configs")
		return
	}
	logTypes := map[string]bool{}
	for _, raw := range configs {
		config, ok := raw.(map[string]any)
		logType, _ := config["log_type"].(string)
		exempted, _ := config["exempted_members"].([]any)
		if !ok || len(exempted) != 0 || logTypes[logType] {
			*violations = append(*violations, resource.Address+" Data Access audit configs must contain no exemptions or duplicates")
			return
		}
		logTypes[logType] = true
	}
	if !sameStringSet(logTypes, stringSet("DATA_READ", "DATA_WRITE")) {
		*violations = append(*violations, resource.Address+" must enable exactly DATA_READ and DATA_WRITE")
	}
}

func validateProjectContract(resource resourceChange, after map[string]any, violations *[]string) {
	projectID, _ := after["project_id"].(string)
	orgID, _ := after["org_id"].(string)
	billingAccount, _ := after["billing_account"].(string)
	name, _ := after["name"].(string)
	if !googleProjectIDPattern.MatchString(projectID) || topLevelUnknown(resource.Change.AfterUnknown, "project_id") {
		*violations = append(*violations, resource.Address+" must declare one explicit valid Google Cloud project ID")
	}
	if !numericIDPattern.MatchString(orgID) || topLevelUnknown(resource.Change.AfterUnknown, "org_id") {
		*violations = append(*violations, resource.Address+" must attach to one explicit numeric organization")
	}
	if !billingAccountPattern.MatchString(billingAccount) || topLevelUnknown(resource.Change.AfterUnknown, "billing_account") {
		*violations = append(*violations, resource.Address+" must attach to one explicit canonical billing account")
	}
	if name != projectID {
		*violations = append(*violations, resource.Address+" project display name must exactly match its compiler-declared project ID")
	}
	requireEqual(after, "auto_create_network", false, resource.Address, violations)
	requireEqual(after, "deletion_policy", "PREVENT", resource.Address, violations)
}

func validateProjectServiceContract(resource resourceChange, after map[string]any, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	project, _ := after["project"].(string)
	service, _ := after["service"].(string)
	if !indexed || !googleProjectIDPattern.MatchString(project) || topLevelUnknown(resource.Change.AfterUnknown, "project") {
		*violations = append(*violations, resource.Address+" must enable its service in one explicit valid project")
	}
	expectedService := instance
	if base == "google_project_service.state" {
		parts := strings.SplitN(instance, ":", 2)
		if len(parts) == 2 {
			expectedService = parts[1]
		}
	}
	if base == "module.break_glass.google_project_service.pam" {
		expectedService = "privilegedaccessmanager.googleapis.com"
		if project != instance {
			*violations = append(*violations, resource.Address+" PAM service index must equal its explicit target project")
		}
	}
	if service != expectedService || topLevelUnknown(resource.Change.AfterUnknown, "service") {
		*violations = append(*violations, resource.Address+" must enable only the service named by its approved address instance")
	}
	requireEqual(after, "disable_on_destroy", false, resource.Address, violations)
}

func validateKMSKeyRingContract(resource resourceChange, after map[string]any, violations *[]string) {
	type ringContract struct {
		name     string
		location string
	}
	contracts := map[string]ringContract{
		"module.root_state.google_kms_key_ring.state":             {name: "state-backend", location: "us-central1"},
		"module.root_state.google_kms_key_ring.replica":           {name: "state-replica", location: "us-east4"},
		"module.recovery_state.google_kms_key_ring.state":         {name: "state-backend", location: "us-east4"},
		"module.recovery_state.google_kms_key_ring.replica":       {name: "state-replica", location: "us-central1"},
		"module.signing_root.google_kms_key_ring.signing":         {name: "bootstrap-signing", location: "us-central1"},
		"module.recovery_exports.google_kms_key_ring.recovery":    {name: "bootstrap-recovery", location: "us-east4"},
		`module.audit_root.google_kms_key_ring.audit["primary"]`:  {name: "audit-primary", location: "us-central1"},
		`module.audit_root.google_kms_key_ring.audit["recovery"]`: {name: "audit-recovery", location: "us-east4"},
	}
	contract, ok := contracts[resource.Address]
	if !ok {
		*violations = append(*violations, resource.Address+" is outside the exact KMS key-ring instances")
		return
	}
	project, _ := after["project"].(string)
	if !googleProjectIDPattern.MatchString(project) || topLevelUnknown(resource.Change.AfterUnknown, "project") {
		*violations = append(*violations, resource.Address+" must create its key ring in one explicit project")
	}
	requireEqual(after, "name", contract.name, resource.Address, violations)
	requireEqual(after, "location", contract.location, resource.Address, violations)
}

func validateStorageBucketContract(resource resourceChange, after map[string]any, violations *[]string) {
	project, _ := after["project"].(string)
	name, _ := after["name"].(string)
	if !googleProjectIDPattern.MatchString(project) || !validBucketName(name) ||
		topLevelUnknown(resource.Change.AfterUnknown, "project") || topLevelUnknown(resource.Change.AfterUnknown, "name") {
		*violations = append(*violations, resource.Address+" must use explicit valid bucket and project IDs")
	}
	requireEqual(after, "storage_class", "STANDARD", resource.Address, violations)
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	instance, _, _ := terraformAddressStringIndex(resource.Address, base)
	if base == "module.recovery_exports.google_storage_bucket.recovery" {
		expectedSuffix := "-recovery-" + instance
		if name != project+expectedSuffix || after["location"] != "US-EAST4" {
			*violations = append(*violations, resource.Address+" must use its deterministic recovery bucket name and region")
		}
		retention := firstObject(after["retention_policy"])
		expectedRetention := "2592000"
		if instance == "evidence" {
			expectedRetention = "220752000"
		}
		if retention["retention_period"] != expectedRetention || retention["is_locked"] != true {
			*violations = append(*violations, resource.Address+" must use its exact locked recovery retention policy")
		}
		return
	}
	locations := map[string]map[string]string{
		"module.root_state.google_storage_bucket.state":     {"primary": "US-CENTRAL1", "replica": "US-EAST4"},
		"module.recovery_state.google_storage_bucket.state": {"primary": "US-EAST4", "replica": "US-CENTRAL1"},
	}
	if expected := locations[base][instance]; expected != "" && after["location"] != expected {
		*violations = append(*violations, resource.Address+" must remain in its approved primary/replica region")
	}
	if locations[base] != nil {
		validateStateBucketLifecycle(resource, after, violations)
	}
}

func validateStateBucketLifecycle(resource resourceChange, after map[string]any, violations *[]string) {
	rules, rulesOK := after["lifecycle_rule"].([]any)
	if !rulesOK || len(rules) != 1 || !approvedStateBucketLifecycleUnknowns(resource) {
		*violations = append(*violations, resource.Address+" must configure exactly one explicit noncurrent-generation Delete lifecycle rule")
		return
	}
	rule, ruleOK := rules[0].(map[string]any)
	action, actionOK := singleObject(rule["action"])
	condition, conditionOK := singleObject(rule["condition"])
	if !ruleOK || !actionOK || !conditionOK || action["type"] != "Delete" ||
		condition["days_since_noncurrent_time"] != float64(365) ||
		condition["num_newer_versions"] != float64(3) ||
		condition["send_age_if_zero"] != false {
		*violations = append(*violations, resource.Address+" lifecycle must delete only noncurrent generations after 365 days while preserving the three newest generations")
	}
}

func approvedStateBucketLifecycleUnknowns(resource resourceChange) bool {
	unknown := firstObject(resource.Change.AfterUnknown)
	if !containsUnknown(unknown["lifecycle_rule"]) {
		return true
	}
	rules, ok := unknown["lifecycle_rule"].([]any)
	if !ok || len(rules) != 1 {
		return false
	}
	rule, ok := rules[0].(map[string]any)
	if !ok || len(rule) != 2 {
		return false
	}
	action, actionOK := singleObject(rule["action"])
	condition, conditionOK := singleObject(rule["condition"])
	if !actionOK || len(action) != 0 || !conditionOK || len(condition) != 4 || condition["with_state"] != true {
		return false
	}
	for _, key := range []string{"matches_prefix", "matches_storage_class", "matches_suffix"} {
		values, valuesOK := condition[key].([]any)
		if !valuesOK || len(values) != 0 {
			return false
		}
	}
	return true
}

func validBucketName(name string) bool {
	return len(name) >= 3 && len(name) <= 63 && regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*[a-z0-9]$`).MatchString(name) &&
		!strings.HasPrefix(name, "goog") && !strings.Contains(name, "google")
}

func validateFederatedServiceAccount(resource resourceChange, after map[string]any, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	expectedAccountID := ""
	switch base {
	case "module.github_federation.google_service_account.github":
		instance, _, _ := terraformAddressStringIndex(resource.Address, base)
		expectedAccountID = map[string]string{
			"plan": "bootstrap-plan", "apply": "bootstrap-apply", "recovery": "bootstrap-recovery",
		}[instance]
	case "module.github_federation.google_service_account.ci_evidence":
		instance, _, _ := terraformAddressStringIndex(resource.Address, base)
		expectedAccountID = map[string]string{
			"writer": "ci-evidence-writer", "verifier": "ci-evidence-verifier",
		}[instance]
	case "module.github_federation.google_service_account.github_config":
		instance, _, _ := terraformAddressStringIndex(resource.Address, base)
		expectedAccountID = map[string]string{"plan": "github-config-plan", "apply": "github-config-apply"}[instance]
	case "module.github_federation.google_service_account.infrastructure_live":
		instance, _, _ := terraformAddressStringIndex(resource.Address, base)
		expectedAccountID = instance
	case "module.github_federation.google_service_account.infrastructure_drift":
		instance, _, _ := terraformAddressStringIndex(resource.Address, base)
		if instance == "drift" {
			expectedAccountID = "infrastructure-plan"
		}
	case "module.buildkite_federation.google_service_account.buildkite":
		expectedAccountID = "buildkite-bootstrap"
	case "module.gitops_federation.google_service_account.gitops":
		expectedAccountID = "gitops-bootstrap"
	default:
		return
	}
	project, _ := after["project"].(string)
	if !googleProjectIDPattern.MatchString(project) || topLevelUnknown(resource.Change.AfterUnknown, "project") {
		*violations = append(*violations, resource.Address+" must create its keyless identity in one explicit project")
	}
	requireEqual(after, "account_id", expectedAccountID, resource.Address, violations)
	if disabled, ok := after["disabled"].(bool); ok && disabled {
		*violations = append(*violations, resource.Address+" bootstrap service account must remain enabled")
	}
}

func validateIdentityPoolContract(resource resourceChange, after map[string]any, violations *[]string) {
	if resource.Type == "google_iam_workload_identity_pool" {
		project, _ := after["project"].(string)
		poolID, _ := after["workload_identity_pool_id"].(string)
		if !googleProjectIDPattern.MatchString(project) || !googleShortIDPattern.MatchString(poolID) ||
			topLevelUnknown(resource.Change.AfterUnknown, "project") {
			*violations = append(*violations, resource.Address+" workload pool must use explicit valid project and pool IDs")
		}
		base := resource.Address
		if index := strings.IndexByte(base, '['); index >= 0 {
			base = base[:index]
		}
		switch base {
		case "module.github_federation.google_iam_workload_identity_pool.github":
			instance, _, _ := terraformAddressStringIndex(resource.Address, base)
			requireEqual(after, "workload_identity_pool_id", "bootstrap-github-"+instance, resource.Address, violations)
		case "module.github_federation.google_iam_workload_identity_pool.ci_evidence":
			requireEqual(after, "workload_identity_pool_id", "github-ci-evidence", resource.Address, violations)
		case "module.github_federation.google_iam_workload_identity_pool.github_config":
			requireEqual(after, "workload_identity_pool_id", "github-config", resource.Address, violations)
		case "module.github_federation.google_iam_workload_identity_pool.infrastructure_live":
			requireEqual(after, "workload_identity_pool_id", "infrastructure-live", resource.Address, violations)
		case "module.buildkite_federation.google_iam_workload_identity_pool.buildkite":
			requireEqual(after, "workload_identity_pool_id", "bootstrap-buildkite", resource.Address, violations)
		case "module.gitops_federation.google_iam_workload_identity_pool.gitops":
			requireEqual(after, "workload_identity_pool_id", "bootstrap-gitops", resource.Address, violations)
		}
		return
	}
	poolID, _ := after["workforce_pool_id"].(string)
	parent, _ := after["parent"].(string)
	if !googleShortIDPattern.MatchString(poolID) || !strings.HasPrefix(parent, "organizations/") ||
		!numericIDPattern.MatchString(strings.TrimPrefix(parent, "organizations/")) {
		*violations = append(*violations, resource.Address+" workforce pool must use explicit organization and pool IDs")
	}
	requireEqual(after, "location", "global", resource.Address, violations)
	requireEqual(after, "workforce_pool_id", "mindclade-workforce", resource.Address, violations)
}

func validateIdentityProviderContract(resource resourceChange, after map[string]any, violations *[]string) {
	if resource.Type == "google_iam_workload_identity_pool_provider" {
		project, _ := after["project"].(string)
		poolID, _ := after["workload_identity_pool_id"].(string)
		providerID, _ := after["workload_identity_pool_provider_id"].(string)
		if !googleProjectIDPattern.MatchString(project) || !googleShortIDPattern.MatchString(poolID) || !googleShortIDPattern.MatchString(providerID) {
			*violations = append(*violations, resource.Address+" workload provider must use explicit valid project, pool, and provider IDs")
		}
		base := resource.Address
		if index := strings.IndexByte(base, '['); index >= 0 {
			base = base[:index]
		}
		switch base {
		case "module.github_federation.google_iam_workload_identity_pool_provider.github":
			instance, _, _ := terraformAddressStringIndex(resource.Address, base)
			requireEqual(after, "workload_identity_pool_id", "bootstrap-github-"+instance, resource.Address, violations)
			requireEqual(after, "workload_identity_pool_provider_id", "github-actions-"+instance, resource.Address, violations)
		case "module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence":
			instance, _, _ := terraformAddressStringIndex(resource.Address, base)
			requireEqual(after, "workload_identity_pool_id", "github-ci-evidence", resource.Address, violations)
			requireEqual(after, "workload_identity_pool_provider_id", instance, resource.Address, violations)
		case "module.github_federation.google_iam_workload_identity_pool_provider.github_config":
			instance, _, _ := terraformAddressStringIndex(resource.Address, base)
			requireEqual(after, "workload_identity_pool_id", "github-config", resource.Address, violations)
			requireEqual(after, "workload_identity_pool_provider_id", "github-config-"+instance, resource.Address, violations)
		case "module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_live":
			instance, _, _ := terraformAddressStringIndex(resource.Address, base)
			requireEqual(after, "workload_identity_pool_id", "infrastructure-live", resource.Address, violations)
			requireEqual(after, "workload_identity_pool_provider_id", instance, resource.Address, violations)
		case "module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_drift":
			requireEqual(after, "workload_identity_pool_id", "infrastructure-live", resource.Address, violations)
			requireEqual(after, "workload_identity_pool_provider_id", "infrastructure-plan", resource.Address, violations)
		case "module.buildkite_federation.google_iam_workload_identity_pool_provider.buildkite":
			requireEqual(after, "workload_identity_pool_id", "bootstrap-buildkite", resource.Address, violations)
			requireEqual(after, "workload_identity_pool_provider_id", "buildkite", resource.Address, violations)
		case "module.gitops_federation.google_iam_workload_identity_pool_provider.gitops":
			requireEqual(after, "workload_identity_pool_id", "bootstrap-gitops", resource.Address, violations)
			requireEqual(after, "workload_identity_pool_provider_id", "gitops", resource.Address, violations)
		}
		oidc, _ := singleObject(after["oidc"])
		issuer, _ := oidc["issuer_uri"].(string)
		switch base {
		case "module.github_federation.google_iam_workload_identity_pool_provider.github",
			"module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence",
			"module.github_federation.google_iam_workload_identity_pool_provider.github_config",
			"module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_live",
			"module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_drift":
			if issuer != "https://token.actions.githubusercontent.com" {
				*violations = append(*violations, resource.Address+" must use the canonical GitHub Actions issuer")
			}
		case "module.buildkite_federation.google_iam_workload_identity_pool_provider.buildkite":
			if issuer != "https://agent.buildkite.com" {
				*violations = append(*violations, resource.Address+" must use the canonical Buildkite issuer")
			}
		case "module.gitops_federation.google_iam_workload_identity_pool_provider.gitops":
			if !strings.HasPrefix(issuer, "https://") {
				*violations = append(*violations, resource.Address+" GitOps issuer must use HTTPS")
			}
		}
		switch base {
		case "module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence":
			validateCIEvidenceProviderClaims(resource, after, violations)
		case "module.github_federation.google_iam_workload_identity_pool_provider.github_config":
			validateGithubConfigProviderClaims(resource, after, violations)
		case "module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_live":
			validateInfrastructureProviderClaims(resource, after, violations)
		case "module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_drift":
			validateInfrastructureDriftProviderClaims(resource, after, violations)
		default:
			validateWorkloadProviderClaims(resource, after, base, violations)
		}
		return
	}
	poolID, _ := after["workforce_pool_id"].(string)
	providerID, _ := after["provider_id"].(string)
	if !googleShortIDPattern.MatchString(poolID) || !googleShortIDPattern.MatchString(providerID) {
		*violations = append(*violations, resource.Address+" workforce provider must use explicit valid pool and provider IDs")
	}
	requireEqual(after, "location", "global", resource.Address, violations)
	requireEqual(after, "detailed_audit_logging", true, resource.Address, violations)
	requireEqual(after, "workforce_pool_id", "mindclade-workforce", resource.Address, violations)
	requireEqual(after, "provider_id", "primary-idp", resource.Address, violations)
	oidc, ok := singleObject(after["oidc"])
	issuer, _ := oidc["issuer_uri"].(string)
	clientID, _ := oidc["client_id"].(string)
	if !ok || !strings.HasPrefix(issuer, "https://") || strings.TrimSpace(clientID) == "" {
		*violations = append(*violations, resource.Address+" workforce provider must use one explicit HTTPS OIDC issuer and client ID")
	}
	validateWorkforceProviderClaims(resource, after, violations)
}

func validateCIEvidenceProviderClaims(resource resourceChange, after map[string]any, violations *[]string) {
	base := "module.github_federation.google_iam_workload_identity_pool_provider.ci_evidence"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	commonMapping := map[string]string{
		"google.subject":                  githubRepositorySubjectMapping("ci-evidence-" + instance),
		"attribute.evidence_role":         "'" + instance + "'",
		"attribute.repository_id":         "assertion.repository_id",
		"attribute.repository_owner_id":   "assertion.repository_owner_id",
		"attribute.ref":                   "assertion.ref",
		"attribute.event_name":            "assertion.event_name",
		"attribute.repository_visibility": "assertion.repository_visibility",
		"attribute.runner_environment":    "assertion.runner_environment",
	}
	expectedMapping := map[string]string{}
	for key, value := range commonMapping {
		expectedMapping[key] = value
	}
	condition, _ := after["attribute_condition"].(string)
	validCondition := false
	switch instance {
	case "writer":
		expectedMapping["attribute.job_workflow_ref"] = "assertion.job_workflow_ref"
		expectedMapping["attribute.job_workflow_sha"] = "assertion.job_workflow_sha"
		pattern := regexp.MustCompile(`^assertion\.repository_owner_id == '316676129' && assertion\.repository_id in \['1350980188', '1350986053', '1350991612', '1350991963', '1350992171', '1351193819'\] && assertion\.repository_visibility == 'public' && assertion\.runner_environment == 'github-hosted' && assertion\.job_workflow_ref == 'mindclade/\.github/\.github/workflows/reusable-required-check\.yml@([0-9a-f]{40})' && assertion\.job_workflow_sha == '([0-9a-f]{40})' && \(\(assertion\.event_name == 'push' && assertion\.ref == 'refs/heads/main'\) \|\| \(assertion\.event_name == 'release' && assertion\.ref\.startsWith\('refs/tags/v'\)\)\)$`)
		matches := pattern.FindStringSubmatch(condition)
		validCondition = len(matches) == 3 && matches[1] == matches[2]
	case "verifier":
		expectedMapping["attribute.workflow_ref"] = "assertion.workflow_ref"
		expectedMapping["attribute.workflow_sha"] = "assertion.workflow_sha"
		expectedMapping["attribute.environment"] = "assertion.environment"
		pattern := regexp.MustCompile(`^assertion\.repository_owner_id == '316676129' && assertion\.repository_id == '1350992171' && assertion\.repository_visibility == 'public' && assertion\.runner_environment == 'github-hosted' && assertion\.workflow_ref == 'mindclade/infrastructure-live/\.github/workflows/disaster-recovery\.yml@refs/heads/main' && assertion\.workflow_sha == '[0-9a-f]{40}' && assertion\.ref == 'refs/heads/main' && assertion\.event_name == 'workflow_dispatch' && assertion\.environment == 'infrastructure-apply'$`)
		validCondition = pattern.MatchString(condition)
	}
	oidc := firstObject(after["oidc"])
	if !indexed || !exactStringMap(after["attribute_mapping"], expectedMapping) || !validCondition || !plannedUnset(oidc["allowed_audiences"]) {
		*violations = append(*violations, resource.Address+" must bind its exact immutable CI-evidence claims and static evidence role")
	}
}

func validateGithubConfigProviderClaims(resource resourceChange, after map[string]any, violations *[]string) {
	base := "module.github_federation.google_iam_workload_identity_pool_provider.github_config"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	expectedMapping := map[string]string{
		"google.subject":                   githubRepositorySubjectMapping("github-config-" + instance),
		"attribute.github_config_identity": "'" + instance + "'",
		"attribute.repository_id":          "assertion.repository_id",
		"attribute.repository_owner_id":    "assertion.repository_owner_id",
		"attribute.ref":                    "assertion.ref",
		"attribute.workflow_ref":           "assertion.workflow_ref",
		"attribute.workflow_sha":           "assertion.workflow_sha",
		"attribute.repository_visibility":  "assertion.repository_visibility",
		"attribute.runner_environment":     "assertion.runner_environment",
	}
	oidc := firstObject(after["oidc"])
	condition := stringValue(after["attribute_condition"])
	validCondition := condition == githubConfigProviderCondition(instance)
	if instance == "plan" {
		validCondition = validCondition || condition == githubConfigProviderConditionForSubjects(instance, stringSet("github-config-protected-plan"))
	}
	if !indexed || !stringSet("plan", "apply")[instance] || !exactStringMap(after["attribute_mapping"], expectedMapping) ||
		!validCondition ||
		!exactStringSet(oidc["allowed_audiences"], []string{"sts.googleapis.com"}) {
		*violations = append(*violations, resource.Address+" must bind the exact github-config immutable custom subjects and singleton audience")
	}
}

func githubConfigProviderCondition(instance string) string {
	return githubConfigProviderConditionForSubjects(instance, nil)
}

func githubConfigProviderConditionForSubjects(instance string, activeSubjects map[string]bool) string {
	base := []string{
		"assertion.repository == 'mindclade/github-config'",
		"assertion.repository_owner == 'mindclade'",
		"assertion.repository_owner_id == '316676129'",
		"assertion.repository_id == '1350986053'",
		"assertion.repository_visibility == 'public'",
		"assertion.runner_environment == 'github-hosted'",
	}
	subject := func(workflowRef, contextType, contextValue string) string {
		contextPredicate := fmt.Sprintf("assertion.%s == '%s'", contextType, contextValue)
		return "(" + strings.Join([]string{
			fmt.Sprintf("assertion.sub == 'repo:mindclade@316676129/github-config@1350986053:%s:%s:workflow_ref:%s:workflow_sha:' + assertion.workflow_sha", contextType, contextValue, workflowRef),
			fmt.Sprintf("assertion.workflow_ref == '%s'", workflowRef),
			"assertion.workflow_sha == assertion.sha",
			contextPredicate,
		}, " && ") + ")"
	}
	conditions := []string{}
	switch instance {
	case "plan":
		if activeSubjects == nil || activeSubjects["github-config-drift-plan"] {
			conditions = append(conditions, subject("mindclade/github-config/.github/workflows/drift-detection.yml@refs/heads/main", "ref", "refs/heads/main"))
		}
		if activeSubjects == nil || activeSubjects["github-config-protected-plan"] {
			conditions = append(conditions, subject("mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main", "environment", "trusted-build"))
		}
	case "apply":
		if activeSubjects == nil || activeSubjects["github-config-protected-apply"] {
			conditions = append(conditions, subject("mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main", "environment", "infrastructure-apply"))
		}
	}
	return strings.Join(append(base, "("+strings.Join(conditions, " || ")+")"), " && ")
}

func validateInfrastructureDriftProviderClaims(resource resourceChange, after map[string]any, violations *[]string) {
	expectedMapping := map[string]string{
		"google.subject":                    githubRepositorySubjectMapping("infrastructure-live-drift-plan"),
		"attribute.infrastructure_identity": "'drift-plan'",
		"attribute.repository_id":           "assertion.repository_id",
		"attribute.repository_owner_id":     "assertion.repository_owner_id",
		"attribute.workflow_ref":            "assertion.workflow_ref",
		"attribute.workflow_sha":            "assertion.workflow_sha",
		"attribute.environment":             "assertion.environment",
	}
	oidc := firstObject(after["oidc"])
	if !exactStringMap(after["attribute_mapping"], expectedMapping) ||
		after["attribute_condition"] != infrastructureDriftProviderCondition() ||
		!exactStringSet(oidc["allowed_audiences"], []string{"sts.googleapis.com"}) {
		*violations = append(*violations, resource.Address+" must bind the exact infrastructure drift custom subject and singleton audience")
	}
}

func infrastructureDriftProviderCondition() string {
	workflowRef := "mindclade/infrastructure-live/.github/workflows/drift-detection.yml@refs/heads/main"
	return strings.Join([]string{
		fmt.Sprintf("assertion.sub == 'repo:mindclade@316676129/infrastructure-live@1350992171:environment:trusted-build:workflow_ref:%s:workflow_sha:' + assertion.workflow_sha", workflowRef),
		"assertion.repository == 'mindclade/infrastructure-live'",
		"assertion.repository_owner == 'mindclade'",
		"assertion.repository_owner_id == '316676129'",
		"assertion.repository_id == '1350992171'",
		"assertion.repository_visibility == 'public'",
		"assertion.ref == 'refs/heads/main'",
		fmt.Sprintf("assertion.workflow_ref == '%s'", workflowRef),
		"assertion.workflow_sha == assertion.sha",
		"assertion.environment == 'trusted-build'",
		"assertion.runner_environment == 'github-hosted'",
	}, " && ")
}

func validateInfrastructureProviderClaims(resource resourceChange, after map[string]any, violations *[]string) {
	base := "module.github_federation.google_iam_workload_identity_pool_provider.infrastructure_live"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	identityParts := strings.Split(instance, "-")
	if !indexed || len(identityParts) != 2 || !stringSet("development", "staging", "production", "restricted")[identityParts[0]] ||
		!stringSet("plan", "apply")[identityParts[1]] {
		*violations = append(*violations, resource.Address+" must be one of the exact eight infrastructure-live identities")
		return
	}
	environment := "trusted-build"
	if identityParts[1] == "apply" {
		environment = "infrastructure-apply"
	}
	declaration := map[string]any{
		"immutable_repository": "mindclade@316676129/infrastructure-live@1350992171",
		"repository_full_name": "mindclade/infrastructure-live",
		"repository_owner_id":  "316676129",
		"repository_id":        "1350992171",
		"branch_ref":           "refs/heads/main",
		"workflow_ref":         "mindclade/infrastructure-live/.github/workflows/protected-apply.yml@refs/heads/main",
	}
	expectedMapping := map[string]string{
		"google.subject":                    githubRepositorySubjectMapping("infrastructure-live-" + instance),
		"attribute.infrastructure_identity": "'" + instance + "'",
		"attribute.repository_id":           "assertion.repository_id",
		"attribute.repository_owner_id":     "assertion.repository_owner_id",
		"attribute.workflow_ref":            "assertion.workflow_ref",
		"attribute.workflow_sha":            "assertion.workflow_sha",
		"attribute.environment":             "assertion.environment",
	}
	oidc := firstObject(after["oidc"])
	expectedAudience := "https://github.mindclade.io/oidc/infrastructure-live/" + identityParts[0] + "/" + identityParts[1]
	if !exactStringMap(after["attribute_mapping"], expectedMapping) ||
		after["attribute_condition"] != infrastructureProviderCondition(declaration, environment) ||
		!exactStringSet(oidc["allowed_audiences"], []string{expectedAudience}) {
		*violations = append(*violations, resource.Address+" must bind its exact immutable custom subject, source SHA, execution environment, and singleton audience")
	}
}

func validateWorkloadProviderClaims(resource resourceChange, after map[string]any, base string, violations *[]string) {
	if base == "module.github_federation.google_iam_workload_identity_pool_provider.github" {
		validateBootstrapProviderClaims(resource, after, violations)
		return
	}
	mappingContracts := map[string]map[string]string{
		"module.buildkite_federation.google_iam_workload_identity_pool_provider.buildkite": {
			"google.subject":              "assertion.sub",
			"attribute.organization_slug": "assertion.organization_slug",
			"attribute.pipeline_slug":     "assertion.pipeline_slug",
			"attribute.pipeline_id":       "assertion.pipeline_id",
			"attribute.build_branch":      "assertion.build_branch",
			"attribute.step_key":          "assertion.step_key",
		},
		"module.gitops_federation.google_iam_workload_identity_pool_provider.gitops": {
			"google.subject":       "assertion.sub",
			"attribute.repository": "assertion.repository",
			"attribute.ref":        "assertion.ref",
		},
	}
	if !exactStringMap(after["attribute_mapping"], mappingContracts[base]) {
		*violations = append(*violations, resource.Address+" must use its exact immutable workload-claim mapping")
	}
	condition, _ := after["attribute_condition"].(string)
	claims, ok := parseExactClaimConjunction(condition)
	expectedClaims := map[string]bool{}
	switch base {
	case "module.buildkite_federation.google_iam_workload_identity_pool_provider.buildkite":
		expectedClaims = stringSet("sub", "organization_slug", "pipeline_slug", "pipeline_id", "build_branch", "step_key")
		ok = ok && regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`).MatchString(claims["pipeline_id"]) &&
			claims["sub"] == claims["pipeline_id"] && claims["build_branch"] == "main" && claims["step_key"] == "bootstrap-ring0-signing"
	case "module.gitops_federation.google_iam_workload_identity_pool_provider.gitops":
		expectedClaims = stringSet("sub", "repository", "ref")
		ok = ok && claims["ref"] == "refs/heads/main"
	}
	if !ok || len(claims) != len(expectedClaims) {
		*violations = append(*violations, resource.Address+" must use only exact nonempty equality predicates for its immutable claims")
		return
	}
	for claim := range claims {
		if !expectedClaims[claim] {
			*violations = append(*violations, resource.Address+" contains an unapproved workload-identity claim predicate")
		}
	}
}

func validateBootstrapProviderClaims(resource resourceChange, after map[string]any, violations *[]string) {
	base := "module.github_federation.google_iam_workload_identity_pool_provider.github"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	environment := map[string]string{"plan": "trusted-build", "apply": "infrastructure-apply", "recovery": "infrastructure-apply"}[instance]
	workflowRef := "mindclade/bootstrap/.github/workflows/protected-apply.yml@refs/heads/main"
	if instance == "recovery" {
		workflowRef = "mindclade/bootstrap/.github/workflows/recovery-verification.yml@refs/heads/main"
	}
	github := map[string]any{
		"repository_full_name": "mindclade/bootstrap",
		"repository_owner_id":  "316676129",
		"repository_id":        "1350991612",
		"branch_ref":           "refs/heads/main",
	}
	expectedMapping := map[string]string{
		"google.subject":                  githubRepositorySubjectMapping("bootstrap-" + instance),
		"attribute.repository_id":         "assertion.repository_id",
		"attribute.repository_owner_id":   "assertion.repository_owner_id",
		"attribute.ref":                   "assertion.ref",
		"attribute.workflow_ref":          "assertion.workflow_ref",
		"attribute.workflow_sha":          "assertion.workflow_sha",
		"attribute.environment":           "assertion.environment",
		"attribute.event_name":            "assertion.event_name",
		"attribute.repository_visibility": "assertion.repository_visibility",
		"attribute.runner_environment":    "assertion.runner_environment",
	}
	oidc := firstObject(after["oidc"])
	if !indexed || environment == "" || !exactStringMap(after["attribute_mapping"], expectedMapping) ||
		after["attribute_condition"] != bootstrapProviderCondition(github, environment, workflowRef) ||
		!exactStringSet(oidc["allowed_audiences"], []string{"sts.googleapis.com"}) {
		*violations = append(*violations, resource.Address+" must bind the exact immutable bootstrap custom subject, source SHA, protected workflow/environment, self-hosted runner, and organization-approved audience")
	}
}

func githubRepositorySubjectMapping(role string) string {
	return "'" + role + ":' + assertion.repository_id"
}

func validateWorkforceProviderClaims(resource resourceChange, after map[string]any, violations *[]string) {
	expectedMapping := map[string]string{
		"google.subject":      "assertion.sub",
		"google.display_name": "assertion.name",
		"google.groups":       "assertion.groups",
	}
	condition, _ := after["attribute_condition"].(string)
	conditionPattern := regexp.MustCompile(`^assertion\.groups\.exists\(group, group == '([^']+)'\)$`)
	matches := conditionPattern.FindStringSubmatch(condition)
	if !exactStringMap(after["attribute_mapping"], expectedMapping) || len(matches) != 2 || strings.TrimSpace(matches[1]) == "" || strings.Contains(matches[1], "*") {
		*violations = append(*violations, resource.Address+" must map the exact workforce claims and require one explicit administrator group")
	}
	oidc, _ := singleObject(after["oidc"])
	webSSO, ok := singleObject(oidc["web_sso_config"])
	if !ok || webSSO["response_type"] != "CODE" || webSSO["assertion_claims_behavior"] != "MERGE_USER_INFO_OVER_ID_TOKEN_CLAIMS" ||
		!exactStringSet(webSSO["additional_scopes"], []string{"groups"}) {
		*violations = append(*violations, resource.Address+" must use the exact code-flow workforce SSO contract")
	}
}

func exactStringMap(value any, expected map[string]string) bool {
	actual, ok := value.(map[string]any)
	if !ok || len(actual) != len(expected) {
		return false
	}
	for key, expectedValue := range expected {
		if actual[key] != expectedValue {
			return false
		}
	}
	return true
}

func parseExactClaimConjunction(condition string) (map[string]string, bool) {
	parts := strings.Split(condition, " && ")
	if len(parts) == 0 {
		return nil, false
	}
	predicate := regexp.MustCompile(`^assertion\.([a-z_]+) == '((?:\\.|[^'])+)'$`)
	claims := map[string]string{}
	for _, part := range parts {
		matches := predicate.FindStringSubmatch(part)
		if len(matches) != 3 || strings.TrimSpace(matches[2]) == "" || strings.Contains(matches[2], "*") || claims[matches[1]] != "" {
			return nil, false
		}
		claims[matches[1]] = matches[2]
	}
	return claims, true
}

func validateFederationClaimGraph(resources []resourceChange, violations *[]string) {
	providerClaims := map[string]map[string]string{}
	for _, resource := range resources {
		if resource.Type != "google_iam_workload_identity_pool_provider" {
			continue
		}
		base := resource.Address
		if index := strings.IndexByte(base, '['); index >= 0 {
			base = base[:index]
		}
		key := ""
		switch base {
		case "module.github_federation.google_iam_workload_identity_pool_provider.github":
			instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
			if indexed {
				key = "github:" + instance
			}
		case "module.buildkite_federation.google_iam_workload_identity_pool_provider.buildkite":
			key = "buildkite"
		case "module.gitops_federation.google_iam_workload_identity_pool_provider.gitops":
			key = "gitops"
		}
		if key == "" {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		condition, _ := after["attribute_condition"].(string)
		claims, ok := parseExactClaimConjunction(condition)
		if ok {
			providerClaims[key] = claims
		}
	}

	for _, resource := range resources {
		if resource.Type != "google_service_account_iam_member" {
			continue
		}
		base := resource.Address
		if index := strings.IndexByte(base, '['); index >= 0 {
			base = base[:index]
		}
		var providerKey, poolID, attribute, claim string
		switch base {
		case "module.github_federation.google_service_account_iam_member.github":
			instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
			if !indexed {
				continue
			}
			after, _ := resource.Change.After.(map[string]any)
			member, _ := after["member"].(string)
			if member == "" && topLevelUnknown(resource.Change.AfterUnknown, "member") {
				continue
			}
			pattern := regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/bootstrap-github-` + regexp.QuoteMeta(instance) + `/attribute\.repository_id/1350991612$`)
			if !pattern.MatchString(member) {
				*violations = append(*violations, resource.Address+" principalSet must bind only the exact bootstrap repository ID")
			}
			continue
		case "module.github_federation.google_service_account_iam_member.ci_evidence":
			instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
			if !indexed || (instance != "writer" && instance != "verifier") {
				continue
			}
			after, _ := resource.Change.After.(map[string]any)
			member, _ := after["member"].(string)
			if member == "" && topLevelUnknown(resource.Change.AfterUnknown, "member") {
				continue
			}
			pattern := regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/github-ci-evidence/attribute\.evidence_role/` + regexp.QuoteMeta(instance) + `$`)
			if !pattern.MatchString(member) {
				*violations = append(*violations, resource.Address+" principalSet must bind only its static CI-evidence provider role")
			}
			continue
		case "module.github_federation.google_service_account_iam_member.github_config":
			instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
			if !indexed || !stringSet("plan", "apply")[instance] {
				continue
			}
			after, _ := resource.Change.After.(map[string]any)
			member, _ := after["member"].(string)
			if member == "" && topLevelUnknown(resource.Change.AfterUnknown, "member") {
				continue
			}
			pattern := regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/github-config/attribute\.github_config_identity/` + regexp.QuoteMeta(instance) + `$`)
			if !pattern.MatchString(member) {
				*violations = append(*violations, resource.Address+" principalSet must bind only its provider-owned github-config identity")
			}
			continue
		case "module.github_federation.google_service_account_iam_member.infrastructure_live":
			instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
			if !indexed || !stringSet(
				"development-plan", "development-apply", "staging-plan", "staging-apply",
				"production-plan", "production-apply", "restricted-plan", "restricted-apply",
			)[instance] {
				continue
			}
			after, _ := resource.Change.After.(map[string]any)
			member, _ := after["member"].(string)
			if member == "" && topLevelUnknown(resource.Change.AfterUnknown, "member") {
				continue
			}
			pattern := regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/infrastructure-live/attribute\.infrastructure_identity/` + regexp.QuoteMeta(instance) + `$`)
			if !pattern.MatchString(member) {
				*violations = append(*violations, resource.Address+" principalSet must bind only its static infrastructure-live environment/role identity")
			}
			continue
		case "module.github_federation.google_service_account_iam_member.infrastructure_drift":
			instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
			if !indexed || instance != "drift" {
				continue
			}
			after, _ := resource.Change.After.(map[string]any)
			member, _ := after["member"].(string)
			if member == "" && topLevelUnknown(resource.Change.AfterUnknown, "member") {
				continue
			}
			pattern := regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/infrastructure-live/attribute\.infrastructure_identity/drift-plan$`)
			if !pattern.MatchString(member) {
				*violations = append(*violations, resource.Address+" principalSet must bind only the exact infrastructure drift identity")
			}
			continue
		case "module.buildkite_federation.google_service_account_iam_member.buildkite":
			providerKey, poolID, attribute, claim = "buildkite", "bootstrap-buildkite", "pipeline_id", "pipeline_id"
		case "module.gitops_federation.google_service_account_iam_member.gitops":
			providerKey, poolID, attribute, claim = "gitops", "bootstrap-gitops", "repository", "repository"
		default:
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		member, _ := after["member"].(string)
		if member == "" && topLevelUnknown(resource.Change.AfterUnknown, "member") {
			continue
		}
		claimValue := providerClaims[providerKey][claim]
		pattern := regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/` +
			regexp.QuoteMeta(poolID) + `/attribute\.` + regexp.QuoteMeta(attribute) + `/` + regexp.QuoteMeta(claimValue) + `$`)
		if claimValue == "" || !pattern.MatchString(member) {
			*violations = append(*violations, resource.Address+" principalSet must exactly match its provider's immutable condition literal")
		}
	}
}

func validateWorkforceSecretRevision(resource resourceChange, after map[string]any, violations *[]string) {
	if resource.Address != "module.workforce_identity.google_iam_workforce_pool_provider.oidc" {
		return
	}
	revision, ok := workforceSecretRevision(after)
	if !ok || revision < 1 {
		*violations = append(*violations, resource.Address+" must declare a positive integer write-only client-secret revision")
		return
	}
	if strings.Join(resource.Change.Actions, ",") != "update" {
		return
	}
	before, beforeOK := resource.Change.Before.(map[string]any)
	previous, previousOK := workforceSecretRevision(before)
	if !beforeOK || !previousOK || revision <= previous {
		*violations = append(*violations, resource.Address+" write-only client-secret revision must increase on every provider update")
	}
}

func workforceSecretRevision(value map[string]any) (uint64, bool) {
	oidc, ok := singleObject(value["oidc"])
	if !ok {
		return 0, false
	}
	clientSecret, ok := singleObject(oidc["client_secret"])
	if !ok {
		return 0, false
	}
	secretValue, ok := singleObject(clientSecret["value"])
	if !ok {
		return 0, false
	}
	switch revision := secretValue["plain_text_wo_version"].(type) {
	case string:
		if !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(revision) {
			return 0, false
		}
		parsed, err := strconv.ParseUint(revision, 10, 64)
		return parsed, err == nil
	case float64:
		if revision < 1 || revision != float64(uint64(revision)) {
			return 0, false
		}
		return uint64(revision), true
	default:
		return 0, false
	}
}

func validateAuditLogBucket(resource resourceChange, after map[string]any, violations *[]string) {
	base := "module.audit_root.google_logging_project_bucket_config.audit"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	locations := map[string]string{"primary": "us-central1", "recovery": "us-east4"}
	bucketIDs := map[string]string{"primary": "bootstrap-audit-primary", "recovery": "bootstrap-audit-recovery"}
	if !indexed || locations[instance] == "" {
		*violations = append(*violations, resource.Address+" is outside the primary/recovery audit bucket instances")
		return
	}
	project, _ := after["project"].(string)
	bucketID, _ := after["bucket_id"].(string)
	if !googleProjectIDPattern.MatchString(project) || topLevelUnknown(resource.Change.AfterUnknown, "project") || bucketID != bucketIDs[instance] {
		*violations = append(*violations, resource.Address+" must use its exact compiler-declared audit project and bucket ID")
	}
	requireEqual(after, "location", locations[instance], resource.Address, violations)
	requireEqual(after, "retention_days", float64(2555), resource.Address, violations)
	validateAuditBucketLockTransition(resource, after, violations)
	requireEqual(after, "deletion_policy", "PREVENT", resource.Address, violations)
	cmek, ok := singleObject(after["cmek_settings"])
	kmsKey, known := cmek["kms_key_name"].(string)
	if !ok || ((!known || kmsKey == "") && !nestedUnknown(resource.Change.AfterUnknown, "cmek_settings", "kms_key_name")) {
		*violations = append(*violations, resource.Address+" must use one known or computed audit-bucket CMEK")
	}
}

func validateAuditBucketLockTransition(resource resourceChange, after map[string]any, violations *[]string) {
	locked, known := after["locked"].(bool)
	if !known || topLevelUnknown(resource.Change.AfterUnknown, "locked") {
		*violations = append(*violations, resource.Address+" audit retention lock state must be explicit")
		return
	}
	actions := strings.Join(resource.Change.Actions, ",")
	before, beforeKnown := resource.Change.Before.(map[string]any)
	beforeLocked, beforeLockKnown := before["locked"].(bool)
	if beforeKnown && !beforeLockKnown {
		*violations = append(*violations, resource.Address+" audit retention prior lock state must be explicit")
		return
	}
	if actions == "create" {
		if locked {
			*violations = append(*violations, resource.Address+" audit retention may not be created already locked")
		}
		return
	}
	if beforeLockKnown && beforeLocked && !locked {
		*violations = append(*violations, resource.Address+" audit retention lock must never transition from true to false")
		return
	}
	if resource.auditLock.declared {
		if locked != resource.auditLock.locked {
			*violations = append(*violations, resource.Address+" audit retention lock must equal the compiled qualification declaration")
		}
		if actions == "update" && (!resource.auditLock.locked || !beforeLockKnown || beforeLocked || !locked) {
			*violations = append(*violations, resource.Address+" audit lock update must be the one-way reviewed false-to-true transition")
		}
		if (actions == "no-op" || actions == "read") && locked && (!beforeLockKnown || !beforeLocked) {
			*violations = append(*violations, resource.Address+" locked audit retention no-op must prove the prior state was already locked")
		}
		return
	}
	// Resource-level diagnostic fixtures predate the root variable contract;
	// they may only exercise the safe, unlocked state.
	if locked {
		*violations = append(*violations, resource.Address+" locked audit retention requires compiled qualification evidence")
	}
}

func validateAuditOrganizationSink(resource resourceChange, after map[string]any, violations *[]string) {
	base := "module.audit_root.google_logging_organization_sink.audit"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	type sinkContract struct {
		name     string
		filter   string
		location string
	}
	contracts := map[string]sinkContract{
		"admin-activity":           {name: "bootstrap-admin-activity", filter: `log_id("cloudaudit.googleapis.com/activity")`, location: "us-central1"},
		"admin-activity-recovery":  {name: "bootstrap-admin-activity-recovery", filter: `log_id("cloudaudit.googleapis.com/activity")`, location: "us-east4"},
		"data-access":              {name: "bootstrap-data-access", filter: `log_id("cloudaudit.googleapis.com/data_access") AND protoPayload.serviceName="storage.googleapis.com"`, location: "us-central1"},
		"data-access-recovery":     {name: "bootstrap-data-access-recovery", filter: `log_id("cloudaudit.googleapis.com/data_access") AND protoPayload.serviceName="storage.googleapis.com"`, location: "us-east4"},
		"security-events":          {name: "bootstrap-security-events", filter: `severity>=WARNING OR protoPayload.serviceName="iam.googleapis.com"`, location: "us-central1"},
		"security-events-recovery": {name: "bootstrap-security-events-recovery", filter: `severity>=WARNING OR protoPayload.serviceName="iam.googleapis.com"`, location: "us-east4"},
	}
	bucketIDs := map[string]string{
		"admin-activity":           "bootstrap-audit-primary",
		"admin-activity-recovery":  "bootstrap-audit-recovery",
		"data-access":              "bootstrap-audit-primary",
		"data-access-recovery":     "bootstrap-audit-recovery",
		"security-events":          "bootstrap-audit-primary",
		"security-events-recovery": "bootstrap-audit-recovery",
	}
	contract, ok := contracts[instance]
	if !indexed || !ok {
		*violations = append(*violations, resource.Address+" is outside the six exact organization audit sinks")
		return
	}
	requireEqual(after, "name", contract.name, resource.Address, violations)
	requireEqual(after, "filter", contract.filter, resource.Address, violations)
	requireEqual(after, "include_children", true, resource.Address, violations)
	requireEqual(after, "intercept_children", false, resource.Address, violations)
	if !plannedUnset(after["unique_writer_identity"]) || topLevelUnknown(resource.Change.AfterUnknown, "unique_writer_identity") {
		*violations = append(*violations, resource.Address+" must not configure the unsupported unique_writer_identity argument")
	}
	requireEqual(after, "deletion_policy", "PREVENT", resource.Address, violations)
	requireEqual(after, "disabled", false, resource.Address, violations)
	if !exactEmptyCollection(after["exclusions"]) || nestedUnknown(resource.Change.AfterUnknown, "exclusions") {
		*violations = append(*violations, resource.Address+" must have an explicit empty exclusions list")
	}
	orgID, _ := after["org_id"].(string)
	if !numericIDPattern.MatchString(orgID) || topLevelUnknown(resource.Change.AfterUnknown, "org_id") {
		*violations = append(*violations, resource.Address+" must aggregate one explicit organization")
	}
	destination, _ := after["destination"].(string)
	if destination == "" && topLevelUnknown(resource.Change.AfterUnknown, "destination") {
		return
	}
	parts := strings.Split(destination, "/")
	if len(parts) != 7 || parts[0] != "logging.googleapis.com" || parts[1] != "projects" ||
		!googleProjectIDPattern.MatchString(parts[2]) || parts[3] != "locations" || parts[4] != contract.location ||
		parts[5] != "buckets" || parts[6] != bucketIDs[instance] {
		*violations = append(*violations, resource.Address+" destination must be its exact protected regional logging bucket")
	}
}

func exactEmptyCollection(value any) bool {
	switch collection := value.(type) {
	case []any:
		return len(collection) == 0
	case map[string]any:
		return len(collection) == 0
	default:
		return false
	}
}

func validatePAMEntitlement(resource resourceChange, after map[string]any, violations *[]string) {
	base := "module.break_glass.google_privileged_access_manager_entitlement.break_glass"
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	expectedRoles := map[string][]string{
		"root-trust-administration":    {"roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin"},
		"signing-root-administration":  {"roles/cloudkms.admin"},
		"identity-root-administration": {"roles/iam.serviceAccountAdmin", "roles/iam.workloadIdentityPoolAdmin", "roles/resourcemanager.projectIamAdmin", "roles/serviceusage.serviceUsageAdmin"},
		"recovery-root-administration": {"roles/cloudkms.admin", "roles/iam.roleAdmin", "roles/iam.serviceAccountAdmin", "roles/logging.admin", "roles/resourcemanager.projectIamAdmin", "roles/serviceusage.serviceUsageAdmin", "roles/storage.admin", "roles/storagetransfer.user"},
	}
	roles, exactInstance := expectedRoles[instance]
	if !indexed || !exactInstance {
		*violations = append(*violations, resource.Address+" is outside the four exact break-glass entitlements")
		return
	}
	requireEqual(after, "entitlement_id", instance, resource.Address, violations)
	requireEqual(after, "location", "global", resource.Address, violations)
	requireEqual(after, "max_request_duration", "7200s", resource.Address, violations)
	requireEqual(after, "deletion_policy", "PREVENT", resource.Address, violations)
	parent, _ := after["parent"].(string)
	if !strings.HasPrefix(parent, "projects/") || !googleProjectIDPattern.MatchString(strings.TrimPrefix(parent, "projects/")) {
		*violations = append(*violations, resource.Address+" must target one explicit project parent")
	}

	justification, justificationOK := singleObject(after["requester_justification_config"])
	_, unstructuredOK := singleObject(justification["unstructured"])
	if !justificationOK || !unstructuredOK {
		*violations = append(*violations, resource.Address+" must require an unstructured requester justification")
	}

	eligible, eligibleOK := singleObject(after["eligible_users"])
	requesters, requestersOK := explicitUserSet(eligible["principals"])
	if !eligibleOK || !requestersOK || len(requesters) < 2 {
		*violations = append(*violations, resource.Address+" must name at least two explicit human requesters")
	}

	privileged, privilegedOK := singleObject(after["privileged_access"])
	gcpIAM, gcpIAMOK := singleObject(privileged["gcp_iam_access"])
	projectID := strings.TrimPrefix(parent, "projects/")
	if !privilegedOK || !gcpIAMOK || gcpIAM["resource"] != "//cloudresourcemanager.googleapis.com/projects/"+projectID ||
		gcpIAM["resource_type"] != "cloudresourcemanager.googleapis.com/Project" {
		*violations = append(*violations, resource.Address+" privileged access must target only its declared project")
	}
	var actualRoles []string
	if bindings, ok := gcpIAM["role_bindings"].([]any); ok {
		for _, value := range bindings {
			binding, ok := value.(map[string]any)
			role, roleOK := binding["role"].(string)
			if !ok || !roleOK {
				actualRoles = nil
				break
			}
			actualRoles = append(actualRoles, role)
		}
	}
	roleValues := make([]any, 0, len(actualRoles))
	for _, role := range actualRoles {
		roleValues = append(roleValues, role)
	}
	if !exactStringSet(roleValues, roles) {
		*violations = append(*violations, resource.Address+" must grant exactly its compiler-approved emergency role set")
	}

	workflow, workflowOK := singleObject(after["approval_workflow"])
	manual, manualOK := singleObject(workflow["manual_approvals"])
	steps, stepsOK := manual["steps"].([]any)
	approverSet := map[string]bool{}
	var approvalRecipientLists [][]any
	if !workflowOK || !manualOK || manual["require_approver_justification"] != true || !stepsOK || len(steps) != 2 {
		*violations = append(*violations, resource.Address+" must require two justified manual approval steps")
	} else {
		for _, value := range steps {
			step, ok := value.(map[string]any)
			approvers, approversOK := singleObject(step["approvers"])
			principals, principalsOK := explicitUserSet(approvers["principals"])
			if !ok || !approversOK || !principalsOK || len(principals) == 0 || step["approvals_needed"] != float64(1) {
				*violations = append(*violations, resource.Address+" each approval step must require one explicit human approver")
				continue
			}
			for principal := range principals {
				if approverSet[principal] {
					*violations = append(*violations, resource.Address+" approval-step principal sets must be disjoint")
				}
				approverSet[principal] = true
			}
			recipients, recipientsOK := step["approver_email_recipients"].([]any)
			if !recipientsOK || !explicitEmailList(recipients) {
				*violations = append(*violations, resource.Address+" each approval step must notify all explicit approvers")
			}
			approvalRecipientLists = append(approvalRecipientLists, recipients)
		}
	}
	if len(approverSet) < 2 {
		*violations = append(*violations, resource.Address+" must use at least two independent approvers")
	}
	for requester := range requesters {
		if approverSet[requester] {
			*violations = append(*violations, resource.Address+" requester and approver identities must be disjoint")
		}
	}
	expectedApproverEmails := map[string]bool{}
	for principal := range approverSet {
		expectedApproverEmails[strings.TrimPrefix(principal, "user:")] = true
	}
	for _, recipients := range approvalRecipientLists {
		if !exactEmailSet(recipients, expectedApproverEmails) {
			*violations = append(*violations, resource.Address+" approval recipient list must exactly match the declared approvers")
		}
	}

	notifications, ok := singleObject(after["additional_notification_targets"])
	adminRecipients, adminOK := notifications["admin_email_recipients"].([]any)
	requesterRecipients, requesterOK := notifications["requester_email_recipients"].([]any)
	if !ok || !adminOK || !requesterOK || !explicitEmailList(adminRecipients) || !explicitEmailList(requesterRecipients) ||
		!exactEmailSet(requesterRecipients, emailSet(adminRecipients)) {
		*violations = append(*violations, resource.Address+" must notify explicit independent security recipients")
	}
}

func emailSet(values []any) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		if email, ok := value.(string); ok {
			result[email] = true
		}
	}
	return result
}

func exactEmailSet(values []any, expected map[string]bool) bool {
	if len(values) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		email, ok := value.(string)
		if !ok || !expected[email] || seen[email] {
			return false
		}
		seen[email] = true
	}
	return true
}

func explicitUserSet(value any) (map[string]bool, bool) {
	values, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := map[string]bool{}
	for _, value := range values {
		principal, ok := value.(string)
		if !ok || !strings.HasPrefix(principal, "user:") || !emailPrincipalPattern.MatchString(principal) || result[principal] {
			return nil, false
		}
		result[principal] = true
	}
	return result, true
}

func explicitEmailList(value any) bool {
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		email, ok := value.(string)
		if !ok || !canonicalEmailPattern.MatchString(email) || seen[email] {
			return false
		}
		seen[email] = true
	}
	return true
}

func validateIndexedIAMAddressContract(resource resourceChange, after map[string]any, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
	role, _ := after["role"].(string)
	member, _ := after["member"].(string)

	switch base {
	case "google_organization_iam_member.plan_read", "google_organization_iam_member.plan_workforce_viewer",
		"google_organization_iam_member.recovery_sink_read", "google_organization_iam_member.apply_iam",
		"google_organization_iam_member.apply_logging_config_writer",
		"google_organization_iam_member.apply_organization_role_admin", "google_organization_iam_member.apply_workforce_admin":
		orgID, _ := after["org_id"].(string)
		if !numericIDPattern.MatchString(orgID) {
			*violations = append(*violations, resource.Address+" must target one explicit organization")
		}
		validPrincipal := bootstrapPlanPrincipalPattern.MatchString(member)
		principalDescription := "compiler-derived bootstrap identity"
		if strings.Contains(base, ".recovery_") {
			validPrincipal = bootstrapRecoveryPrincipalPattern.MatchString(member)
		} else if strings.Contains(base, ".apply_") {
			validPrincipal = groupEmailPrincipalPattern.MatchString(member)
			principalDescription = "independent named root-administrator group, never bootstrap-apply"
		}
		if !validPrincipal || topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must bind only its "+principalDescription)
		}
		customRoleID := ""
		switch base {
		case "google_organization_iam_member.plan_read":
			customRoleID = organizationPlanReadRoleContract.roleID
		case "google_organization_iam_member.recovery_sink_read":
			customRoleID = recoverySinkReadRoleContract.roleID
		case "google_organization_iam_member.apply_iam":
			customRoleID = organizationIAMApplyRoleContract.roleID
		}
		if customRoleID != "" && role != fmt.Sprintf("organizations/%s/roles/%s", orgID, customRoleID) {
			*violations = append(*violations, resource.Address+" must bind its custom role from the same exact organization")
		}
		if !plannedUnset(after["condition"]) || nestedUnknown(resource.Change.AfterUnknown, "condition") {
			*violations = append(*violations, resource.Address+" must remain an unconditional exact organization binding")
		}
	case "google_project_iam_member.apply_administration", "google_project_iam_member.plan_read":
		parts := strings.SplitN(instance, ":", 2)
		if !indexed || len(parts) != 2 || role != parts[1] {
			*violations = append(*violations, resource.Address+" role must exactly match its approved project-role instance")
		}
		project, _ := after["project"].(string)
		if !googleProjectIDPattern.MatchString(project) {
			*violations = append(*violations, resource.Address+" must target one explicit project")
		}
		expectedPrincipal := bootstrapApplyPrincipalPattern
		if base == "google_project_iam_member.plan_read" {
			expectedPrincipal = bootstrapPlanPrincipalPattern
		}
		if !expectedPrincipal.MatchString(member) || topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must bind only its compiler-derived bootstrap identity")
		}
	case "module.audit_root.google_project_iam_member.sink_writer":
		if !indexed || role != "roles/logging.bucketWriter" {
			*violations = append(*violations, resource.Address+" must be an exact audit-sink writer instance")
		}
		project, _ := after["project"].(string)
		if !googleProjectIDPattern.MatchString(project) {
			*violations = append(*violations, resource.Address+" sink writer must target one explicit destination project")
		}
		if member != "" && !auditSinkWriterPrincipalPattern.MatchString(member) {
			*violations = append(*violations, resource.Address+" must bind only the sink's generated service account")
		}
		condition, ok := singleObject(after["condition"])
		location := map[string]string{"primary": "us-central1", "recovery": "us-east4"}[instance]
		bucketID := map[string]string{"primary": "bootstrap-audit-primary", "recovery": "bootstrap-audit-recovery"}[instance]
		expectedTitle := "bootstrap-audit-" + instance + "-bucket-only"
		expectedExpression := fmt.Sprintf("resource.type == 'logging.googleapis.com/LogBucket' && resource.name == 'projects/%s/locations/%s/buckets/%s'", project, location, bucketID)
		if !ok || nestedUnknown(resource.Change.AfterUnknown, "condition") || condition["title"] != expectedTitle || condition["expression"] != expectedExpression {
			*violations = append(*violations, resource.Address+" must condition the shared sink writer on its exact protected audit bucket")
		}
	case "module.audit_root.google_project_iam_member.reader":
		parts := strings.SplitN(instance, ":", 2)
		project, _ := after["project"].(string)
		bucketKey := ""
		if len(parts) == 2 {
			bucketKey = parts[0]
		}
		location := map[string]string{"primary": "us-central1", "recovery": "us-east4"}[bucketKey]
		bucketID := map[string]string{"primary": "bootstrap-audit-primary", "recovery": "bootstrap-audit-recovery"}[bucketKey]
		condition, conditionOK := singleObject(after["condition"])
		expectedTitle := "bootstrap-audit-" + bucketKey + "-all-logs-view"
		expectedExpression := fmt.Sprintf("resource.name == 'projects/%s/locations/%s/buckets/%s/views/_AllLogs'", project, location, bucketID)
		validReaderPrincipal := groupEmailPrincipalPattern.MatchString(member) || bootstrapRecoveryPrincipalPattern.MatchString(member)
		if !indexed || len(parts) != 2 || member != parts[1] || !validReaderPrincipal || role != "roles/logging.viewAccessor" ||
			location == "" || !conditionOK || nestedUnknown(resource.Change.AfterUnknown, "condition") || condition["title"] != expectedTitle || condition["expression"] != expectedExpression {
			*violations = append(*violations, resource.Address+" reader must bind one canonical group or the exact recovery identity to only its exact audit-bucket _AllLogs view")
		}
	case "module.audit_root.google_project_iam_member.administrator":
		parts := strings.SplitN(instance, ":", 2)
		project, _ := after["project"].(string)
		if !indexed || len(parts) != 2 || role != parts[0] || member != parts[1] || !googleProjectIDPattern.MatchString(project) {
			*violations = append(*violations, resource.Address+" administrator fields must exactly match its role-principal instance")
		}
	case "module.audit_root.google_project_iam_member.plan_read":
		project, _ := after["project"].(string)
		expectedRole := fmt.Sprintf("projects/%s/roles/%s", project, auditPlanReadRoleContract.roleID)
		if !indexed || (instance != "primary" && instance != "recovery") || role != expectedRole ||
			!bootstrapPlanPrincipalPattern.MatchString(member) || topLevelUnknown(resource.Change.AfterUnknown, "member") || !googleProjectIDPattern.MatchString(project) {
			*violations = append(*violations, resource.Address+" must bind the exact audit configuration-read role to bootstrap-plan")
		}
		if !plannedUnset(after["condition"]) || nestedUnknown(resource.Change.AfterUnknown, "condition") {
			*violations = append(*violations, resource.Address+" audit configuration-read binding must remain unconditional")
		}
	case "module.signing_root.google_kms_key_ring_iam_member.administrator":
		if !indexed || member != instance || role != "roles/cloudkms.admin" || !explicitPrincipal(member) {
			*violations = append(*violations, resource.Address+" signing administrator must exactly match its explicit principal instance")
		}
		if !plannedUnset(after["condition"]) || nestedUnknown(resource.Change.AfterUnknown, "condition") {
			*violations = append(*violations, resource.Address+" signing key-ring administration must remain unconditional")
		}
		keyRingID, known := after["key_ring_id"].(string)
		if known && keyRingID != "" {
			if !canonicalSigningKeyRing(keyRingID) || topLevelUnknown(resource.Change.AfterUnknown, "key_ring_id") {
				*violations = append(*violations, resource.Address+" must target the canonical bootstrap-signing key ring")
			}
		} else if strings.Join(resource.Change.Actions, ",") != "create" || !topLevelUnknown(resource.Change.AfterUnknown, "key_ring_id") {
			*violations = append(*violations, resource.Address+" must use a known key-ring ID except for its exact initial-create dependency")
		}
	case "module.signing_root.google_kms_crypto_key_iam_member.signer":
		validateSigningIAMCondition(resource, after, instance, indexed, violations)
	case "module.github_federation.google_service_account_iam_member.github":
		validateFederationServiceAccountBinding(resource, after, instance, indexed, "attribute.repository_id", violations)
	case "module.github_federation.google_service_account_iam_member.ci_evidence":
		validateFederationServiceAccountBinding(resource, after, instance, indexed, "attribute.evidence_role", violations)
	case "module.github_federation.google_service_account_iam_member.github_config":
		validateFederationServiceAccountBinding(resource, after, instance, indexed, "attribute.github_config_identity", violations)
	case "module.github_federation.google_service_account_iam_member.infrastructure_live":
		validateFederationServiceAccountBinding(resource, after, instance, indexed, "attribute.infrastructure_identity", violations)
	case "module.github_federation.google_service_account_iam_member.infrastructure_drift":
		validateFederationServiceAccountBinding(resource, after, "infrastructure-plan", indexed && instance == "drift", "attribute.infrastructure_identity", violations)
	case "module.buildkite_federation.google_service_account_iam_member.buildkite":
		validateFederationServiceAccountBinding(resource, after, "buildkite-bootstrap", true, "attribute.pipeline_id", violations)
	case "module.gitops_federation.google_service_account_iam_member.gitops":
		validateFederationServiceAccountBinding(resource, after, "gitops-bootstrap", true, "attribute.repository", violations)
	}
}

func validateFederationServiceAccountBinding(resource resourceChange, after map[string]any, instance string, indexed bool, attribute string, violations *[]string) {
	expectedAccountID := instance
	base := resourceAddressBase(resource.Address)
	switch base {
	case "module.github_federation.google_service_account_iam_member.github":
		expectedAccountID = map[string]string{"plan": "bootstrap-plan", "apply": "bootstrap-apply", "recovery": "bootstrap-recovery"}[instance]
	case "module.github_federation.google_service_account_iam_member.ci_evidence":
		expectedAccountID = map[string]string{"writer": "ci-evidence-writer", "verifier": "ci-evidence-verifier"}[instance]
	case "module.github_federation.google_service_account_iam_member.github_config":
		expectedAccountID = map[string]string{"plan": "github-config-plan", "apply": "github-config-apply"}[instance]
	}
	serviceAccountID, _ := after["service_account_id"].(string)
	parts := strings.Split(serviceAccountID, "/")
	validServiceAccount := len(parts) == 4 && parts[0] == "projects" && googleProjectIDPattern.MatchString(parts[1]) &&
		parts[2] == "serviceAccounts" && parts[3] == expectedAccountID+"@"+parts[1]+".iam.gserviceaccount.com"
	if !indexed || !validServiceAccount || after["role"] != "roles/iam.workloadIdentityUser" {
		*violations = append(*violations, resource.Address+" must target its exact keyless bootstrap service account")
	}
	member, _ := after["member"].(string)
	if member == "" && topLevelUnknown(resource.Change.AfterUnknown, "member") {
		return
	}
	if !strings.HasPrefix(member, "principalSet://iam.googleapis.com/") || !strings.Contains(member, "/"+attribute+"/") || strings.Contains(member, "*") {
		*violations = append(*violations, resource.Address+" must bind only its immutable workload-identity attribute principal set")
	}
}

func validateSigningIAMCondition(resource resourceChange, after map[string]any, instance string, indexed bool, violations *[]string) {
	parts := strings.SplitN(instance, ":", 2)
	if !indexed || len(parts) != 2 || !stringSet(signingKeyNames...)[parts[0]] || after["role"] != "roles/cloudkms.signerVerifier" || after["member"] != parts[1] {
		*violations = append(*violations, resource.Address+" signer fields must exactly match its key-principal instance")
		return
	}
	keyContract, contractOK := signingKeyDeclaration(resource.signingContract, parts[0])
	if !contractOK {
		*violations = append(*violations, resource.Address+" cannot resolve its compiled signing declaration")
		return
	}
	activeRef := keyContract.activeVersionRef
	window := keyContract.versions[activeRef]
	expectedTitle := "sign-" + parts[0] + "-" + activeRef + "-within-window"
	if resource.initialSigningCreateProof {
		if !exactInitialSignerIAMEnvelope(resource, after, expectedTitle) {
			*violations = append(*violations, resource.Address+" initial-create signer unknowns must exactly match the reviewed active-version dependency envelope")
		}
		return
	}
	cryptoKeyID, _ := after["crypto_key_id"].(string)
	if !canonicalSigningCryptoKey(cryptoKeyID, parts[0]) || topLevelUnknown(resource.Change.AfterUnknown, "crypto_key_id") {
		*violations = append(*violations, resource.Address+" signer binding must target its canonical parent signing key")
	}
	condition, ok := singleObject(after["condition"])
	if !ok || nestedUnknown(resource.Change.AfterUnknown, "condition") {
		*violations = append(*violations, resource.Address+" signer binding must use one explicit active-version time-window condition")
		return
	}
	expression, _ := condition["expression"].(string)
	pattern := regexp.MustCompile(`^resource\.type == 'cloudkms\.googleapis\.com/CryptoKeyVersion' && resource\.name == '([^']+)' && request\.time >= timestamp\('([^']+)'\) && request\.time < timestamp\('([^']+)'\)$`)
	matches := pattern.FindStringSubmatch(expression)
	if condition["title"] != expectedTitle || len(matches) != 4 {
		*violations = append(*violations, resource.Address+" signer condition must bind the active version and exact activation window")
		return
	}
	versionNameParts := strings.Split(matches[1], "/")
	validVersionName := len(versionNameParts) == 10 && canonicalSigningCryptoKey(strings.Join(versionNameParts[:8], "/"), parts[0]) &&
		versionNameParts[8] == "cryptoKeyVersions" && numericIDPattern.MatchString(versionNameParts[9])
	start, startError := time.Parse(time.RFC3339, matches[2])
	deadline, deadlineError := time.Parse(time.RFC3339, matches[3])
	if !validVersionName || startError != nil || deadlineError != nil || deadline.Sub(start) != 90*24*time.Hour ||
		matches[2] != window.activationWindowStart || matches[3] != window.rotationDeadline {
		*violations = append(*violations, resource.Address+" signer condition must name the compiled active version with its exact 90-day window")
	}
}

func validateRecoverySigningMetadataBinding(resource resourceChange, after map[string]any, violations *[]string) {
	const address = "module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata"
	if resource.Type != "google_kms_crypto_key_iam_member" || resource.Address != address {
		return
	}
	member, _ := after["member"].(string)
	if !bootstrapRecoveryPrincipalPattern.MatchString(member) || topLevelUnknown(resource.Change.AfterUnknown, "member") {
		*violations = append(*violations, resource.Address+" must bind only the compiler-derived bootstrap-recovery identity")
	}
	if resource.initialSigningCreateProof {
		if !exactInitialRecoveryMetadataEnvelope(resource, after) {
			*violations = append(*violations, resource.Address+" initial-create recovery metadata unknowns must exactly match the reviewed active-version dependency envelope")
		}
		return
	}
	cryptoKey, _ := after["crypto_key_id"].(string)
	roleProject, roleID, roleOK := splitCustomRole(stringValue(after["role"]))
	keyParts := strings.Split(cryptoKey, "/")
	keyProject := ""
	if len(keyParts) == 8 {
		keyProject = keyParts[1]
	}
	if !canonicalSigningCryptoKey(cryptoKey, "recovery-evidence") || topLevelUnknown(resource.Change.AfterUnknown, "crypto_key_id") {
		*violations = append(*violations, resource.Address+" must target only the canonical recovery-evidence CryptoKey")
	}
	if !roleOK || roleID != recoverySigningMetadataRoleContract.roleID || roleProject != keyProject || topLevelUnknown(resource.Change.AfterUnknown, "role") {
		*violations = append(*violations, resource.Address+" must use the exact recovery signing-metadata role in the signing project")
	}
	condition, exact := singleObject(after["condition"])
	if !exact || nestedUnknown(resource.Change.AfterUnknown, "condition") {
		*violations = append(*violations, resource.Address+" must use one explicit recovery-evidence metadata condition")
		return
	}
	expression, _ := condition["expression"].(string)
	versionName, expressionOK := recoveryMetadataVersionName(expression, cryptoKey)
	if condition["title"] != "read-recovery-evidence-active-key-version-only" || !expressionOK || !canonicalSigningVersionName(versionName, cryptoKey) {
		*violations = append(*violations, resource.Address+" condition must allow only recovery-evidence key metadata and its active version metadata")
	}
}

func exactInitialSignerIAMEnvelope(resource resourceChange, after map[string]any, expectedTitle string) bool {
	condition, ok := singleObject(after["condition"])
	return len(after) == 3 && ok && len(condition) == 2 && condition["description"] == nil && condition["title"] == expectedTitle &&
		plannedUnset(condition["expression"]) && exactUnknownLeafSet(resource.Change.AfterUnknown, []string{
		"condition[0].expression", "crypto_key_id", "etag", "id",
	})
}

func exactInitialRecoveryMetadataEnvelope(resource resourceChange, after map[string]any) bool {
	condition, ok := singleObject(after["condition"])
	roleProject, roleID, roleOK := splitCustomRole(stringValue(after["role"]))
	return len(after) == 3 && ok && len(condition) == 2 &&
		bootstrapRecoveryPrincipalPattern.MatchString(stringValue(after["member"])) &&
		roleOK && googleProjectIDPattern.MatchString(roleProject) && roleID == recoverySigningMetadataRoleContract.roleID &&
		condition["description"] == "Permit connected verification to inspect only the recovery-evidence key and its source-selected active version." &&
		condition["title"] == "read-recovery-evidence-active-key-version-only" && plannedUnset(condition["expression"]) &&
		exactUnknownLeafSet(resource.Change.AfterUnknown, []string{
			"condition[0].expression", "crypto_key_id", "etag", "id",
		})
}

func recoveryMetadataVersionName(expression, cryptoKey string) (string, bool) {
	pattern := regexp.MustCompile(`^\(resource\.type == 'cloudkms\.googleapis\.com/CryptoKey' && resource\.name == '([^']+)'\) \|\| \(resource\.type == 'cloudkms\.googleapis\.com/CryptoKeyVersion' && resource\.name == '([^']+)'\)$`)
	matches := pattern.FindStringSubmatch(expression)
	if len(matches) != 3 || matches[1] != cryptoKey {
		return "", false
	}
	return matches[2], true
}

func canonicalSigningVersionName(name, cryptoKey string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 10 && strings.Join(parts[:8], "/") == cryptoKey && parts[8] == "cryptoKeyVersions" && numericIDPattern.MatchString(parts[9])
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func validateSigningVersionGraph(resources []resourceChange, contract *signingContract, violations *[]string) {
	activeVersions := map[string]string{}
	activeParents := map[string]string{}
	for _, resource := range resources {
		keyName, versionRef, ok := declaredSigningVersionAddress(resource.Address, contract)
		if !ok || contract.keys[keyName].activeVersionRef != versionRef || resource.Type != "google_kms_crypto_key_version" {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		cryptoKey, _ := after["crypto_key"].(string)
		name, _ := after["name"].(string)
		if cryptoKey != "" {
			activeParents[keyName] = cryptoKey
		}
		if name != "" {
			activeVersions[keyName] = name
		}
	}
	for _, resource := range resources {
		const base = "module.signing_root.data.google_kms_crypto_key_version.active"
		keyName, indexed, valid := terraformAddressStringIndex(resource.Address, base)
		if resource.Mode != "data" || resource.Type != "google_kms_crypto_key_version" || !valid || !indexed {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		cryptoKey, _ := after["crypto_key"].(string)
		name, _ := after["name"].(string)
		if name != "" {
			if activeVersions[keyName] == "" || name != activeVersions[keyName] {
				*violations = append(*violations, resource.Address+" must resolve the managed version selected by activeVersionRef")
			}
		} else if cryptoKey != "" && (activeParents[keyName] == "" || cryptoKey != activeParents[keyName]) {
			*violations = append(*violations, resource.Address+" deferred read must use the managed active version's canonical parent key")
		}
	}
	for _, resource := range resources {
		const base = "module.signing_root.google_kms_crypto_key_iam_member.signer"
		instance, indexed, _ := terraformAddressStringIndex(resource.Address, base)
		if resource.Type != "google_kms_crypto_key_iam_member" || !indexed {
			continue
		}
		parts := strings.SplitN(instance, ":", 2)
		if len(parts) != 2 {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		keyContract, ok := signingKeyDeclaration(contract, parts[0])
		if !ok {
			continue
		}
		if resource.initialSigningCreateProof && exactInitialSignerIAMEnvelope(resource, after, "sign-"+parts[0]+"-"+keyContract.activeVersionRef+"-within-window") {
			continue
		}
		condition, _ := singleObject(after["condition"])
		expression, _ := condition["expression"].(string)
		activeVersion := activeVersions[parts[0]]
		if activeVersion == "" || !strings.Contains(expression, "resource.name == '"+activeVersion+"'") {
			*violations = append(*violations, resource.Address+" signer condition must reference the planned active CryptoKeyVersion resource")
		}
	}
	for _, resource := range resources {
		if resource.Address != "module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata" {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		if resource.initialSigningCreateProof && exactInitialRecoveryMetadataEnvelope(resource, after) {
			continue
		}
		condition, _ := singleObject(after["condition"])
		expression, _ := condition["expression"].(string)
		cryptoKey, _ := after["crypto_key_id"].(string)
		versionName, ok := recoveryMetadataVersionName(expression, cryptoKey)
		if !ok || activeVersions["recovery-evidence"] == "" || versionName != activeVersions["recovery-evidence"] {
			*violations = append(*violations, resource.Address+" condition must reference the planned active recovery-evidence CryptoKeyVersion")
		}
	}
}

func approvedUnknownBucketCMEK(resource resourceChange) bool {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	return resource.Type == "google_storage_bucket" && (base == "module.root_state.google_storage_bucket.state" ||
		base == "module.recovery_state.google_storage_bucket.state" ||
		base == "module.recovery_exports.google_storage_bucket.recovery")
}

func approvedStateBucketEncryptionUnknowns(resource resourceChange) bool {
	if !approvedUnknownBucketCMEK(resource) {
		return false
	}
	encryption, ok := singleObject(firstObject(resource.Change.AfterUnknown)["encryption"])
	if !ok || encryption["default_kms_key_name"] != true {
		return false
	}
	if len(encryption) == 1 {
		return true
	}
	if len(encryption) != 4 {
		return false
	}
	for _, key := range []string{
		"customer_managed_encryption_enforcement_config",
		"customer_supplied_encryption_enforcement_config",
		"google_managed_encryption_enforcement_config",
	} {
		values, valuesOK := encryption[key].([]any)
		if !valuesOK || len(values) != 0 {
			return false
		}
	}
	return true
}

func approvedStateBucketSoftDeleteUnknowns(resource resourceChange) bool {
	base := resourceAddressBase(resource.Address)
	if resource.Mode != "managed" || resource.Type != "google_storage_bucket" ||
		(base != "module.root_state.google_storage_bucket.state" && base != "module.recovery_state.google_storage_bucket.state") {
		return false
	}
	after, _ := resource.Change.After.(map[string]any)
	policy, policyOK := singleObject(after["soft_delete_policy"])
	unknownPolicy, unknownOK := singleObject(firstObject(resource.Change.AfterUnknown)["soft_delete_policy"])
	return policyOK && len(policy) == 1 && policy["retention_duration_seconds"] == float64(2592000) &&
		unknownOK && len(unknownPolicy) == 1 && unknownPolicy["effective_time"] == true
}

func approvedInitialAuditBucketServiceAccount(resource resourceChange) bool {
	return resource.Mode == "managed" && resource.Type == "google_logging_project_bucket_config" &&
		resourceAddressBase(resource.Address) == "module.audit_root.google_logging_project_bucket_config.audit" &&
		strings.Join(resource.Change.Actions, ",") == "create" &&
		nestedUnknown(resource.Change.AfterUnknown, "cmek_settings", "service_account_id")
}

func approvedInitialWorkforceSecretThumbprint(resource resourceChange) bool {
	if resource.Mode != "managed" || resource.Address != "module.workforce_identity.google_iam_workforce_pool_provider.oidc" ||
		strings.Join(resource.Change.Actions, ",") != "create" {
		return false
	}
	after, _ := resource.Change.After.(map[string]any)
	oidc, oidcOK := singleObject(after["oidc"])
	secret, secretOK := singleObject(oidc["client_secret"])
	value, valueOK := singleObject(secret["value"])
	_, revisionOK := workforceSecretRevision(after)
	unknownOIDC, unknownOIDCOK := singleObject(firstObject(resource.Change.AfterUnknown)["oidc"])
	unknownSecret, unknownSecretOK := singleObject(unknownOIDC["client_secret"])
	unknownValue, unknownValueOK := singleObject(unknownSecret["value"])
	return oidcOK && secretOK && valueOK && revisionOK && value["plain_text"] == nil && value["plain_text_wo"] == nil &&
		unknownOIDCOK && unknownSecretOK && unknownValueOK && len(unknownValue) == 1 && unknownValue["thumbprint"] == true
}

func approvedBinding(resourceType, address, role string) bool {
	base := address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	roles := func(allowed ...string) bool {
		for _, candidate := range allowed {
			if role == candidate {
				return true
			}
		}
		return false
	}
	switch resourceType {
	case "google_organization_iam_member":
		expected := map[string]string{
			"google_organization_iam_member.plan_workforce_viewer":         "roles/iam.workforcePoolViewer",
			"google_organization_iam_member.apply_logging_config_writer":   "roles/logging.configWriter",
			"google_organization_iam_member.apply_organization_role_admin": "roles/iam.organizationRoleAdmin",
			"google_organization_iam_member.apply_workforce_admin":         "roles/iam.workforcePoolAdmin",
		}
		if base == "google_organization_iam_member.plan_read" {
			return matchesOrganizationCustomRole(role, organizationPlanReadRoleContract.roleID)
		}
		if base == "google_organization_iam_member.recovery_sink_read" {
			return matchesOrganizationCustomRole(role, recoverySinkReadRoleContract.roleID)
		}
		if base == "google_organization_iam_member.apply_iam" {
			return matchesOrganizationCustomRole(role, organizationIAMApplyRoleContract.roleID)
		}
		return expected[base] == role
	case "google_project_iam_member":
		if contract, _, ok := replicationBindingContract(resourceType, address); ok {
			return matchesReplicationCustomRole(role, contract.roleID)
		}
		if contract, _, ok := recoveryStateExportBindingContract(resourceType, address); ok {
			return roleMatchesContract(role, contract)
		}
		if approvedRecoveryAdministrationBinding(address, role) {
			return true
		}
		if approvedReplicationPredefinedRole(address, role) {
			return true
		}
		switch base {
		case "google_project_iam_member.apply_administration":
			return approvedIndexedProjectRole(address, base, role)
		case "google_project_iam_member.plan_read":
			return approvedIndexedProjectRole(address, base, role)
		case "module.audit_root.google_project_iam_member.sink_writer":
			return role == "roles/logging.bucketWriter"
		case "module.audit_root.google_project_iam_member.reader":
			return role == "roles/logging.viewAccessor"
		case "module.audit_root.google_project_iam_member.plan_read":
			return matchesReplicationCustomRole(role, auditPlanReadRoleContract.roleID)
		case "module.audit_root.google_project_iam_member.administrator":
			return role == "roles/logging.configWriter"
		}
	case "google_kms_key_ring_iam_member":
		return base == "module.signing_root.google_kms_key_ring_iam_member.administrator" && role == "roles/cloudkms.admin"
	case "google_kms_crypto_key_iam_member":
		switch base {
		case "module.audit_root.google_kms_crypto_key_iam_member.logging",
			"module.recovery_exports.google_kms_crypto_key_iam_member.storage",
			"module.root_state.google_kms_crypto_key_iam_member.state_service_agent",
			"module.root_state.google_kms_crypto_key_iam_member.replica_service_agent",
			"module.recovery_state.google_kms_crypto_key_iam_member.state_service_agent",
			"module.recovery_state.google_kms_crypto_key_iam_member.replica_service_agent":
			return role == "roles/cloudkms.cryptoKeyEncrypterDecrypter"
		case "module.signing_root.google_kms_crypto_key_iam_member.signer":
			return role == "roles/cloudkms.signerVerifier"
		case "module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata":
			return roleMatchesContract(role, recoverySigningMetadataRoleContract)
		}
	case "google_service_account_iam_member":
		if contract, _, ok := recoveryStateExportBindingContract(resourceType, address); ok {
			return roleMatchesContract(role, contract)
		}
		return roles("roles/iam.workloadIdentityUser") && (base == "module.github_federation.google_service_account_iam_member.github" ||
			base == "module.github_federation.google_service_account_iam_member.ci_evidence" ||
			base == "module.github_federation.google_service_account_iam_member.github_config" ||
			base == "module.github_federation.google_service_account_iam_member.infrastructure_live" ||
			base == "module.github_federation.google_service_account_iam_member.infrastructure_drift" ||
			base == "module.buildkite_federation.google_service_account_iam_member.buildkite" ||
			base == "module.gitops_federation.google_service_account_iam_member.gitops")
	case "google_secret_manager_secret_iam_member":
		return base == "module.signing_root.google_secret_manager_secret_iam_member.nix_cache_accessor" && role == "roles/secretmanager.secretAccessor"
	case "google_storage_bucket_iam_member":
		if contract, _, ok := replicationBindingContract(resourceType, address); ok {
			return matchesReplicationCustomRole(role, contract.roleID)
		}
		if contract, _, ok := recoveryStateExportBindingContract(resourceType, address); ok {
			return roleMatchesContract(role, contract)
		}
		if approvedStateBackendAccess(address, role) || approvedRecoveryExportAccess(address, role) {
			return true
		}
		if recoveryPlanReadBinding(address) {
			return matchesReplicationCustomRole(role, recoveryPlanReadRoleContract.roleID)
		}
		if recoveryPlanObjectReadBinding(address) {
			return matchesReplicationCustomRole(role, recoveryPlanObjectReadRoleContract.roleID)
		}
	}
	return false
}

func approvedIndexedProjectRole(address, base, role string) bool {
	instance, indexed, valid := terraformAddressStringIndex(address, base)
	parts := strings.SplitN(instance, ":", 2)
	return valid && indexed && exactResourceAddressKeys[base][instance] && len(parts) == 2 && parts[1] == role
}

func exactReplicationAddress(address, suffix string) (string, string, bool) {
	for module, prefix := range replicationPrefixes {
		if address == module+"."+suffix {
			return module, prefix, true
		}
	}
	return "", "", false
}

func approvedReplicationPredefinedRole(address, role string) bool {
	roleResources := map[string]string{
		"roles/iam.roleAdmin":          "google_project_iam_member.apply_administration",
		"roles/iam.roleViewer":         "google_project_iam_member.plan_read",
		"roles/storagetransfer.user":   "google_project_iam_member.apply_administration",
		"roles/storagetransfer.viewer": "google_project_iam_member.plan_read",
	}
	resourceName, ok := roleResources[role]
	if !ok {
		return false
	}
	for _, projectKey := range []string{"state", "recovery"} {
		expected := fmt.Sprintf(`%s[%q]`, resourceName, projectKey+":"+role)
		if address == expected {
			return true
		}
	}
	return false
}

func approvedRecoveryAdministrationBinding(address, role string) bool {
	if !recoveryAdministrationRoles[role] {
		return false
	}
	expected := fmt.Sprintf(`google_project_iam_member.recovery_administration[%q]`, role)
	return address == expected
}

func validateRecoveryAdministration(resources []resourceChange, violations *[]string) {
	recoveryProjectID := ""
	for _, resource := range resources {
		if resource.Type != "google_project" || resource.Address != `google_project.state["recovery"]` {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		recoveryProjectID, _ = after["project_id"].(string)
	}

	seen := map[string]bool{}
	for _, resource := range resources {
		if resource.Type != "google_project_iam_member" ||
			!strings.HasPrefix(resource.Address, "google_project_iam_member.recovery_administration[") {
			continue
		}
		after, _ := resource.Change.After.(map[string]any)
		role, _ := after["role"].(string)
		if !approvedRecoveryAdministrationBinding(resource.Address, role) {
			*violations = append(*violations, resource.Address+" must use its exact recovery-administration role instance")
			continue
		}
		if seen[role] {
			*violations = append(*violations, resource.Address+" duplicates a recovery-administration role")
		}
		seen[role] = true
		project, _ := after["project"].(string)
		if recoveryProjectID == "" || project != recoveryProjectID {
			*violations = append(*violations, resource.Address+" must target only the declared recovery project")
		}
		member, _ := after["member"].(string)
		if !groupEmailPrincipalPattern.MatchString(member) {
			*violations = append(*violations, resource.Address+" must bind one explicit recovery-administrator group email")
		}
	}
	if len(seen) > 0 && len(seen) != len(recoveryAdministrationRoles) {
		*violations = append(*violations, "root-trust plans must contain the exact recovery-administration role set")
	}
}

func approvedStateBackendAccess(address, role string) bool {
	for module := range replicationPrefixes {
		for instance, expectedRole := range stateBackendAccessRoles {
			expectedAddress := fmt.Sprintf(`%s.google_storage_bucket_iam_member.backend_access[%q]`, module, instance)
			if address == expectedAddress {
				if expectedRole == "custom/"+statePlanLockRoleContract.roleID {
					return matchesReplicationCustomRole(role, statePlanLockRoleContract.roleID)
				}
				return role == expectedRole
			}
		}
	}
	return false
}

func stateBackendAccessContract(address string) (string, string, string, bool) {
	for module := range replicationPrefixes {
		for instance, role := range stateBackendAccessRoles {
			expectedAddress := fmt.Sprintf(`%s.google_storage_bucket_iam_member.backend_access[%q]`, module, instance)
			if address == expectedAddress {
				return module, instance, role, true
			}
		}
	}
	return "", "", "", false
}

func validateStateBackendAccessContract(resource resourceChange, after map[string]any, violations *[]string) {
	module, instance, _, ok := stateBackendAccessContract(resource.Address)
	if resource.Type != "google_storage_bucket_iam_member" || !ok {
		return
	}
	if strings.Contains(instance, "-plan-") {
		member, _ := after["member"].(string)
		if !bootstrapPlanPrincipalPattern.MatchString(member) || topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must bind the exact bootstrap-plan service account")
		}
	} else if strings.Contains(instance, "-apply") {
		member, _ := after["member"].(string)
		expected := bootstrapApplyPrincipalPattern.MatchString(member)
		if module == "module.recovery_state" {
			expected = groupEmailPrincipalPattern.MatchString(member)
		}
		if !expected || topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must bind the root apply identity or independent recovery-administrator group selected for that backend")
		}
	} else if strings.Contains(instance, "-recovery") {
		member, _ := after["member"].(string)
		if !bootstrapRecoveryPrincipalPattern.MatchString(member) || topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must bind the exact bootstrap-recovery service account")
		}
	}
	conditionRequired := instance == "primary-plan-state" || instance == "replica-plan-state" ||
		instance == "primary-plan-lock" || instance == "primary-apply" || instance == "primary-recovery" || instance == "replica-recovery"
	if !conditionRequired {
		if !plannedUnset(after["condition"]) || nestedUnknown(resource.Change.AfterUnknown, "condition") {
			*violations = append(*violations, resource.Address+" must not vary from its unconditional bucket-access contract")
		}
		return
	}

	bucket, _ := after["bucket"].(string)
	if bucket == "" || topLevelUnknown(resource.Change.AfterUnknown, "bucket") {
		*violations = append(*violations, resource.Address+" must bind one explicit state bucket")
		return
	}
	condition, ok := singleObject(after["condition"])
	if !ok || nestedUnknown(resource.Change.AfterUnknown, "condition") {
		*violations = append(*violations, resource.Address+" must use one explicit object-scoped IAM condition")
		return
	}
	title := "bootstrap-plan-" + strings.TrimSuffix(instance, "-plan-state") + "-state-read"
	objectName := replicationPrefixes[module]
	if instance == "primary-plan-lock" {
		title = "bootstrap-plan-primary-lock"
		objectName = strings.TrimSuffix(objectName, "default.tfstate") + "default.tflock"
	} else if instance == "primary-apply" {
		title = "bootstrap-apply-primary-state-and-lock"
	} else if strings.HasSuffix(instance, "-recovery") {
		title = "bootstrap-recovery-" + strings.TrimSuffix(instance, "-recovery") + "-state-read"
	}
	expression := fmt.Sprintf("resource.name == 'projects/_/buckets/%s/objects/%s'", bucket, objectName)
	if instance == "primary-apply" {
		expression += fmt.Sprintf(" || resource.name == 'projects/_/buckets/%s/objects/%s'", bucket, strings.TrimSuffix(objectName, "default.tfstate")+"default.tflock")
	}
	if condition["title"] != title {
		*violations = append(*violations, fmt.Sprintf("%s must use IAM condition title %s", resource.Address, title))
	}
	if condition["expression"] != expression {
		*violations = append(*violations, resource.Address+" IAM condition must bind only the exact state or lock object")
	}
}

func validateReplicationBucketAccessContract(resource resourceChange, after map[string]any, violations *[]string) {
	if resource.Type != "google_storage_bucket_iam_member" {
		return
	}
	module := ""
	instance := ""
	for candidateModule := range replicationPrefixes {
		for _, candidateInstance := range []string{"source", "destination"} {
			expected := fmt.Sprintf(`%s.google_storage_bucket_iam_member.replication[%q]`, candidateModule, candidateInstance)
			if resource.Address == expected {
				module = candidateModule
				instance = candidateInstance
			}
		}
	}
	if module == "" {
		return
	}
	bucket, _ := after["bucket"].(string)
	condition, ok := singleObject(after["condition"])
	if bucket == "" || topLevelUnknown(resource.Change.AfterUnknown, "bucket") || !ok || nestedUnknown(resource.Change.AfterUnknown, "condition") {
		*violations = append(*violations, resource.Address+" must use one explicit bucket-scoped state-replication condition")
		return
	}
	expectedTitle := "bootstrap-replication-" + instance + "-state-only"
	expectedExpression := fmt.Sprintf("(resource.type == 'storage.googleapis.com/Bucket' && resource.name == 'projects/_/buckets/%s') || (resource.type == 'storage.googleapis.com/Object' && resource.name == 'projects/_/buckets/%s/objects/%s')", bucket, bucket, replicationPrefixes[module])
	if condition["title"] != expectedTitle || condition["expression"] != expectedExpression {
		*violations = append(*violations, resource.Address+" IAM condition must grant bucket metadata plus only the exact default.tfstate object")
	}
}

func validateRecoveryPlanReadAccessContract(resource resourceChange, after map[string]any, violations *[]string) {
	if resource.Type != "google_storage_bucket_iam_member" ||
		(!recoveryPlanReadBinding(resource.Address) && !recoveryPlanObjectReadBinding(resource.Address)) {
		return
	}
	bucket, _ := after["bucket"].(string)
	if bucket == "" || topLevelUnknown(resource.Change.AfterUnknown, "bucket") {
		*violations = append(*violations, resource.Address+" must target one explicit recovery bucket")
		return
	}
	role, _ := after["role"].(string)
	roleProject, _, roleOK := splitCustomRole(role)
	expectedSuffix := "-recovery-exports"
	if strings.Contains(resource.Address, `["evidence"]`) {
		expectedSuffix = "-recovery-evidence"
	}
	if !roleOK || bucket != roleProject+expectedSuffix {
		*violations = append(*violations, resource.Address+" must bind its exact role to the matching protected recovery bucket")
	}
	if recoveryPlanReadBinding(resource.Address) {
		if !plannedUnset(after["condition"]) || nestedUnknown(resource.Change.AfterUnknown, "condition") {
			*violations = append(*violations, resource.Address+" metadata-only plan read must remain unconditional")
		}
		return
	}
	objects := map[string]string{
		"exports":  "restore/inventory.json",
		"evidence": "trust/public-trust-metadata.json",
	}
	instance := ""
	for candidate := range objects {
		if resource.Address == fmt.Sprintf(`module.recovery_exports.google_storage_bucket_iam_member.plan_object_read[%q]`, candidate) {
			instance = candidate
		}
	}
	condition, ok := singleObject(after["condition"])
	if instance == "" || !ok || nestedUnknown(resource.Change.AfterUnknown, "condition") {
		*violations = append(*violations, resource.Address+" must use one explicit declared-object read condition")
		return
	}
	expectedTitle := "read-" + instance + "-declared-object-only"
	expectedExpression := fmt.Sprintf("resource.type == 'storage.googleapis.com/Object' && resource.name == 'projects/_/buckets/%s/objects/%s'", bucket, objects[instance])
	if condition["title"] != expectedTitle || condition["expression"] != expectedExpression {
		*violations = append(*violations, resource.Address+" IAM condition must allow only its fixed non-state recovery object")
	}
}

func approvedRecoveryExportAccess(address, role string) bool {
	instanceRoles := map[string]string{
		"exports-exporter":           "roles/storage.objectCreator",
		"exports-recovery":           "roles/storage.objectViewer",
		"exports-recovery-metadata":  "roles/storage.legacyBucketReader",
		"evidence-exporter":          "roles/storage.objectCreator",
		"evidence-recovery":          "roles/storage.objectViewer",
		"evidence-recovery-metadata": "roles/storage.legacyBucketReader",
	}
	for instance, expectedRole := range instanceRoles {
		expectedAddress := fmt.Sprintf(`module.recovery_exports.google_storage_bucket_iam_member.access[%q]`, instance)
		if address == expectedAddress {
			return role == expectedRole
		}
	}
	return false
}

func recoveryPlanReadBinding(address string) bool {
	return address == `module.recovery_exports.google_storage_bucket_iam_member.plan_read["exports"]` ||
		address == `module.recovery_exports.google_storage_bucket_iam_member.plan_read["evidence"]`
}

func recoveryPlanObjectReadBinding(address string) bool {
	return address == `module.recovery_exports.google_storage_bucket_iam_member.plan_object_read["exports"]` ||
		address == `module.recovery_exports.google_storage_bucket_iam_member.plan_object_read["evidence"]`
}

func replicationCustomRoleContract(address string) (replicationRoleContract, bool) {
	if resourceAddressBase(address) == "module.audit_root.google_project_iam_custom_role.plan_read" {
		return auditPlanReadRoleContract, true
	}
	if address == "google_organization_iam_custom_role.plan_read" {
		return organizationPlanReadRoleContract, true
	}
	if address == "google_organization_iam_custom_role.recovery_sink_read" {
		return recoverySinkReadRoleContract, true
	}
	if address == "google_organization_iam_custom_role.apply_iam" {
		return organizationIAMApplyRoleContract, true
	}
	if address == "module.signing_root.google_project_iam_custom_role.recovery_metadata" {
		return recoverySigningMetadataRoleContract, true
	}
	if address == "module.recovery_exports.google_project_iam_custom_role.plan_read" {
		return recoveryPlanReadRoleContract, true
	}
	if address == "module.recovery_exports.google_project_iam_custom_role.plan_object_read" {
		return recoveryPlanObjectReadRoleContract, true
	}
	for suffix, contract := range recoveryStateExportRoleContracts {
		if strings.HasPrefix(suffix, "destination_") {
			if address == "module.recovery_exports.google_project_iam_custom_role.state_export_"+suffix {
				return contract, true
			}
			continue
		}
		if _, ok := exactRecoveryStateExportAddress(address, "google_project_iam_custom_role.state_export_"+suffix); ok {
			return contract, true
		}
	}
	for module := range replicationPrefixes {
		if address == module+".google_project_iam_custom_role.plan_lock" {
			return statePlanLockRoleContract, true
		}
		for instance, contract := range replicationRoleContracts {
			expected := fmt.Sprintf(`%s.google_project_iam_custom_role.replication[%q]`, module, instance)
			if address == expected {
				return contract, true
			}
		}
	}
	return replicationRoleContract{}, false
}

func exactRecoveryStateExportAddress(address, suffix string) (string, bool) {
	for _, key := range recoveryStateExportKeys {
		if address == fmt.Sprintf(`module.recovery_exports.%s[%q]`, suffix, key) {
			return key, true
		}
	}
	return "", false
}

func replicationBindingContract(resourceType, address string) (replicationRoleContract, string, bool) {
	type bindingContract struct {
		instance string
		roleKey  string
		agent    string
	}
	var suffix string
	var contracts []bindingContract
	switch resourceType {
	case "google_storage_bucket_iam_member":
		suffix = "google_storage_bucket_iam_member.replication"
		contracts = []bindingContract{
			{instance: "source", roleKey: "source_bucket", agent: "transfer"},
			{instance: "destination", roleKey: "destination_bucket", agent: "transfer"},
		}
	case "google_project_iam_member":
		suffix = "google_project_iam_member.replication_events"
		contracts = []bindingContract{
			{instance: "transfer", roleKey: "transfer_events", agent: "transfer"},
			{instance: "storage", roleKey: "storage_events", agent: "storage"},
		}
	default:
		return replicationRoleContract{}, "", false
	}
	for module := range replicationPrefixes {
		for _, binding := range contracts {
			expected := fmt.Sprintf(`%s.%s[%q]`, module, suffix, binding.instance)
			if address == expected {
				return replicationRoleContracts[binding.roleKey], binding.agent, true
			}
		}
	}
	return replicationRoleContract{}, "", false
}

type recoveryStateExportBinding struct {
	contract   replicationRoleContract
	instance   string
	key        string
	memberKind string
}

func recoveryStateExportBindingDetails(resourceType, address string) (recoveryStateExportBinding, bool) {
	type candidate struct {
		resourceType string
		suffix       string
		roleKey      string
		memberKind   string
		predefined   string
	}
	candidates := []candidate{
		{resourceType: "google_service_account_iam_member", suffix: "google_service_account_iam_member.state_export_apply", memberKind: "apply", predefined: "roles/iam.serviceAccountUser"},
		{resourceType: "google_service_account_iam_member", suffix: "google_service_account_iam_member.state_export_transfer", memberKind: "transfer", predefined: "roles/iam.serviceAccountTokenCreator"},
		{resourceType: "google_project_iam_member", suffix: "google_project_iam_member.state_export_transfer_events", roleKey: "transfer_events", memberKind: "export"},
		{resourceType: "google_project_iam_member", suffix: "google_project_iam_member.state_export_storage_events", roleKey: "storage_events", memberKind: "storage"},
		{resourceType: "google_storage_bucket_iam_member", suffix: "google_storage_bucket_iam_member.state_export_source_metadata", roleKey: "source_metadata", memberKind: "export"},
		{resourceType: "google_storage_bucket_iam_member", suffix: "google_storage_bucket_iam_member.state_export_source_object", roleKey: "source_object", memberKind: "export"},
		{resourceType: "google_storage_bucket_iam_member", suffix: "google_storage_bucket_iam_member.state_export_destination_metadata", roleKey: "destination_metadata", memberKind: "export"},
		{resourceType: "google_storage_bucket_iam_member", suffix: "google_storage_bucket_iam_member.state_export_destination_object", roleKey: "destination_object", memberKind: "export"},
	}
	for _, candidate := range candidates {
		if resourceType != candidate.resourceType {
			continue
		}
		key, ok := exactRecoveryStateExportAddress(address, candidate.suffix)
		if !ok {
			continue
		}
		contract := recoveryStateExportRoleContracts[candidate.roleKey]
		if candidate.predefined != "" {
			contract = replicationRoleContract{roleID: candidate.predefined}
		}
		return recoveryStateExportBinding{
			contract:   contract,
			instance:   strings.TrimPrefix(candidate.suffix, resourceType+".state_export_"),
			key:        key,
			memberKind: candidate.memberKind,
		}, true
	}
	return recoveryStateExportBinding{}, false
}

func recoveryStateExportBindingContract(resourceType, address string) (replicationRoleContract, string, bool) {
	binding, ok := recoveryStateExportBindingDetails(resourceType, address)
	if !ok {
		return replicationRoleContract{}, "", false
	}
	return binding.contract, binding.memberKind, true
}

func roleMatchesContract(role string, contract replicationRoleContract) bool {
	if strings.HasPrefix(contract.roleID, "roles/") {
		return role == contract.roleID
	}
	return matchesReplicationCustomRole(role, contract.roleID)
}

func matchesReplicationCustomRole(role, roleID string) bool {
	parts := strings.Split(role, "/")
	return len(parts) == 4 && parts[0] == "projects" && googleProjectIDPattern.MatchString(parts[1]) &&
		parts[2] == "roles" && parts[3] == roleID
}

func matchesOrganizationCustomRole(role, roleID string) bool {
	parts := strings.Split(role, "/")
	return len(parts) == 4 && parts[0] == "organizations" && numericIDPattern.MatchString(parts[1]) &&
		parts[2] == "roles" && parts[3] == roleID
}

func validateReplicationCustomRole(resource resourceChange, after map[string]any, violations *[]string) {
	contract, ok := replicationCustomRoleContract(resource.Address)
	if !ok || resource.Mode != "managed" {
		*violations = append(*violations, resource.Address+" is outside the exact Ring-0 custom-role addresses")
		return
	}
	if resource.Type == "google_organization_iam_custom_role" {
		orgID, _ := after["org_id"].(string)
		if !numericIDPattern.MatchString(orgID) || topLevelUnknown(resource.Change.AfterUnknown, "org_id") {
			*violations = append(*violations, resource.Address+" must bind its custom role to one explicit organization ID")
		}
	} else {
		project, _ := after["project"].(string)
		if !googleProjectIDPattern.MatchString(project) || topLevelUnknown(resource.Change.AfterUnknown, "project") {
			*violations = append(*violations, resource.Address+" must bind its custom role to one explicit project ID")
		}
	}
	if roleID, _ := after["role_id"].(string); roleID != contract.roleID {
		*violations = append(*violations, fmt.Sprintf("%s must use custom role ID %s", resource.Address, contract.roleID))
	}
	if topLevelUnknown(resource.Change.AfterUnknown, "role_id") {
		*violations = append(*violations, resource.Address+" custom role ID must be explicit")
	}
	if stage, _ := after["stage"].(string); stage != "GA" {
		*violations = append(*violations, resource.Address+" custom role must be at GA stage")
	}
	if topLevelUnknown(resource.Change.AfterUnknown, "stage") {
		*violations = append(*violations, resource.Address+" custom role stage must be explicit")
	}
	if !exactStringSet(after["permissions"], contract.permissions) || topLevelUnknown(resource.Change.AfterUnknown, "permissions") {
		*violations = append(*violations, resource.Address+" custom role permissions must exactly match its approved Ring-0 contract")
	}
	deleted, deletedKnown := after["deleted"].(bool)
	deletedUnknown := topLevelUnknown(resource.Change.AfterUnknown, "deleted")
	initialComputedDeleted := strings.Join(resource.Change.Actions, ",") == "create" && !deletedKnown && deletedUnknown
	if deleted || (!initialComputedDeleted && (!deletedKnown || deletedUnknown)) {
		*violations = append(*violations, resource.Address+" custom role deleted state must be explicit false")
	}
}

func validateTransferServiceAccountData(resource resourceChange, after map[string]any, violations *[]string) {
	_, _, backendAddress := exactReplicationAddress(resource.Address, "data.google_storage_transfer_project_service_account.replication")
	_, exportAddress := exactRecoveryStateExportAddress(resource.Address, "data.google_storage_transfer_project_service_account.state_export")
	exactAddress := backendAddress || exportAddress
	if resource.Mode != "data" || !exactAddress {
		*violations = append(*violations, resource.Address+" is outside the exact approved transfer-agent data addresses")
		return
	}
	project, _ := after["project"].(string)
	if !googleProjectIDPattern.MatchString(project) {
		*violations = append(*violations, resource.Address+" must resolve the transfer agent for one explicit project ID")
	}
	member, _ := after["member"].(string)
	if member != "" {
		if !transferServiceAgentPattern.MatchString(member) {
			*violations = append(*violations, resource.Address+" must resolve to the Google-managed Storage Transfer service agent")
		}
	} else if !topLevelUnknown(resource.Change.AfterUnknown, "member") {
		*violations = append(*violations, resource.Address+" must expose a known or computed Storage Transfer service-agent member")
	}
}

func validateExpectedServiceAgentMember(resource resourceChange, after map[string]any, violations *[]string) {
	if resource.Type == "google_storage_bucket_iam_member" &&
		(recoveryPlanReadBinding(resource.Address) || recoveryPlanObjectReadBinding(resource.Address)) {
		member, _ := after["member"].(string)
		if !bootstrapPlanPrincipalPattern.MatchString(member) || topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must bind the compiler-derived bootstrap-plan service account")
		}
		return
	}
	if binding, ok := recoveryStateExportBindingDetails(resource.Type, resource.Address); ok {
		switch binding.memberKind {
		case "transfer":
			validateKnownOrComputedAgentMember(resource, after, "transfer", violations)
		case "storage":
			validateKnownOrComputedAgentMember(resource, after, "storage", violations)
		}
		return
	}
	_, agent, isReplicationBinding := replicationBindingContract(resource.Type, resource.Address)
	if !isReplicationBinding {
		base := resource.Address
		if index := strings.IndexByte(base, '['); index >= 0 {
			base = base[:index]
		}
		if resource.Type == "google_kms_crypto_key_iam_member" {
			switch base {
			case "module.recovery_exports.google_kms_crypto_key_iam_member.storage",
				"module.root_state.google_kms_crypto_key_iam_member.state_service_agent",
				"module.root_state.google_kms_crypto_key_iam_member.replica_service_agent",
				"module.recovery_state.google_kms_crypto_key_iam_member.state_service_agent",
				"module.recovery_state.google_kms_crypto_key_iam_member.replica_service_agent":
				agent = "storage"
			default:
				return
			}
		} else {
			return
		}
	}

	member, _ := after["member"].(string)
	if member == "" {
		if !topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must use a known or computed Google-managed service-agent member")
		}
		return
	}
	pattern := storageServiceAgentPattern
	if agent == "transfer" {
		pattern = transferServiceAgentPattern
	}
	if !pattern.MatchString(member) {
		*violations = append(*violations, resource.Address+" must grant only the expected Google-managed "+agent+" service agent")
	}
}

func validateKnownOrComputedAgentMember(resource resourceChange, after map[string]any, agent string, violations *[]string) {
	member, _ := after["member"].(string)
	if member == "" {
		if !topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must use a known or computed Google-managed "+agent+" service-agent member")
		}
		return
	}
	pattern := storageServiceAgentPattern
	if agent == "transfer" {
		pattern = transferServiceAgentPattern
	}
	if !pattern.MatchString(member) {
		*violations = append(*violations, resource.Address+" must grant only the expected Google-managed "+agent+" service agent")
	}
}

func validateRecoveryStateExportStorageServiceAccountData(resource resourceChange, after map[string]any, violations *[]string) {
	if resource.Mode != "data" {
		*violations = append(*violations, resource.Address+" storage service-agent lookup must be a data resource")
		return
	}
	if strings.HasPrefix(resource.Address, "module.recovery_exports.data.google_storage_project_service_account.state_export_source") {
		if _, ok := exactRecoveryStateExportAddress(resource.Address, "data.google_storage_project_service_account.state_export_source"); !ok {
			*violations = append(*violations, resource.Address+" is outside the two exact recovery state-export source-agent lookups")
			return
		}
	}
	project, _ := after["project"].(string)
	if !googleProjectIDPattern.MatchString(project) || topLevelUnknown(resource.Change.AfterUnknown, "project") {
		*violations = append(*violations, resource.Address+" must resolve the storage service agent for one explicit project ID")
	}
	if email, _ := after["email_address"].(string); email != "" && !storageServiceAgentEmailPattern.MatchString(email) {
		*violations = append(*violations, resource.Address+" must resolve to the Google-managed Cloud Storage service-agent email")
	}
	if member, _ := after["member"].(string); member != "" && !storageServiceAgentPattern.MatchString(member) {
		*violations = append(*violations, resource.Address+" must resolve to the Google-managed Cloud Storage service-agent member")
	}
}

func validateRecoveryStateExportServiceAccount(resource resourceChange, after map[string]any, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	if base != "module.recovery_exports.google_service_account.state_export" {
		return
	}
	if _, ok := exactRecoveryStateExportAddress(resource.Address, "google_service_account.state_export"); !ok || resource.Mode != "managed" {
		*violations = append(*violations, resource.Address+" is outside the two exact recovery state-export service accounts")
		return
	}
	project, _ := after["project"].(string)
	if !googleProjectIDPattern.MatchString(project) || topLevelUnknown(resource.Change.AfterUnknown, "project") {
		*violations = append(*violations, resource.Address+" must create the export identity in one explicit source project")
	}
	requireEqual(after, "account_id", "bootstrap-recovery-export", resource.Address, violations)
	requireEqual(after, "disabled", false, resource.Address, violations)
	requireEqual(after, "deletion_policy", "PREVENT", resource.Address, violations)
	validateUnknownLeafAllowlist(resource, map[string]bool{
		"email":     true,
		"id":        true,
		"member":    true,
		"name":      true,
		"unique_id": true,
	}, violations)
}

func validateRecoveryStateExportIAMBinding(resource resourceChange, after map[string]any, violations *[]string) {
	binding, ok := recoveryStateExportBindingDetails(resource.Type, resource.Address)
	if !ok {
		return
	}
	role, _ := after["role"].(string)
	if !roleMatchesContract(role, binding.contract) || topLevelUnknown(resource.Change.AfterUnknown, "role") {
		*violations = append(*violations, resource.Address+" must use its exact recovery state-export role")
	}

	member, _ := after["member"].(string)
	roleProject, _, customRole := splitCustomRole(role)
	sourceProject := ""
	switch resource.Type {
	case "google_service_account_iam_member":
		serviceAccountID, _ := after["service_account_id"].(string)
		var exact bool
		sourceProject, exact = stateExportServiceAccountProject(serviceAccountID)
		if !exact || topLevelUnknown(resource.Change.AfterUnknown, "service_account_id") {
			*violations = append(*violations, resource.Address+" must target the deterministic recovery-export service account in its source project")
		}
	case "google_project_iam_member":
		sourceProject, _ = after["project"].(string)
		if !googleProjectIDPattern.MatchString(sourceProject) || topLevelUnknown(resource.Change.AfterUnknown, "project") ||
			!customRole || roleProject != sourceProject {
			*violations = append(*violations, resource.Address+" custom role and binding must target the same explicit source project")
		}
	case "google_storage_bucket_iam_member":
		bucket, _ := after["bucket"].(string)
		if bucket == "" || topLevelUnknown(resource.Change.AfterUnknown, "bucket") || !customRole {
			*violations = append(*violations, resource.Address+" must target one explicit bucket with its exact custom role")
		}
		if binding.instance == "source_metadata" || binding.instance == "source_object" {
			sourceProject = roleProject
		} else if bucket != roleProject+"-recovery-exports" {
			*violations = append(*violations, resource.Address+" destination binding must target only its recovery project's export bucket")
		}
	}

	switch binding.memberKind {
	case "apply":
		if !bootstrapApplyPrincipalPattern.MatchString(member) || topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must bind only the explicit bootstrap-apply service account")
		}
	case "export":
		memberProject, exact := stateExportMemberProject(member)
		if !exact || topLevelUnknown(resource.Change.AfterUnknown, "member") {
			*violations = append(*violations, resource.Address+" must bind the deterministic bootstrap-recovery-export service account")
		} else if sourceProject != "" && memberProject != sourceProject {
			*violations = append(*violations, resource.Address+" export member must belong to the binding's source project")
		}
	}

	conditionRequired := binding.instance == "source_object" || binding.instance == "destination_object"
	if !conditionRequired {
		if !plannedUnset(after["condition"]) || nestedUnknown(resource.Change.AfterUnknown, "condition") {
			*violations = append(*violations, resource.Address+" metadata and service/project bindings must remain unconditional")
		}
		return
	}
	bucket, _ := after["bucket"].(string)
	condition, exact := singleObject(after["condition"])
	if !exact || nestedUnknown(resource.Change.AfterUnknown, "condition") {
		*violations = append(*violations, resource.Address+" must use one explicit exact-state-object IAM condition")
		return
	}
	verb := "read"
	if binding.instance == "destination_object" {
		verb = "write"
	}
	expectedTitle := verb + "-" + binding.key + "-default-state-only"
	expectedExpression := fmt.Sprintf("resource.type == 'storage.googleapis.com/Object' && resource.name == 'projects/_/buckets/%s/objects/%s/default.tfstate'", bucket, binding.key)
	if condition["title"] != expectedTitle || condition["expression"] != expectedExpression {
		*violations = append(*violations, resource.Address+" IAM condition must select only the exact default.tfstate object and exclude locks")
	}
}

func splitCustomRole(role string) (string, string, bool) {
	parts := strings.Split(role, "/")
	if len(parts) != 4 || parts[0] != "projects" || !googleProjectIDPattern.MatchString(parts[1]) || parts[2] != "roles" || parts[3] == "" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

func stateExportServiceAccountProject(serviceAccountID string) (string, bool) {
	const marker = "/serviceAccounts/bootstrap-recovery-export@"
	if !strings.HasPrefix(serviceAccountID, "projects/") || !strings.Contains(serviceAccountID, marker) || !strings.HasSuffix(serviceAccountID, ".iam.gserviceaccount.com") {
		return "", false
	}
	project := strings.TrimPrefix(strings.SplitN(serviceAccountID, marker, 2)[0], "projects/")
	emailProject := strings.TrimSuffix(strings.SplitN(serviceAccountID, marker, 2)[1], ".iam.gserviceaccount.com")
	return project, googleProjectIDPattern.MatchString(project) && emailProject == project
}

func stateExportMemberProject(member string) (string, bool) {
	const prefix = "serviceAccount:bootstrap-recovery-export@"
	if !strings.HasPrefix(member, prefix) || !strings.HasSuffix(member, ".iam.gserviceaccount.com") {
		return "", false
	}
	project := strings.TrimSuffix(strings.TrimPrefix(member, prefix), ".iam.gserviceaccount.com")
	return project, googleProjectIDPattern.MatchString(project)
}

func validateReplicationTransferJob(resource resourceChange, after map[string]any, violations *[]string) {
	_, requiredPrefix, backendAddress := exactReplicationAddress(resource.Address, "google_storage_transfer_job.replication")
	exportKey, exportAddress := exactRecoveryStateExportAddress(resource.Address, "google_storage_transfer_job.state_export")
	if exportAddress {
		requiredPrefix = exportKey + "/default.tfstate"
	}
	if resource.Mode != "managed" || (!backendAddress && !exportAddress) {
		*violations = append(*violations, resource.Address+" is outside the exact approved native-replication transfer-job addresses")
		return
	}
	validateReplicationTransferUnknowns(resource, backendAddress, violations)
	requireEqual(after, "status", "ENABLED", resource.Address, violations)
	requireEqual(after, "deletion_policy", "PREVENT", resource.Address, violations)
	project, _ := after["project"].(string)
	if !googleProjectIDPattern.MatchString(project) {
		*violations = append(*violations, resource.Address+" must create the transfer job in one explicit project")
	}

	for _, field := range []string{"event_stream", "logging_config", "notification_config", "schedule", "transfer_spec"} {
		if !plannedUnset(after[field]) || nestedUnknown(resource.Change.AfterUnknown, field) {
			*violations = append(*violations, fmt.Sprintf("%s must not configure %s for native cross-bucket replication", resource.Address, field))
		}
	}
	if exportAddress {
		expectedServiceAccount := "bootstrap-recovery-export@" + project + ".iam.gserviceaccount.com"
		if after["service_account"] != expectedServiceAccount || topLevelUnknown(resource.Change.AfterUnknown, "service_account") {
			*violations = append(*violations, resource.Address+" must run only as the deterministic recovery-export service account in its source project")
		}
	} else if !plannedUnset(after["service_account"]) || topLevelUnknown(resource.Change.AfterUnknown, "service_account") {
		*violations = append(*violations, resource.Address+" backend replication must use the Google-managed transfer service agent")
	}

	spec, ok := singleObject(after["replication_spec"])
	if !ok {
		*violations = append(*violations, resource.Address+" must configure exactly one native replication_spec block")
		return
	}
	source, sourceOK := singleObject(spec["gcs_data_source"])
	sink, sinkOK := singleObject(spec["gcs_data_sink"])
	if !sourceOK || !sinkOK {
		*violations = append(*violations, resource.Address+" must configure exactly one GCS source and one GCS destination")
		return
	}
	sourceName, sourceKnown := source["bucket_name"].(string)
	sinkName, sinkKnown := sink["bucket_name"].(string)
	sourceKnown = sourceKnown && sourceName != ""
	sinkKnown = sinkKnown && sinkName != ""
	if !sourceKnown && !nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "gcs_data_source", "bucket_name") {
		*violations = append(*violations, resource.Address+" must identify a known or computed source bucket")
	}
	if !sinkKnown && !nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "gcs_data_sink", "bucket_name") {
		*violations = append(*violations, resource.Address+" must identify a known or computed destination bucket")
	}
	if sourceKnown && sinkKnown && sourceName == sinkName {
		*violations = append(*violations, resource.Address+" source and destination buckets must be distinct")
	}
	if exportAddress && (!sourceKnown || !sinkKnown) {
		*violations = append(*violations, resource.Address+" recovery export must use explicit, distinct source and destination buckets")
	}
	for label, endpoint := range map[string]map[string]any{"source": source, "destination": sink} {
		if path, _ := endpoint["path"].(string); path != "" {
			*violations = append(*violations, fmt.Sprintf("%s %s bucket path must be empty; isolation is enforced by object_conditions", resource.Address, label))
		}
	}
	if nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "gcs_data_source", "path") ||
		nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "gcs_data_sink", "path") {
		*violations = append(*violations, resource.Address+" bucket paths must not be unknown")
	}

	conditions, ok := singleObject(spec["object_conditions"])
	if !ok || !exactStringSet(conditions["include_prefixes"], []string{requiredPrefix}) ||
		nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "object_conditions", "include_prefixes") {
		*violations = append(*violations, fmt.Sprintf("%s must include only the exact state prefix %s", resource.Address, requiredPrefix))
	}
	if ok {
		for _, field := range []string{"exclude_prefixes", "last_modified_before", "last_modified_since", "max_time_elapsed_since_last_modification", "min_time_elapsed_since_last_modification"} {
			if !plannedUnset(conditions[field]) || nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "object_conditions", field) {
				*violations = append(*violations, fmt.Sprintf("%s must not broaden or time-limit replication with object_conditions.%s", resource.Address, field))
			}
		}
	}

	options, ok := singleObject(spec["transfer_options"])
	if !ok {
		*violations = append(*violations, resource.Address+" must configure exactly one transfer_options block")
		return
	}
	if overwrite, _ := options["overwrite_when"].(string); overwrite != "DIFFERENT" ||
		nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "transfer_options", "overwrite_when") {
		*violations = append(*violations, resource.Address+" must overwrite destination objects only when content differs")
	}
	for _, field := range []string{"delete_objects_from_source_after_transfer", "delete_objects_unique_in_sink", "overwrite_objects_already_existing_in_sink"} {
		if !falseOrUnset(options[field]) || nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "transfer_options", field) {
			*violations = append(*violations, fmt.Sprintf("%s must keep transfer_options.%s disabled", resource.Address, field))
		}
	}

	metadata, ok := singleObject(options["metadata_options"])
	if !ok {
		*violations = append(*violations, resource.Address+" must configure exactly one metadata_options block")
		return
	}
	for key, expected := range map[string]string{
		"acl":           "ACL_DESTINATION_BUCKET_DEFAULT",
		"kms_key":       "KMS_KEY_DESTINATION_BUCKET_DEFAULT",
		"storage_class": "STORAGE_CLASS_DESTINATION_BUCKET_DEFAULT",
	} {
		if actual, _ := metadata[key].(string); actual != expected ||
			nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "transfer_options", "metadata_options", key) {
			*violations = append(*violations, fmt.Sprintf("%s must set metadata_options.%s to %s", resource.Address, key, expected))
		}
	}
	for _, field := range []string{"gid", "mode", "symlink", "temporary_hold", "time_created", "uid"} {
		if !plannedUnset(metadata[field]) || nestedUnknown(resource.Change.AfterUnknown, "replication_spec", "transfer_options", "metadata_options", field) {
			*violations = append(*violations, fmt.Sprintf("%s must leave metadata_options.%s unset", resource.Address, field))
		}
	}
}

func validateReplicationTransferUnknowns(resource resourceChange, allowComputedBuckets bool, violations *[]string) {
	allowed := map[string]bool{
		"creation_time":          true,
		"deletion_time":          true,
		"id":                     true,
		"last_modification_time": true,
		"name":                   true,
	}
	if allowComputedBuckets {
		allowed["replication_spec[0].gcs_data_sink[0].bucket_name"] = true
		allowed["replication_spec[0].gcs_data_source[0].bucket_name"] = true
	}
	validateUnknownLeafAllowlist(resource, allowed, violations)
}

func validateUnknownLeafAllowlist(resource resourceChange, allowed map[string]bool, violations *[]string) {
	var paths []string
	collectUnknownLeafPaths(resource.Change.AfterUnknown, "", &paths)
	for _, path := range paths {
		if !allowed[path] {
			*violations = append(*violations, fmt.Sprintf("%s.%s contains an unapproved computed contract value", resource.Address, path))
		}
	}
}

func validateSigningCryptoKey(resource resourceChange, after map[string]any, violations *[]string) {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	if base != "module.signing_root.google_kms_crypto_key.signing" {
		return
	}
	keyName, ok := signingKeyAddress(resource.Address)
	if !ok {
		*violations = append(*violations, resource.Address+" is outside the three exact signing-key instances")
		return
	}
	requireEqual(after, "name", keyName, resource.Address, violations)
	requireEqual(after, "skip_initial_version_creation", true, resource.Address, violations)
	keyRing, known := after["key_ring"].(string)
	if ((!known || keyRing == "") && !topLevelUnknown(resource.Change.AfterUnknown, "key_ring")) ||
		(known && keyRing != "" && !canonicalSigningKeyRing(keyRing)) {
		*violations = append(*violations, resource.Address+" must use the canonical bootstrap-signing HSM key ring")
	}
}

func validateSigningCryptoKeyVersion(resource resourceChange, after map[string]any, violations *[]string) {
	keyName, versionRef, exactAddress := declaredSigningVersionAddress(resource.Address, resource.signingContract)
	if resource.Mode != "managed" || !exactAddress {
		*violations = append(*violations, resource.Address+" is outside the append-only declared signing-version addresses")
		return
	}
	actions := strings.Join(resource.Change.Actions, ",")
	if actions != "create" && actions != "read" && actions != "no-op" {
		*violations = append(*violations, resource.Address+" signing key versions are append-only and may only be created or read")
	}
	if resource.signingVersionCreateProof {
		if !exactInitialSigningVersionEnvelope(resource, after) {
			*violations = append(*violations, resource.Address+" initial-create version unknowns must exactly match the reviewed server-assigned version envelope")
		}
		return
	}
	cryptoKey, _ := after["crypto_key"].(string)
	if !canonicalSigningCryptoKey(cryptoKey, keyName) || topLevelUnknown(resource.Change.AfterUnknown, "crypto_key") {
		*violations = append(*violations, resource.Address+" must use the canonical parent name for its declared signing key")
	}
	versionName, knownVersionName := after["name"].(string)
	if knownVersionName && versionName != "" {
		parts := strings.Split(versionName, "/")
		if len(parts) != 10 || strings.Join(parts[:8], "/") != cryptoKey || parts[8] != "cryptoKeyVersions" || !numericIDPattern.MatchString(parts[9]) {
			*violations = append(*violations, resource.Address+" must expose a canonical immutable version name under its declared signing key")
		}
	} else if !topLevelUnknown(resource.Change.AfterUnknown, "name") {
		*violations = append(*violations, resource.Address+" must expose a known or computed immutable CryptoKeyVersion name")
	}
	state, knownState := after["state"].(string)
	if (!knownState || state == "") && topLevelUnknown(resource.Change.AfterUnknown, "state") {
		// State is assigned by Cloud KMS during creation and checked again once
		// known by the postcondition and future plans.
	} else if resource.signingContract.keys[keyName].activeVersionRef == versionRef && state != "ENABLED" {
		*violations = append(*violations, resource.Address+" active signing version must remain ENABLED")
	} else if resource.signingContract.keys[keyName].activeVersionRef != versionRef && state != "ENABLED" && state != "DISABLED" {
		*violations = append(*violations, resource.Address+" historical signing version may only be ENABLED or DISABLED")
	}
	validateKnownOrComputedString(resource, after, "algorithm", "EC_SIGN_P256_SHA256", violations)
	validateKnownOrComputedString(resource, after, "protection_level", "HSM", violations)
}

func validateActiveSigningVersionData(resource resourceChange, after map[string]any, violations *[]string) {
	const base = "module.signing_root.data.google_kms_crypto_key_version.active"
	keyName, indexed, valid := terraformAddressStringIndex(resource.Address, base)
	_, contractOK := signingKeyDeclaration(resource.signingContract, keyName)
	actions := strings.Join(resource.Change.Actions, ",")
	if resource.Mode != "data" || !valid || !indexed || !contractOK || (actions != "read" && actions != "no-op") {
		*violations = append(*violations, resource.Address+" must read only one exact compiled active signing version")
		return
	}
	valid = activeSigningPlannedValueMatches(resource, keyName, after)
	if activeSigningVersionDeferredEnvelope(resource, after) {
		beforeValid := resource.Change.Before == nil
		if len(after) != 0 {
			beforeValid = validResolvedActiveSigningVersionValue(resource.Change.Before, keyName)
		}
		if actions != "read" || !beforeValid || !valid {
			*violations = append(*violations, resource.Address+" must use the exact deferred active-signing read envelope")
		}
		return
	}
	_, _, resolved := resolvedActiveSigningVersion(after, keyName)
	valid = valid && resolved && exactTopLevelUnknowns(resource.Change.AfterUnknown, nil)
	if actions == "no-op" {
		before, beforeOK := resource.Change.Before.(map[string]any)
		valid = valid && beforeOK && sameJSONValue(before, after)
	} else if resource.Change.Before != nil {
		valid = valid && validResolvedActiveSigningVersionValue(resource.Change.Before, keyName)
	}
	if !valid {
		*violations = append(*violations, resource.Address+" must resolve the exact enabled HSM P-256 active signing version")
	}
}

var activeSigningVersionFields = []string{
	"algorithm", "crypto_key", "id", "name", "protection_level", "public_key", "state", "version",
}

func activeSigningVersionDeferredEnvelope(resource resourceChange, after map[string]any) bool {
	const base = "module.signing_root.data.google_kms_crypto_key_version.active"
	keyName, indexed, valid := terraformAddressStringIndex(resource.Address, base)
	_, contractOK := signingKeyDeclaration(resource.signingContract, keyName)
	if resource.Mode != "data" || !valid || !indexed || !contractOK {
		return false
	}
	if len(after) == 0 {
		return exactTopLevelUnknowns(resource.Change.AfterUnknown, activeSigningVersionFields)
	}
	cryptoKey, _ := after["crypto_key"].(string)
	return exactObjectKeys(after, []string{"crypto_key"}) && canonicalSigningCryptoKey(cryptoKey, keyName) &&
		exactTopLevelUnknowns(resource.Change.AfterUnknown, []string{
			"algorithm", "id", "name", "protection_level", "public_key", "state", "version",
		})
}

func activeSigningPlannedValueMatches(resource resourceChange, keyName string, after map[string]any) bool {
	planned := resource.plannedValue
	if planned == nil || planned.Address != resource.Address || planned.Mode != "data" ||
		planned.Type != "google_kms_crypto_key_version" || planned.Name != "active" ||
		planned.ProviderName != "registry.opentofu.org/hashicorp/google" || planned.SchemaVersion != 0 {
		return false
	}
	index, indexOK := planned.Index.(string)
	if !indexOK || index != keyName {
		return false
	}
	unknowns, _ := resource.Change.AfterUnknown.(map[string]any)
	knownProjection := map[string]any{}
	for key, value := range planned.Values {
		if unknowns[key] == true {
			continue
		}
		knownProjection[key] = value
	}
	return sameJSONValue(knownProjection, after)
}

func validResolvedActiveSigningVersionValue(value any, keyName string) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	_, _, valid := resolvedActiveSigningVersion(object, keyName)
	return valid
}

func resolvedActiveSigningVersion(value map[string]any, keyName string) (string, string, bool) {
	if !exactObjectKeys(value, activeSigningVersionFields) {
		return "", "", false
	}
	cryptoKey, _ := value["crypto_key"].(string)
	name, _ := value["name"].(string)
	version, versionOK := positiveJSONInteger(value["version"])
	publicKey, publicKeyOK := singleObject(value["public_key"])
	publicKeyAlgorithm, _ := publicKey["algorithm"].(string)
	publicKeyPEM, _ := publicKey["pem"].(string)
	valid := canonicalSigningCryptoKey(cryptoKey, keyName) && versionOK &&
		name == cryptoKey+"/cryptoKeyVersions/"+version &&
		value["id"] == "//cloudkms.googleapis.com/v1/"+name &&
		value["algorithm"] == "EC_SIGN_P256_SHA256" && value["protection_level"] == "HSM" && value["state"] == "ENABLED" &&
		publicKeyOK && exactObjectKeys(publicKey, []string{"algorithm", "pem"}) &&
		publicKeyAlgorithm == value["algorithm"] && validP256PublicKeyPEM(publicKeyPEM)
	return cryptoKey, name, valid
}

func positiveJSONInteger(value any) (string, bool) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 1 || math.Trunc(number) != number || number > float64(1<<53-1) {
		return "", false
	}
	return strconv.FormatFloat(number, 'f', 0, 64), true
}

func validP256PublicKeyPEM(value string) bool {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	// ParsePKIXPublicKey rejects points outside the declared curve.
	return err == nil && ok && publicKey.Curve == elliptic.P256()
}

func exactInitialSigningVersionEnvelope(resource resourceChange, after map[string]any) bool {
	externalOptions, externalOK := after["external_protection_level_options"].([]any)
	return len(after) == 3 && externalOK && len(externalOptions) == 0 && after["timeouts"] == nil && after["deletion_policy"] == "PREVENT" &&
		exactUnknownLeafSet(resource.Change.AfterUnknown, []string{
			"algorithm", "attestation", "crypto_key", "generate_time", "id", "name", "protection_level", "state",
		})
}

func validateKnownOrComputedString(resource resourceChange, after map[string]any, key, expected string, violations *[]string) {
	value, known := after[key].(string)
	if known && value == expected {
		return
	}
	if (!known || value == "") && topLevelUnknown(resource.Change.AfterUnknown, key) {
		return
	}
	*violations = append(*violations, fmt.Sprintf("%s must resolve %s to %s", resource.Address, key, expected))
}

func signingKeyAddress(address string) (string, bool) {
	for _, keyName := range signingKeyNames {
		if address == fmt.Sprintf(`module.signing_root.google_kms_crypto_key.signing[%q]`, keyName) {
			return keyName, true
		}
	}
	return "", false
}

func signingVersionAddress(address string) (string, string, bool) {
	const prefix = `module.signing_root.google_kms_crypto_key_version.signing["`
	if !strings.HasPrefix(address, prefix) || !strings.HasSuffix(address, `"]`) {
		return "", "", false
	}
	instance := strings.TrimSuffix(strings.TrimPrefix(address, prefix), `"]`)
	parts := strings.Split(instance, ":")
	if len(parts) != 2 || !signingVersionPattern.MatchString(parts[1]) {
		return "", "", false
	}
	for _, keyName := range signingKeyNames {
		if parts[0] == keyName {
			return parts[0], parts[1], true
		}
	}
	return "", "", false
}

func declaredSigningVersionAddress(address string, contract *signingContract) (string, string, bool) {
	keyName, versionRef, syntaxOK := signingVersionAddress(address)
	return keyName, versionRef, syntaxOK && contract != nil && contract.versions[address]
}

func signingKeyDeclaration(contract *signingContract, keyName string) (signingKeyContract, bool) {
	if contract == nil {
		return signingKeyContract{}, false
	}
	declaration, ok := contract.keys[keyName]
	return declaration, ok
}

func canonicalSigningKeyRing(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 6 && parts[0] == "projects" && googleProjectIDPattern.MatchString(parts[1]) &&
		parts[2] == "locations" && parts[3] == "us-central1" && parts[4] == "keyRings" && parts[5] == "bootstrap-signing"
}

func canonicalSigningCryptoKey(name, expectedKey string) bool {
	parts := strings.Split(name, "/")
	if len(parts) != 8 || parts[0] != "projects" || !googleProjectIDPattern.MatchString(parts[1]) ||
		parts[2] != "locations" || parts[3] == "" || parts[4] != "keyRings" || parts[5] == "" ||
		parts[6] != "cryptoKeys" || parts[7] != expectedKey {
		return false
	}
	return !strings.Contains(parts[3], " ") && !strings.Contains(parts[5], " ")
}

func validateFixedRecoveryObject(resource resourceChange, after map[string]any, violations *[]string) {
	type objectContract struct {
		name         string
		bucketSuffix string
	}
	objects := map[string]objectContract{
		"module.recovery_exports.google_storage_bucket_object.public_trust_metadata": {name: "trust/public-trust-metadata.json", bucketSuffix: "-recovery-evidence"},
		"module.recovery_exports.google_storage_bucket_object.restore_inventory":     {name: "restore/inventory.json", bucketSuffix: "-recovery-exports"},
	}
	contract, exactAddress := objects[resource.Address]
	if resource.Mode != "managed" || !exactAddress {
		*violations = append(*violations, resource.Address+" is outside the two exact fixed recovery JSON-object addresses")
		return
	}
	actions := strings.Join(resource.Change.Actions, ",")
	if actions != "create" && actions != "update" && actions != "no-op" {
		*violations = append(*violations, resource.Address+" fixed recovery objects may only be created or updated in place")
	}
	requireEqual(after, "name", contract.name, resource.Address, violations)
	requireEqual(after, "content_type", "application/json", resource.Address, violations)
	requireEqual(after, "deletion_policy", "ABANDON", resource.Address, violations)
	if !plannedUnset(after["source"]) || topLevelUnknown(resource.Change.AfterUnknown, "content") {
		*violations = append(*violations, resource.Address+" must carry explicit inline JSON content")
	}
	bucket, _ := after["bucket"].(string)
	project := strings.TrimSuffix(bucket, contract.bucketSuffix)
	if !strings.HasSuffix(bucket, contract.bucketSuffix) || !googleProjectIDPattern.MatchString(project) || topLevelUnknown(resource.Change.AfterUnknown, "bucket") {
		*violations = append(*violations, resource.Address+" must target its exact protected recovery bucket")
	}
	if resource.Address == "module.recovery_exports.google_storage_bucket_object.restore_inventory" {
		validateRestoreInventoryContent(resource, after, bucket, violations)
	} else {
		validatePublicTrustMetadataContent(resource, after, violations)
	}
}

func validatePublicTrustMetadataContent(resource resourceChange, after map[string]any, violations *[]string) {
	content, _ := after["content"].(string)
	var metadata map[string]any
	if json.Unmarshal([]byte(content), &metadata) != nil {
		return
	}
	valid := exactObjectKeys(metadata, []string{
		"schema_version", "manifest_digests", "signing_key_versions", "signing_public_key_pem_sha256", "signing_windows",
		"federation_providers", "federation_audiences", "state_backends",
	}) && metadata["schema_version"] == float64(2)

	manifestPaths := []string{
		"manifests/audit-roots.yaml",
		"manifests/break-glass-roles.yaml",
		"manifests/identity-federation.yaml",
		"manifests/recovery-policy.yaml",
		"manifests/signing-roots.yaml",
		"manifests/state-backends.yaml",
		"manifests/trust-anchors.yaml",
	}
	digests, digestsOK := metadata["manifest_digests"].(map[string]any)
	valid = valid && digestsOK && exactObjectKeys(digests, manifestPaths)
	for _, path := range manifestPaths {
		digest, _ := digests[path].(string)
		valid = valid && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(digest)
	}

	versions, versionsOK := metadata["signing_key_versions"].(map[string]any)
	publicKeyDigests, publicKeyDigestsOK := metadata["signing_public_key_pem_sha256"].(map[string]any)
	windows, windowsOK := metadata["signing_windows"].(map[string]any)
	valid = valid && versionsOK && publicKeyDigestsOK && windowsOK && exactObjectKeys(versions, signingKeyNames) &&
		exactObjectKeys(publicKeyDigests, signingKeyNames) && exactObjectKeys(windows, recoverySigningWindowNames)
	signingProject := ""
	for _, key := range signingKeyNames {
		version, _ := versions[key].(string)
		publicKeyDigest, _ := publicKeyDigests[key].(string)
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(publicKeyDigest) || publicKeyDigest == strings.Repeat("0", 64) {
			valid = false
		}
		parts := strings.Split(version, "/")
		if len(parts) != 10 || parts[0] != "projects" || !googleProjectIDPattern.MatchString(parts[1]) ||
			parts[2] != "locations" || parts[3] != "us-central1" || parts[4] != "keyRings" || parts[5] != "bootstrap-signing" ||
			parts[6] != "cryptoKeys" || parts[7] != key || parts[8] != "cryptoKeyVersions" || !numericIDPattern.MatchString(parts[9]) {
			valid = false
		} else if signingProject == "" {
			signingProject = parts[1]
		} else if signingProject != parts[1] {
			valid = false
		}
	}
	for _, key := range recoverySigningWindowNames {
		window, _ := windows[key].(map[string]any)
		activeRef, _ := window["active_version_ref"].(string)
		startText, _ := window["activation_window_start"].(string)
		deadlineText, _ := window["rotation_deadline"].(string)
		start, startError := time.Parse(time.RFC3339, startText)
		deadline, deadlineError := time.Parse(time.RFC3339, deadlineText)
		valid = valid && exactObjectKeys(window, []string{"active_version_ref", "activation_window_start", "rotation_deadline"}) &&
			signingVersionPattern.MatchString(activeRef) && startError == nil && deadlineError == nil &&
			activeRef == "v"+start.UTC().Format("20060102") && startText == start.UTC().Format("2006-01-02T15:04:05Z") &&
			deadlineText == deadline.UTC().Format("2006-01-02T15:04:05Z") && deadline.Sub(start) == 90*24*time.Hour
		if resource.signingContract != nil && resource.signingContract.explicit {
			declaration, ok := signingKeyDeclaration(resource.signingContract, key)
			expected, versionOK := declaration.versions[declaration.activeVersionRef]
			valid = valid && ok && versionOK && activeRef == declaration.activeVersionRef &&
				startText == expected.activationWindowStart && deadlineText == expected.rotationDeadline
		}
	}

	federationKeys := []string{"github-plan", "github-apply", "github-recovery", "buildkite", "gitops"}
	providers, providersOK := metadata["federation_providers"].(map[string]any)
	audiences, audiencesOK := metadata["federation_audiences"].(map[string]any)
	valid = valid && providersOK && audiencesOK && exactObjectKeys(providers, federationKeys) && exactObjectKeys(audiences, federationKeys)
	identityProviderProject := ""
	recoveryProviderProject := ""
	expectedProviderIDs := map[string][2]string{
		"github-plan":     {"bootstrap-github-plan", "github-actions-plan"},
		"github-apply":    {"bootstrap-github-apply", "github-actions-apply"},
		"github-recovery": {"bootstrap-github-recovery", "github-actions-recovery"},
		"buildkite":       {"bootstrap-buildkite", "buildkite"},
		"gitops":          {"bootstrap-gitops", "gitops"},
	}
	for _, key := range federationKeys {
		provider, _ := providers[key].(string)
		parts := strings.Split(provider, "/")
		expected := expectedProviderIDs[key]
		if len(parts) != 8 || parts[0] != "projects" || !numericIDPattern.MatchString(parts[1]) || parts[2] != "locations" ||
			parts[3] != "global" || parts[4] != "workloadIdentityPools" || parts[5] != expected[0] || parts[6] != "providers" || parts[7] != expected[1] {
			valid = false
		} else if key == "github-recovery" {
			recoveryProviderProject = parts[1]
		} else if identityProviderProject == "" {
			identityProviderProject = parts[1]
		} else if identityProviderProject != parts[1] {
			valid = false
		}
		audience, _ := audiences[key].(string)
		valid = valid && audience != "" && !strings.ContainsAny(audience, "* \t\r\n") &&
			(audience == "sts.googleapis.com" || strings.HasPrefix(audience, "https://") || strings.HasPrefix(audience, "//iam.googleapis.com/"))
	}
	valid = valid && identityProviderProject != "" && recoveryProviderProject != "" && identityProviderProject != recoveryProviderProject

	backends, backendsOK := metadata["state_backends"].(map[string]any)
	valid = valid && backendsOK && exactObjectKeys(backends, recoveryStateExportKeys)
	allBuckets := map[string]bool{}
	for _, key := range recoveryStateExportKeys {
		backend, _ := backends[key].(map[string]any)
		bucket, _ := backend["bucket"].(string)
		replica, _ := backend["replica_bucket"].(string)
		valid = valid && exactObjectKeys(backend, []string{"bucket", "prefix", "replica_bucket"}) && backend["prefix"] == key &&
			validBucketName(bucket) && validBucketName(replica) && bucket != replica && !allBuckets[bucket] && !allBuckets[replica]
		allBuckets[bucket], allBuckets[replica] = true, true
	}
	if !valid {
		*violations = append(*violations, resource.Address+" must publish the exact manifest, signing, federation, and state-backend public trust contract")
	}
}

func exactObjectKeys(object map[string]any, expected []string) bool {
	if len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func validateRestoreInventoryContent(resource resourceChange, after map[string]any, exportBucket string, violations *[]string) {
	content, _ := after["content"].(string)
	var inventory map[string]any
	if json.Unmarshal([]byte(content), &inventory) != nil {
		return
	}
	valid := inventory["schema_version"] == float64(1) &&
		inventory["minimum_retained_state_generations"] == float64(3) &&
		exactStringSet(inventory["runtime_selection_required"], []string{"generation", "sha256"}) &&
		exactStringSet(inventory["excludes"], []string{"kms-private-key-material", "service-account-keys", "credentials"})
	digest, _ := inventory["restore_manifest_digest"].(string)
	valid = valid && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(digest)
	keys := stringSet(recoveryStateExportKeys...)
	sourceBuckets := map[string]bool{}
	for field, destination := range map[string]bool{"source_state_objects": false, "export_state_objects": true} {
		objects, ok := inventory[field].(map[string]any)
		if !ok || len(objects) != len(keys) {
			valid = false
			continue
		}
		for key := range keys {
			entry, ok := objects[key].(map[string]any)
			bucket, bucketOK := entry["bucket"].(string)
			objectName, objectOK := entry["object"].(string)
			if !ok || !bucketOK || !objectOK || !validBucketName(bucket) || objectName != key+"/default.tfstate" {
				valid = false
				continue
			}
			if destination {
				valid = valid && bucket == exportBucket
			} else {
				if sourceBuckets[bucket] {
					valid = false
				}
				sourceBuckets[bucket] = true
			}
		}
	}
	if !valid {
		*violations = append(*violations, resource.Address+" must declare the exact two state coordinates and runtime generation/sha256 restore contract")
	}
}

func validateRecoveryMetadataGraph(resources []resourceChange, violations *[]string) {
	public := fixedRecoveryJSON(resources, "module.recovery_exports.google_storage_bucket_object.public_trust_metadata")
	inventory := fixedRecoveryJSON(resources, "module.recovery_exports.google_storage_bucket_object.restore_inventory")
	if public == nil || inventory == nil {
		return
	}
	backends, _ := public["state_backends"].(map[string]any)
	sources, _ := inventory["source_state_objects"].(map[string]any)
	exports, _ := inventory["export_state_objects"].(map[string]any)
	if backends == nil || sources == nil || exports == nil {
		return
	}
	for _, key := range recoveryStateExportKeys {
		backend, _ := backends[key].(map[string]any)
		source, _ := sources[key].(map[string]any)
		exported, _ := exports[key].(map[string]any)
		sourceBucket, _ := source["bucket"].(string)
		exportBucket, _ := exported["bucket"].(string)
		expectedObject := key + "/default.tfstate"
		valid := backend != nil && source != nil && exported != nil && backend["bucket"] == sourceBucket && backend["prefix"] == key &&
			source["object"] == expectedObject && exported["object"] == expectedObject

		jobAddress := indexedResourceAddress("module.recovery_exports.google_storage_transfer_job.state_export", key)
		if job := resourceAfter(resources, jobAddress); job != nil {
			spec, _ := singleObject(job["replication_spec"])
			jobSource, _ := singleObject(spec["gcs_data_source"])
			jobSink, _ := singleObject(spec["gcs_data_sink"])
			conditions, _ := singleObject(spec["object_conditions"])
			valid = valid && jobSource["bucket_name"] == sourceBucket && jobSink["bucket_name"] == exportBucket &&
				exactStringSet(conditions["include_prefixes"], []string{expectedObject})
		}

		sourceBindingAddress := indexedResourceAddress("module.recovery_exports.google_storage_bucket_iam_member.state_export_source_object", key)
		if binding := resourceAfter(resources, sourceBindingAddress); binding != nil {
			valid = valid && binding["bucket"] == sourceBucket
		}
		destinationBindingAddress := indexedResourceAddress("module.recovery_exports.google_storage_bucket_iam_member.state_export_destination_object", key)
		if binding := resourceAfter(resources, destinationBindingAddress); binding != nil {
			valid = valid && binding["bucket"] == exportBucket
		}
		if !valid {
			*violations = append(*violations, fmt.Sprintf("recovery metadata, inventory, transfer job, and exact IAM bindings must agree on the %s state coordinates", key))
		}
	}
}

func fixedRecoveryJSON(resources []resourceChange, address string) map[string]any {
	after := resourceAfter(resources, address)
	content, _ := after["content"].(string)
	var result map[string]any
	if json.Unmarshal([]byte(content), &result) != nil {
		return nil
	}
	return result
}

func resourceAfter(resources []resourceChange, address string) map[string]any {
	for _, resource := range resources {
		if resource.Address == address {
			after, _ := resource.Change.After.(map[string]any)
			return after
		}
	}
	return nil
}

func collectUnknownLeafPaths(value any, path string, paths *[]string) {
	switch typed := value.(type) {
	case bool:
		if typed {
			*paths = append(*paths, path)
		}
	case map[string]any:
		for key, child := range typed {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			collectUnknownLeafPaths(child, childPath, paths)
		}
	case []any:
		for index, child := range typed {
			collectUnknownLeafPaths(child, fmt.Sprintf("%s[%d]", path, index), paths)
		}
	}
}

func exactUnknownLeafSet(value any, expected []string) bool {
	var actual []string
	collectUnknownLeafPaths(value, "", &actual)
	want := append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(want)
	if len(actual) != len(want) {
		return false
	}
	for index := range actual {
		if actual[index] != want[index] {
			return false
		}
	}
	return true
}

func exactTopLevelUnknowns(value any, expected []string) bool {
	if value == nil {
		return len(expected) == 0
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if object[key] != true {
			return false
		}
	}
	return true
}

func exactStringSet(value any, expected []string) bool {
	values, ok := value.([]any)
	if !ok || len(values) != len(expected) {
		return false
	}
	actual := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		item, ok := value.(string)
		if !ok || seen[item] {
			return false
		}
		seen[item] = true
		actual = append(actual, item)
	}
	want := append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(want)
	for index := range actual {
		if actual[index] != want[index] {
			return false
		}
	}
	return true
}

func singleObject(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, typed != nil
	case []any:
		if len(typed) != 1 {
			return nil, false
		}
		object, ok := typed[0].(map[string]any)
		return object, ok && object != nil
	}
	return nil, false
}

func plannedUnset(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	case bool:
		return !typed
	case []any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	}
	return false
}

func falseOrUnset(value any) bool {
	if value == nil {
		return true
	}
	result, ok := value.(bool)
	return ok && !result
}

func topLevelUnknown(value any, key string) bool {
	object, _ := value.(map[string]any)
	return containsUnknown(object[key])
}

func unsafeCondition(condition string) bool {
	normalized := strings.ToLower(strings.TrimSpace(condition))
	return normalized == "" || normalized == "true" || strings.Contains(normalized, "||") ||
		strings.Contains(normalized, "*") || strings.Contains(normalized, "?")
}

func requireEqual(object map[string]any, key string, expected any, path string, violations *[]string) {
	if object[key] != expected {
		*violations = append(*violations, fmt.Sprintf("%s must set %s to %v", path, key, expected))
	}
}

func firstObject(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case []any:
		if len(typed) > 0 {
			object, _ := typed[0].(map[string]any)
			return object
		}
	}
	return nil
}

func nestedBoolean(value any, key string) bool {
	result, _ := firstObject(value)[key].(bool)
	return result
}

func nestedString(value any, key string) string {
	result, _ := firstObject(value)[key].(string)
	return result
}

func nestedNumber(value any, key string) float64 {
	result, _ := firstObject(value)[key].(float64)
	return result
}

func nestedUnknown(value any, keys ...string) bool {
	current := value
	for _, key := range keys {
		object := firstObject(current)
		if object == nil {
			return false
		}
		current = object[key]
	}
	return containsUnknown(current)
}

func sensitiveField(key string) bool {
	if key == "plain_text_wo_version" || key == "secret_data_wo_version" {
		return false
	}
	for _, fragment := range []string{"access_key", "access_token", "api_token", "client_secret", "credential", "password", "plain_text_wo", "private_key", "refresh_token", "secret_data"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func securityRelevantField(key string) bool {
	if sensitiveField(key) {
		return true
	}
	switch key {
	case "billing_account_id", "bucket", "default_kms_key_name", "kms_key_name", "org_id", "project", "project_id", "service_account_id":
		return true
	}
	for _, fragment := range []string{
		"algorithm", "approval", "attribute_condition", "attribute_mapping", "audience", "billing_account",
		"deletion_policy", "deletion_protection", "eligible_users", "encryption", "force_destroy", "issuer_uri", "locked", "member",
		"principal", "protection_level", "public_access_prevention", "purpose", "retention", "role", "soft_delete",
		"uniform_bucket_level_access", "versioning",
	} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func transferOutputField(key string) bool {
	switch key {
	case "creation_time", "deletion_time", "last_modification_time", "name":
		return true
	}
	return false
}

func allowedUnknownSecurityValue(resource resourceChange, key string) bool {
	base := resource.Address
	if index := strings.IndexByte(base, '['); index >= 0 {
		base = base[:index]
	}
	if key == "default_kms_key_name" {
		return approvedUnknownBucketCMEK(resource)
	}
	if key == "soft_delete_policy" {
		return approvedStateBucketSoftDeleteUnknowns(resource)
	}
	if key == "client_secret" {
		return approvedInitialWorkforceSecretThumbprint(resource)
	}
	if resource.signingVersionCreateProof || resource.initialSigningCreateProof {
		after, _ := resource.Change.After.(map[string]any)
		if resource.signingVersionCreateProof && resource.Type == "google_kms_crypto_key_version" && key == "deletion_policy" {
			return exactInitialSigningVersionEnvelope(resource, after)
		}
		if resource.Address == "module.signing_root.google_kms_crypto_key_iam_member.recovery_metadata" && key == "role" {
			return exactInitialRecoveryMetadataEnvelope(resource, after)
		}
	}
	if key == "encryption" {
		return approvedStateBucketEncryptionUnknowns(resource)
	}
	if key == "kms_key_name" {
		return resource.Type == "google_logging_project_bucket_config" && base == "module.audit_root.google_logging_project_bucket_config.audit"
	}
	if key == "service_account_id" {
		return (resource.Mode == "data" && resource.Type == "google_logging_project_cmek_settings" && base == "module.audit_root.data.google_logging_project_cmek_settings.audit") ||
			approvedInitialAuditBucketServiceAccount(resource)
	}
	if resource.Type == "google_storage_transfer_job" && transferOutputField(key) {
		_, _, backendAddress := exactReplicationAddress(resource.Address, "google_storage_transfer_job.replication")
		_, exportAddress := exactRecoveryStateExportAddress(resource.Address, "google_storage_transfer_job.state_export")
		return resource.Mode == "managed" && (backendAddress || exportAddress)
	}
	if resource.Type == "google_kms_crypto_key_version" && (key == "algorithm" || key == "protection_level") {
		if resource.Mode == "data" {
			after, _ := resource.Change.After.(map[string]any)
			return base == "module.signing_root.data.google_kms_crypto_key_version.active" && activeSigningVersionDeferredEnvelope(resource, after)
		}
		_, _, ok := declaredSigningVersionAddress(resource.Address, resource.signingContract)
		return resource.Mode == "managed" && ok
	}
	if key != "member" && key != "members" && key != "principal" && key != "principals" {
		return false
	}
	after, _ := resource.Change.After.(map[string]any)
	role, _ := after["role"].(string)
	switch resource.Type {
	case "google_kms_crypto_key_iam_member":
		return role == "roles/cloudkms.cryptoKeyEncrypterDecrypter" && (base == "module.audit_root.google_kms_crypto_key_iam_member.logging" ||
			base == "module.recovery_exports.google_kms_crypto_key_iam_member.storage" ||
			base == "module.root_state.google_kms_crypto_key_iam_member.replica_service_agent" ||
			base == "module.root_state.google_kms_crypto_key_iam_member.state_service_agent" ||
			base == "module.recovery_state.google_kms_crypto_key_iam_member.replica_service_agent" ||
			base == "module.recovery_state.google_kms_crypto_key_iam_member.state_service_agent")
	case "google_project_iam_member":
		if _, _, ok := replicationBindingContract(resource.Type, resource.Address); ok {
			return approvedBinding(resource.Type, resource.Address, role)
		}
		if binding, ok := recoveryStateExportBindingDetails(resource.Type, resource.Address); ok {
			return binding.memberKind == "storage" && approvedBinding(resource.Type, resource.Address, role)
		}
		return role == "roles/logging.bucketWriter" && base == "module.audit_root.google_project_iam_member.sink_writer"
	case "google_service_account_iam_member":
		if binding, ok := recoveryStateExportBindingDetails(resource.Type, resource.Address); ok {
			return binding.memberKind == "transfer" && approvedBinding(resource.Type, resource.Address, role)
		}
		return role == "roles/iam.workloadIdentityUser" && (base == "module.buildkite_federation.google_service_account_iam_member.buildkite" ||
			base == "module.github_federation.google_service_account_iam_member.github" ||
			base == "module.github_federation.google_service_account_iam_member.ci_evidence" ||
			base == "module.github_federation.google_service_account_iam_member.github_config" ||
			base == "module.github_federation.google_service_account_iam_member.infrastructure_live" ||
			base == "module.github_federation.google_service_account_iam_member.infrastructure_drift" ||
			base == "module.gitops_federation.google_service_account_iam_member.gitops")
	case "google_storage_bucket_iam_member":
		if _, _, ok := replicationBindingContract(resource.Type, resource.Address); ok {
			return approvedBinding(resource.Type, resource.Address, role)
		}
	case "google_storage_transfer_project_service_account":
		_, _, backendAddress := exactReplicationAddress(resource.Address, "data.google_storage_transfer_project_service_account.replication")
		_, exportAddress := exactRecoveryStateExportAddress(resource.Address, "data.google_storage_transfer_project_service_account.state_export")
		return resource.Mode == "data" && (backendAddress || exportAddress)
	case "google_storage_project_service_account":
		return resource.Mode == "data" && approvedResourceAddress(resource)
	case "google_service_account":
		return resource.Mode == "managed" && approvedResourceAddress(resource)
	}
	return false
}

func containsUnknown(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case map[string]any:
		for _, child := range typed {
			if containsUnknown(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsUnknown(child) {
				return true
			}
		}
	}
	return false
}

func concreteScalar(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case map[string]any, []any:
		return false
	default:
		return true
	}
}
