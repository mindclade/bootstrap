package mindclade.bootstrap.federation_claims

import rego.v1

valid_provider(platform, claims) := {
	"platform": platform,
	"subjectClaim": "assertion.sub",
	"requiredClaims": claims,
	"serviceAccounts": {"bootstrap": {"roles": ["roles/browser"]}},
}

valid_ci_evidence := {
	"platform": "github",
	"projectRef": "identity-root",
	"activationEnabled": false,
	"poolId": "github-ci-evidence",
	"issuerUri": {"valueFrom": {"env": "GITHUB_OIDC_ISSUER_URI"}},
	"subjectClaim": "assertion.sub",
	"repositoryOwnerId": {"literal": "316676129"},
	"repositoryIds": {
		"bootstrap": {"literal": "1350991612"},
		"dot-github": {"literal": "1350980188"},
		"github-config": {"literal": "1350986053"},
		"gitops": {"literal": "1350991963"},
		"infrastructure-live": {"literal": "1350992171"},
		"mindclade": {"literal": "1351193819"},
	},
	"writer": {
		"providerId": "writer",
		"jobWorkflowRef": {"valueFrom": {"env": "GITHUB_CI_EVIDENCE_JOB_WORKFLOW_REF"}},
		"allowedEvents": ["push", "release"],
		"branchRef": "refs/heads/main",
		"releaseTagPrefix": "refs/tags/v",
		"serviceAccount": {"projectRef": "identity-root", "accountId": "ci-evidence-writer", "roles": []},
	},
	"verifier": {
		"providerId": "verifier",
		"repositoryId": {"literal": "1350992171"},
		"workflowRef": {"literal": "mindclade/infrastructure-live/.github/workflows/disaster-recovery.yml@refs/heads/main"},
		"workflowSha": {"valueFrom": {"env": "INFRASTRUCTURE_LIVE_DISASTER_RECOVERY_WORKFLOW_SHA"}},
		"allowedEvents": ["workflow_dispatch"],
		"ref": {"literal": "refs/heads/main"},
		"environment": "infrastructure-apply",
		"serviceAccount": {"projectRef": "identity-root", "accountId": "ci-evidence-verifier", "roles": []},
	},
}

fixture_infrastructure_identity(identity, environment, audience_value) := {
	"providerId": identity,
	"environment": environment,
	"allowedAudience": {"literal": audience_value},
	"serviceAccount": {
		"projectRef": "identity-root",
		"accountId": identity,
		"roles": [],
	},
}

valid_infrastructure := {
	"platform": "github",
	"projectRef": "identity-root",
	"poolId": "infrastructure-live",
	"issuerUri": {"valueFrom": {"env": "GITHUB_OIDC_ISSUER_URI"}},
	"subjectClaim": "assertion.sub",
	"repositoryOwnerId": {"literal": "316676129"},
	"repositoryId": {"literal": "1350992171"},
	"immutableRepository": {"literal": "mindclade@316676129/infrastructure-live@1350992171"},
	"repositoryFullName": {"literal": "mindclade/infrastructure-live"},
	"branchRef": {"literal": "refs/heads/main"},
	"workflowRef": {"literal": "mindclade/infrastructure-live/.github/workflows/protected-apply.yml@refs/heads/main"},
	"identities": {
		"development-plan": fixture_infrastructure_identity("development-plan", "trusted-build", "https://github.mindclade.io/oidc/infrastructure-live/development/plan"),
		"development-apply": fixture_infrastructure_identity("development-apply", "infrastructure-apply", "https://github.mindclade.io/oidc/infrastructure-live/development/apply"),
		"staging-plan": fixture_infrastructure_identity("staging-plan", "trusted-build", "https://github.mindclade.io/oidc/infrastructure-live/staging/plan"),
		"staging-apply": fixture_infrastructure_identity("staging-apply", "infrastructure-apply", "https://github.mindclade.io/oidc/infrastructure-live/staging/apply"),
		"production-plan": fixture_infrastructure_identity("production-plan", "trusted-build", "https://github.mindclade.io/oidc/infrastructure-live/production/plan"),
		"production-apply": fixture_infrastructure_identity("production-apply", "infrastructure-apply", "https://github.mindclade.io/oidc/infrastructure-live/production/apply"),
		"restricted-plan": fixture_infrastructure_identity("restricted-plan", "trusted-build", "https://github.mindclade.io/oidc/infrastructure-live/restricted/plan"),
		"restricted-apply": fixture_infrastructure_identity("restricted-apply", "infrastructure-apply", "https://github.mindclade.io/oidc/infrastructure-live/restricted/apply"),
	},
}

valid_input := {
	"kind": "IdentityFederation",
	"spec": {
		"activation": {"state": "FOUNDER_BOOTSTRAPPED"},
		"workloadIdentityProviders": {
			"github": valid_provider("github", {
				"repository_owner_id": {"valueFrom": {"env": "OWNER_ID"}},
				"repository_id": {"valueFrom": {"env": "REPOSITORY_ID"}},
				"ref": {"literal": "refs/heads/main"},
				"workflow_ref": {"valueFrom": {"env": "WORKFLOW_REF"}},
			}),
			"github-ci-evidence": valid_ci_evidence,
			"github-infrastructure": valid_infrastructure,
			"buildkite": valid_provider("buildkite", {
				"organization_slug": {"valueFrom": {"env": "ORGANIZATION_SLUG"}},
				"pipeline_slug": {"valueFrom": {"env": "PIPELINE_SLUG"}},
				"pipeline_id": {"valueFrom": {"env": "PIPELINE_ID"}},
				"build_branch": {"literal": "main"},
				"step_key": {"literal": "bootstrap-ring0-signing"},
			}),
			"gitops": valid_provider("gitops", {
				"repository": {"valueFrom": {"env": "GITOPS_REPOSITORY"}},
				"ref": {"literal": "refs/heads/main"},
				"subject": {"valueFrom": {"env": "GITOPS_SUBJECT"}},
			}),
		},
	},
}

test_exact_claims_are_allowed if {
	violations := deny with input as valid_input
	count(violations) == 0
}

test_missing_immutable_claim_is_denied if {
	claims := {
		"repository_owner_id": {"valueFrom": {"env": "OWNER_ID"}},
		"ref": {"literal": "refs/heads/main"},
		"workflow_ref": {"valueFrom": {"env": "WORKFLOW_REF"}},
	}
	candidate := {
		"kind": "IdentityFederation",
		"spec": {"workloadIdentityProviders": {"github": valid_provider("github", claims)}},
	}
	violations := deny with input as candidate
	some violation in violations
	violation.code == "FEDERATION_REQUIRED_CLAIM_MISSING"
}

test_wildcard_claim_is_denied if {
	github_claims := object.union(valid_input.spec.workloadIdentityProviders.github.requiredClaims, {"ref": {"literal": "refs/heads/*"}})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github": object.union(valid_input.spec.workloadIdentityProviders.github, {"requiredClaims": github_claims})})
	candidate := object.union(valid_input, {"spec": {"workloadIdentityProviders": providers}})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "FEDERATION_WILDCARD_CLAIM"
	violation.resource == "workloadIdentityProviders.github.requiredClaims.ref"
}

test_primitive_role_is_denied if {
	bad_github := object.union(valid_input.spec.workloadIdentityProviders.github, {"serviceAccounts": {"bootstrap": {"roles": ["roles/owner"]}}})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github": bad_github})
	candidate := object.union(valid_input, {"spec": {"workloadIdentityProviders": providers}})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "FEDERATION_PRIMITIVE_ROLE"
}

test_primitive_viewer_role_is_denied if {
	bad_github := object.union(valid_input.spec.workloadIdentityProviders.github, {"serviceAccounts": {"bootstrap": {"roles": ["roles/viewer"]}}})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github": bad_github})
	candidate := object.union(valid_input, {"spec": {"workloadIdentityProviders": providers}})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "FEDERATION_PRIMITIVE_ROLE"
}

test_ci_evidence_activation_is_fail_closed if {
	bad_evidence := object.union(valid_ci_evidence, {"activationEnabled": true})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github-ci-evidence": bad_evidence})
	spec := object.union(valid_input.spec, {"workloadIdentityProviders": providers})
	candidate := object.union(valid_input, {"spec": spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "CI_EVIDENCE_ACTIVATION_NOT_QUALIFIED"
}

test_blocked_ci_evidence_activation_is_fail_closed if {
	bad_evidence := object.union(valid_ci_evidence, {"activationEnabled": true})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github-ci-evidence": bad_evidence})
	blocked_spec := object.union(valid_input.spec, {"activation": {"state": "BLOCKED"}, "workloadIdentityProviders": providers})
	candidate := object.union(valid_input, {"spec": blocked_spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "CI_EVIDENCE_ACTIVATION_NOT_QUALIFIED"
}

test_ci_evidence_arbitrary_audience_is_denied if {
	bad_writer := object.union(valid_ci_evidence.writer, {"allowedAudience": {"literal": "https://attacker.example/audience"}})
	bad_evidence := object.union(valid_ci_evidence, {"writer": bad_writer})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github-ci-evidence": bad_evidence})
	candidate := object.union(valid_input, {"spec": {"workloadIdentityProviders": providers}})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "CI_EVIDENCE_WRITER_INVALID"
}

test_ci_evidence_unknown_repository_is_denied if {
	bad_repositories := object.union(valid_ci_evidence.repositoryIds, {"unknown": {"literal": "999"}})
	bad_evidence := object.union(valid_ci_evidence, {"repositoryIds": bad_repositories})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github-ci-evidence": bad_evidence})
	candidate := object.union(valid_input, {"spec": {"workloadIdentityProviders": providers}})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "CI_EVIDENCE_REPOSITORY_ALLOWLIST_INVALID"
}

test_ci_evidence_writer_may_not_receive_bucket_role_here if {
	bad_account := object.union(valid_ci_evidence.writer.serviceAccount, {"roles": ["roles/storage.objectCreator"]})
	bad_writer := object.union(valid_ci_evidence.writer, {"serviceAccount": bad_account})
	bad_evidence := object.union(valid_ci_evidence, {"writer": bad_writer})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github-ci-evidence": bad_evidence})
	candidate := object.union(valid_input, {"spec": {"workloadIdentityProviders": providers}})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "CI_EVIDENCE_WRITER_INVALID"
}

test_ci_evidence_writer_and_verifier_accounts_are_distinct if {
	bad_account := object.union(valid_ci_evidence.verifier.serviceAccount, {"accountId": "ci-evidence-writer"})
	bad_verifier := object.union(valid_ci_evidence.verifier, {"serviceAccount": bad_account})
	bad_evidence := object.union(valid_ci_evidence, {"verifier": bad_verifier})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github-ci-evidence": bad_evidence})
	candidate := object.union(valid_input, {"spec": {"workloadIdentityProviders": providers}})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "CI_EVIDENCE_VERIFIER_INVALID"
}

test_infrastructure_live_arbitrary_audience_is_denied if {
	bad_identity := object.union(valid_infrastructure.identities["production-apply"], {"allowedAudience": {"literal": "sts.googleapis.com"}})
	bad_identities := object.union(valid_infrastructure.identities, {"production-apply": bad_identity})
	bad_infrastructure := object.union(valid_infrastructure, {"identities": bad_identities})
	providers := object.union(valid_input.spec.workloadIdentityProviders, {"github-infrastructure": bad_infrastructure})
	candidate := object.union(valid_input, {"spec": {"workloadIdentityProviders": providers}})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "INFRASTRUCTURE_FEDERATION_IDENTITY_INVALID"
}
