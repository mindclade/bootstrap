package mindclade.bootstrap.federation_claims

import rego.v1

valid_provider(platform, claims) := {
	"platform": platform,
	"subjectClaim": "assertion.sub",
	"requiredClaims": claims,
	"serviceAccounts": {"bootstrap": {"roles": ["roles/browser"]}},
}

valid_input := {
	"kind": "IdentityFederation",
	"spec": {"workloadIdentityProviders": {
		"github": valid_provider("github", {
			"repository_owner_id": {"valueFrom": {"env": "OWNER_ID"}},
			"repository_id": {"valueFrom": {"env": "REPOSITORY_ID"}},
			"ref": {"literal": "refs/heads/main"},
			"workflow_ref": {"valueFrom": {"env": "WORKFLOW_REF"}},
		}),
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
	}},
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
