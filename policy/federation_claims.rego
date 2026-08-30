package mindclade.bootstrap.federation_claims

import rego.v1

required_claims := {
	"github": {"repository_owner_id", "repository_id", "ref", "workflow_ref"},
	"buildkite": {"organization_slug", "pipeline_slug", "pipeline_id", "build_branch", "step_key"},
	"gitops": {"repository", "ref", "subject"},
}

has_wildcard(value) if {
	contains(value, "*")
}

has_wildcard(value) if {
	contains(value, "?")
}

deny contains violation if {
	input.kind == "IdentityFederation"
	some provider_id, provider in input.spec.workloadIdentityProviders
	provider.platform != provider_id
	violation := {
		"code": "FEDERATION_PLATFORM_MISMATCH",
		"message": sprintf("provider %q declares platform %q", [provider_id, provider.platform]),
		"resource": sprintf("workloadIdentityProviders.%s", [provider_id]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	some provider_id, provider in input.spec.workloadIdentityProviders
	required := required_claims[provider_id]
	some claim in required
	object.get(provider.requiredClaims, claim, null) == null
	violation := {
		"code": "FEDERATION_REQUIRED_CLAIM_MISSING",
		"message": sprintf("provider %q does not bind immutable claim %q", [provider_id, claim]),
		"resource": sprintf("workloadIdentityProviders.%s.requiredClaims", [provider_id]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	some provider_id, provider in input.spec.workloadIdentityProviders
	required := required_claims[provider_id]
	some claim, _ in provider.requiredClaims
	not required[claim]
	violation := {
		"code": "FEDERATION_UNEXPECTED_CLAIM",
		"message": sprintf("provider %q uses unreviewed claim %q", [provider_id, claim]),
		"resource": sprintf("workloadIdentityProviders.%s.requiredClaims.%s", [provider_id, claim]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	some provider_id, provider in input.spec.workloadIdentityProviders
	some claim, expectation in provider.requiredClaims
	literal := expectation.literal
	has_wildcard(literal)
	violation := {
		"code": "FEDERATION_WILDCARD_CLAIM",
		"message": sprintf("provider %q claim %q must be an exact value", [provider_id, claim]),
		"resource": sprintf("workloadIdentityProviders.%s.requiredClaims.%s", [provider_id, claim]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	some provider_id, provider in input.spec.workloadIdentityProviders
	provider.subjectClaim != "assertion.sub"
	violation := {
		"code": "FEDERATION_MUTABLE_SUBJECT",
		"message": sprintf("provider %q must derive its subject from assertion.sub", [provider_id]),
		"resource": sprintf("workloadIdentityProviders.%s.subjectClaim", [provider_id]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	some provider_id, provider in input.spec.workloadIdentityProviders
	some account_id, account in provider.serviceAccounts
	some role in account.roles
	role in {"roles/owner", "roles/editor", "roles/viewer"}
	violation := {
		"code": "FEDERATION_PRIMITIVE_ROLE",
		"message": sprintf("provider %q service account %q may not receive primitive role %q", [provider_id, account_id, role]),
		"resource": sprintf("workloadIdentityProviders.%s.serviceAccounts.%s", [provider_id, account_id]),
	}
}
