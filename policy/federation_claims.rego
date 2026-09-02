package mindclade.bootstrap.federation_claims

import rego.v1

required_claims := {
	"github": {"repository_owner_id", "repository_id", "ref", "workflow_ref"},
	"buildkite": {"organization_slug", "pipeline_slug", "pipeline_id", "build_branch", "step_key"},
	"gitops": {"repository", "ref", "subject"},
}

legacy_provider(provider_id) if {
	provider_id in {"github", "buildkite", "gitops"}
}

ci_evidence_repository_ids := {
	"bootstrap": "1350991612",
	"dot-github": "1350980188",
	"github-config": "1350986053",
	"gitops": "1350991963",
	"infrastructure-live": "1350992171",
	"mindclade": "1351193819",
}

infrastructure_identities := {
	"development-plan": {"environment": "trusted-build", "audience": "https://github.mindclade.io/oidc/infrastructure-live/development/plan"},
	"development-apply": {"environment": "infrastructure-apply", "audience": "https://github.mindclade.io/oidc/infrastructure-live/development/apply"},
	"staging-plan": {"environment": "trusted-build", "audience": "https://github.mindclade.io/oidc/infrastructure-live/staging/plan"},
	"staging-apply": {"environment": "infrastructure-apply", "audience": "https://github.mindclade.io/oidc/infrastructure-live/staging/apply"},
	"production-plan": {"environment": "trusted-build", "audience": "https://github.mindclade.io/oidc/infrastructure-live/production/plan"},
	"production-apply": {"environment": "infrastructure-apply", "audience": "https://github.mindclade.io/oidc/infrastructure-live/production/apply"},
	"restricted-plan": {"environment": "trusted-build", "audience": "https://github.mindclade.io/oidc/infrastructure-live/restricted/plan"},
	"restricted-apply": {"environment": "infrastructure-apply", "audience": "https://github.mindclade.io/oidc/infrastructure-live/restricted/apply"},
}

valid_infrastructure_boundary(provider) if {
	provider.platform == "github"
	provider.projectRef == "identity-root"
	provider.poolId == "infrastructure-live"
	provider.issuerUri.valueFrom.env == "GITHUB_OIDC_ISSUER_URI"
	provider.subjectClaim == "assertion.sub"
	provider.repositoryOwnerId.literal == "316676129"
	provider.repositoryId.literal == "1350992171"
	provider.immutableRepository.literal == "mindclade@316676129/infrastructure-live@1350992171"
	provider.repositoryFullName.literal == "mindclade/infrastructure-live"
	provider.branchRef.literal == "refs/heads/main"
	provider.workflowRef.literal == "mindclade/infrastructure-live/.github/workflows/protected-apply.yml@refs/heads/main"
}

valid_infrastructure_identity(identity_key, identity) if {
	contract := infrastructure_identities[identity_key]
	identity.providerId == identity_key
	identity.environment == contract.environment
	identity.allowedAudience.literal == contract.audience
	identity.serviceAccount.projectRef == "identity-root"
	identity.serviceAccount.accountId == identity_key
	count(identity.serviceAccount.roles) == 0
}

valid_ci_evidence_boundary(provider) if {
	provider.platform == "github"
	provider.projectRef == "identity-root"
	provider.poolId == "github-ci-evidence"
	provider.subjectClaim == "assertion.sub"
	provider.issuerUri.valueFrom.env == "GITHUB_OIDC_ISSUER_URI"
}

valid_ci_evidence_writer(writer) if {
	writer.providerId == "writer"
	object.get(writer, "allowedAudience", null) == null
	writer.jobWorkflowRef.valueFrom.env == "GITHUB_CI_EVIDENCE_JOB_WORKFLOW_REF"
	writer.allowedEvents == ["push", "release"]
	writer.branchRef == "refs/heads/main"
	writer.releaseTagPrefix == "refs/tags/v"
	writer.serviceAccount.projectRef == "identity-root"
	writer.serviceAccount.accountId == "ci-evidence-writer"
	count(writer.serviceAccount.roles) == 0
}

valid_ci_evidence_verifier(verifier) if {
	verifier.providerId == "verifier"
	object.get(verifier, "allowedAudience", null) == null
	verifier.repositoryId.literal == ci_evidence_repository_ids["infrastructure-live"]
	verifier.workflowRef.literal == "mindclade/infrastructure-live/.github/workflows/disaster-recovery.yml@refs/heads/main"
	verifier.workflowSha.valueFrom.env == "INFRASTRUCTURE_LIVE_DISASTER_RECOVERY_WORKFLOW_SHA"
	verifier.allowedEvents == ["workflow_dispatch"]
	verifier.ref.literal == "refs/heads/main"
	verifier.environment == "infrastructure-apply"
	verifier.serviceAccount.projectRef == "identity-root"
	verifier.serviceAccount.accountId == "ci-evidence-verifier"
	count(verifier.serviceAccount.roles) == 0
}

has_wildcard(value) if {
	contains(value, "*")
}

valid_bootstrap_visibility_transition(transition) if {
	transition.state == "AWAITING_PRIVATE_VISIBILITY"
	transition.activationEnabled == false
	transition.sourceVisibility == "public"
	transition.finalVisibility == "private"
	transition.repositoryFullName == "mindclade/bootstrap"
	transition.repositoryOwnerId == "316676129"
	transition.repositoryId == "1350991612"
	transition.executorRepositoryEnabled == false
	transition.executorRepositoryId == null
	transition.requiredReviewerGates == ["security", "platform"]
	transition.visibilityEvidenceDigest == null
	transition.reviewerEvidenceDigest == null
	transition.blockers == ["private-visibility-not-evidenced", "independent-review-not-evidenced"]
}

valid_bootstrap_visibility_transition(transition) if {
	transition.state == "PRIVATE_QUALIFIED"
	transition.activationEnabled == true
	transition.sourceVisibility == "public"
	transition.finalVisibility == "private"
	transition.repositoryFullName == "mindclade/bootstrap"
	transition.repositoryOwnerId == "316676129"
	transition.repositoryId == "1350991612"
	transition.executorRepositoryEnabled == false
	transition.executorRepositoryId == null
	transition.requiredReviewerGates == ["security", "platform"]
	regex.match("^[0-9a-f]{64}$", transition.visibilityEvidenceDigest)
	regex.match("[1-9a-f]", transition.visibilityEvidenceDigest)
	regex.match("^[0-9a-f]{64}$", transition.reviewerEvidenceDigest)
	regex.match("[1-9a-f]", transition.reviewerEvidenceDigest)
	count(transition.blockers) == 0
}

deny contains violation if {
	input.kind == "IdentityFederation"
	transition := object.get(input.spec, "bootstrapVisibilityTransition", {})
	not valid_bootstrap_visibility_transition(transition)
	violation := {
		"code": "BOOTSTRAP_VISIBILITY_TRANSITION_INVALID",
		"message": "bootstrap OIDC must remain disabled until the exact repository is privately visible and independently reviewed; an executor repository is forbidden",
		"resource": "bootstrapVisibilityTransition",
	}
}

has_wildcard(value) if {
	contains(value, "?")
}

deny contains violation if {
	input.kind == "IdentityFederation"
	some provider_id, provider in input.spec.workloadIdentityProviders
	legacy_provider(provider_id)
	provider.platform != provider_id
	violation := {
		"code": "FEDERATION_PLATFORM_MISMATCH",
		"message": sprintf("provider %q declares platform %q", [provider_id, provider.platform]),
		"resource": sprintf("workloadIdentityProviders.%s", [provider_id]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-infrastructure"]
	not valid_infrastructure_boundary(provider)
	violation := {
		"code": "INFRASTRUCTURE_FEDERATION_BOUNDARY_INVALID",
		"message": "infrastructure-live federation must bind its exact immutable GitHub repository and protected main workflow",
		"resource": "workloadIdentityProviders.github-infrastructure",
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-infrastructure"]
	object.keys(provider.identities) != object.keys(infrastructure_identities)
	violation := {
		"code": "INFRASTRUCTURE_FEDERATION_IDENTITY_SET_INVALID",
		"message": "infrastructure-live federation must expose exactly eight environment/role identities",
		"resource": "workloadIdentityProviders.github-infrastructure.identities",
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-infrastructure"]
	some identity_key, identity in provider.identities
	not valid_infrastructure_identity(identity_key, identity)
	violation := {
		"code": "INFRASTRUCTURE_FEDERATION_IDENTITY_INVALID",
		"message": sprintf("infrastructure-live identity %q must retain its exact provider, account, environment, and singleton audience", [identity_key]),
		"resource": sprintf("workloadIdentityProviders.github-infrastructure.identities.%s", [identity_key]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	some provider_id, provider in input.spec.workloadIdentityProviders
	legacy_provider(provider_id)
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
	legacy_provider(provider_id)
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
	legacy_provider(provider_id)
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
	legacy_provider(provider_id)
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
	legacy_provider(provider_id)
	some account_id, account in provider.serviceAccounts
	some role in account.roles
	role in {"roles/owner", "roles/editor", "roles/viewer"}
	violation := {
		"code": "FEDERATION_PRIMITIVE_ROLE",
		"message": sprintf("provider %q service account %q may not receive primitive role %q", [provider_id, account_id, role]),
		"resource": sprintf("workloadIdentityProviders.%s.serviceAccounts.%s", [provider_id, account_id]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-ci-evidence"]
	input.spec.activation.state in {"BLOCKED", "FOUNDER_BOOTSTRAPPED"}
	provider.activationEnabled != false
	violation := {
		"code": "CI_EVIDENCE_ACTIVATION_NOT_QUALIFIED",
		"message": "CI evidence federation must remain disabled until the lifecycle is CONNECTED_QUALIFIED",
		"resource": "workloadIdentityProviders.github-ci-evidence.activationEnabled",
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-ci-evidence"]
	input.spec.activation.state == "CONNECTED_QUALIFIED"
	provider.activationEnabled != true
	violation := {
		"code": "CI_EVIDENCE_ACTIVATION_NOT_QUALIFIED",
		"message": "CI evidence federation must be enabled in the connected-qualified lifecycle",
		"resource": "workloadIdentityProviders.github-ci-evidence.activationEnabled",
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-ci-evidence"]
	not valid_ci_evidence_boundary(provider)
	violation := {
		"code": "CI_EVIDENCE_TRUST_BOUNDARY_INVALID",
		"message": "CI evidence must use its dedicated canonical GitHub trust boundary",
		"resource": "workloadIdentityProviders.github-ci-evidence",
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-ci-evidence"]
	provider.repositoryOwnerId.literal != "316676129"
	violation := {
		"code": "CI_EVIDENCE_OWNER_ID_INVALID",
		"message": "CI evidence must bind Mindclade's immutable GitHub owner ID",
		"resource": "workloadIdentityProviders.github-ci-evidence.repositoryOwnerId",
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-ci-evidence"]
	some repository, repository_id in ci_evidence_repository_ids
	provider.repositoryIds[repository].literal != repository_id
	violation := {
		"code": "CI_EVIDENCE_REPOSITORY_ID_INVALID",
		"message": sprintf("CI evidence repository %q must use immutable ID %q", [repository, repository_id]),
		"resource": sprintf("workloadIdentityProviders.github-ci-evidence.repositoryIds.%s", [repository]),
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-ci-evidence"]
	object.keys(provider.repositoryIds) != object.keys(ci_evidence_repository_ids)
	violation := {
		"code": "CI_EVIDENCE_REPOSITORY_ALLOWLIST_INVALID",
		"message": "CI evidence must bind exactly the six approved repository IDs",
		"resource": "workloadIdentityProviders.github-ci-evidence.repositoryIds",
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-ci-evidence"]
	not valid_ci_evidence_writer(provider.writer)
	violation := {
		"code": "CI_EVIDENCE_WRITER_INVALID",
		"message": "CI evidence writer must remain a keyless, workflow-bound, role-free handoff identity",
		"resource": "workloadIdentityProviders.github-ci-evidence.writer",
	}
}

deny contains violation if {
	input.kind == "IdentityFederation"
	provider := input.spec.workloadIdentityProviders["github-ci-evidence"]
	not valid_ci_evidence_verifier(provider.verifier)
	violation := {
		"code": "CI_EVIDENCE_VERIFIER_INVALID",
		"message": "CI evidence verifier must remain a keyless, recovery-workflow-bound, role-free handoff identity",
		"resource": "workloadIdentityProviders.github-ci-evidence.verifier",
	}
}
