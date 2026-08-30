package mindclade.bootstrap.root_separation

import rego.v1

valid_input := {
	"kind": "TrustAnchorSet",
	"spec": {
		"projects": {
			"state-root": {"projectId": {"valueFrom": {"env": "STATE_PROJECT"}}, "plane": "root-trust", "region": "us-central1"},
			"audit-root": {"projectId": {"valueFrom": {"env": "AUDIT_PROJECT"}}, "plane": "root-trust", "region": "us-central1"},
			"identity-root": {"projectId": {"valueFrom": {"env": "IDENTITY_PROJECT"}}, "plane": "root-trust", "region": "us-central1"},
			"signing-root": {"projectId": {"valueFrom": {"env": "SIGNING_PROJECT"}}, "plane": "root-trust", "region": "us-central1"},
			"recovery-root": {"projectId": {"valueFrom": {"env": "RECOVERY_PROJECT"}}, "plane": "recovery", "region": "us-east4"},
		},
		"administratorPrincipals": {
			"root": {"valueFrom": {"env": "ROOT_ADMIN"}},
			"recovery": {"valueFrom": {"env": "RECOVERY_ADMIN"}},
		},
		"geographicalBoundary": {"defaultLocation": "us-central1"},
	},
}

test_separated_roots_are_allowed if {
	violations := deny with input as valid_input
	count(violations) == 0
}

test_duplicate_project_is_denied if {
	candidate := object.union_n([valid_input, {"spec": object.union(valid_input.spec, {"projects": object.union(valid_input.spec.projects, {"recovery-root": object.union(valid_input.spec.projects["recovery-root"], {"projectId": {"valueFrom": {"env": "STATE_PROJECT"}}})})})}])
	violations := deny with input as candidate
	some violation in violations
	violation.code == "ROOT_PROJECT_COLLISION"
	violation.resource == "projects.recovery-root"
}

test_shared_administrator_is_denied if {
	candidate := object.union_n([valid_input, {"spec": object.union(valid_input.spec, {"administratorPrincipals": {
		"root": {"valueFrom": {"env": "SHARED_ADMIN"}},
		"recovery": {"valueFrom": {"env": "SHARED_ADMIN"}},
	}})}])
	violations := deny with input as candidate
	some violation in violations
	violation.code == "ROOT_ADMIN_COLLISION"
}
