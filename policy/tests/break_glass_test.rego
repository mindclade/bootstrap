package mindclade.bootstrap.break_glass

import rego.v1

valid_entitlement := {
	"roles": ["roles/iam.securityAdmin"],
	"maxDurationSeconds": 7200,
	"approval": {
		"requiredApprovals": 2,
		"justificationRequired": true,
		"allowSelfApproval": false,
	},
	"standingAccess": false,
}

valid_input := {
	"kind": "BreakGlassRoleSet",
	"spec": {
		"requesters": {
			"one": {"valueFrom": {"env": "REQUESTER_1"}},
			"two": {"valueFrom": {"env": "REQUESTER_2"}},
		},
		"approvers": {
			"one": {"valueFrom": {"env": "APPROVER_1"}},
			"two": {"valueFrom": {"env": "APPROVER_2"}},
		},
		"notificationRecipients": {"security": {"valueFrom": {"env": "SECURITY_NOTIFICATIONS"}}},
		"entitlements": {"root": valid_entitlement},
	},
}

test_gated_break_glass_is_allowed if {
	violations := deny with input as valid_input
	count(violations) == 0
}

test_self_approval_path_is_denied if {
	bad_spec := object.union(valid_input.spec, {"approvers": {
		"one": {"valueFrom": {"env": "REQUESTER_1"}},
		"two": {"valueFrom": {"env": "APPROVER_2"}},
	}})
	candidate := object.union(valid_input, {"spec": bad_spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "BREAK_GLASS_SELF_APPROVAL_PATH"
}

test_duplicate_requester_principals_are_denied if {
	bad_spec := object.union(valid_input.spec, {"requesters": {
		"one": {"valueFrom": {"env": "REQUESTER_1"}},
		"two": {"valueFrom": {"env": "REQUESTER_1"}},
	}})
	candidate := object.union(valid_input, {"spec": bad_spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "BREAK_GLASS_REQUESTER_DUPLICATE"
}

test_duplicate_approver_principals_are_denied if {
	bad_spec := object.union(valid_input.spec, {"approvers": {
		"one": {"valueFrom": {"env": "APPROVER_1"}},
		"two": {"valueFrom": {"env": "APPROVER_1"}},
	}})
	candidate := object.union(valid_input, {"spec": bad_spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "BREAK_GLASS_APPROVER_DUPLICATE"
}

test_long_duration_is_denied if {
	bad_entitlement := object.union(valid_entitlement, {"maxDurationSeconds": 7201})
	bad_spec := object.union(valid_input.spec, {"entitlements": {"root": bad_entitlement}})
	candidate := object.union(valid_input, {"spec": bad_spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "BREAK_GLASS_DURATION_EXCESSIVE"
}

test_primitive_role_is_denied if {
	bad_entitlement := object.union(valid_entitlement, {"roles": ["roles/owner"]})
	bad_spec := object.union(valid_input.spec, {"entitlements": {"root": bad_entitlement}})
	candidate := object.union(valid_input, {"spec": bad_spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "BREAK_GLASS_PRIMITIVE_ROLE"
}

test_primitive_viewer_role_is_denied if {
	bad_entitlement := object.union(valid_entitlement, {"roles": ["roles/viewer"]})
	bad_spec := object.union(valid_input.spec, {"entitlements": {"root": bad_entitlement}})
	candidate := object.union(valid_input, {"spec": bad_spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "BREAK_GLASS_PRIMITIVE_ROLE"
}

test_standing_access_is_denied if {
	bad_entitlement := object.union(valid_entitlement, {"standingAccess": true})
	bad_spec := object.union(valid_input.spec, {"entitlements": {"root": bad_entitlement}})
	candidate := object.union(valid_input, {"spec": bad_spec})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "BREAK_GLASS_STANDING_ACCESS"
}
