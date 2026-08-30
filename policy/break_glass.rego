package mindclade.bootstrap.break_glass

import rego.v1

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	count(input.spec.requesters) < 2
	violation := {
		"code": "BREAK_GLASS_REQUESTERS_INSUFFICIENT",
		"message": "break-glass access requires at least two named human requesters",
		"resource": "requesters",
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	count(input.spec.approvers) < 2
	violation := {
		"code": "BREAK_GLASS_APPROVERS_INSUFFICIENT",
		"message": "break-glass access requires at least two security approvers",
		"resource": "approvers",
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some left_id, left in input.spec.requesters
	some right_id, right in input.spec.requesters
	left_id < right_id
	left.valueFrom.env == right.valueFrom.env
	violation := {
		"code": "BREAK_GLASS_REQUESTER_DUPLICATE",
		"message": sprintf("requesters %q and %q resolve from the same principal", [left_id, right_id]),
		"resource": "requesters",
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some left_id, left in input.spec.approvers
	some right_id, right in input.spec.approvers
	left_id < right_id
	left.valueFrom.env == right.valueFrom.env
	violation := {
		"code": "BREAK_GLASS_APPROVER_DUPLICATE",
		"message": sprintf("approvers %q and %q resolve from the same principal", [left_id, right_id]),
		"resource": "approvers",
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some requester_id, requester in input.spec.requesters
	some approver_id, approver in input.spec.approvers
	requester.valueFrom.env == approver.valueFrom.env
	violation := {
		"code": "BREAK_GLASS_SELF_APPROVAL_PATH",
		"message": sprintf("requester %q and approver %q resolve from the same principal", [requester_id, approver_id]),
		"resource": "approvers",
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some entitlement_id, entitlement in input.spec.entitlements
	duration := object.get(entitlement, "maxDurationSeconds", 0)
	duration <= 0
	violation := {
		"code": "BREAK_GLASS_DURATION_INVALID",
		"message": sprintf("entitlement %q must have a positive maximum duration", [entitlement_id]),
		"resource": sprintf("entitlements.%s.maxDurationSeconds", [entitlement_id]),
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some entitlement_id, entitlement in input.spec.entitlements
	object.get(entitlement, "maxDurationSeconds", 7201) > 7200
	violation := {
		"code": "BREAK_GLASS_DURATION_EXCESSIVE",
		"message": sprintf("entitlement %q may not exceed two hours", [entitlement_id]),
		"resource": sprintf("entitlements.%s.maxDurationSeconds", [entitlement_id]),
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some entitlement_id, entitlement in input.spec.entitlements
	object.get(entitlement.approval, "requiredApprovals", 0) < 2
	violation := {
		"code": "BREAK_GLASS_APPROVALS_INSUFFICIENT",
		"message": sprintf("entitlement %q requires two independent approvals", [entitlement_id]),
		"resource": sprintf("entitlements.%s.approval.requiredApprovals", [entitlement_id]),
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some entitlement_id, entitlement in input.spec.entitlements
	object.get(entitlement.approval, "justificationRequired", false) != true
	violation := {
		"code": "BREAK_GLASS_JUSTIFICATION_DISABLED",
		"message": sprintf("entitlement %q must require a justification", [entitlement_id]),
		"resource": sprintf("entitlements.%s.approval.justificationRequired", [entitlement_id]),
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some entitlement_id, entitlement in input.spec.entitlements
	object.get(entitlement.approval, "allowSelfApproval", true) != false
	violation := {
		"code": "BREAK_GLASS_SELF_APPROVAL_ENABLED",
		"message": sprintf("entitlement %q may not allow self-approval", [entitlement_id]),
		"resource": sprintf("entitlements.%s.approval.allowSelfApproval", [entitlement_id]),
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some entitlement_id, entitlement in input.spec.entitlements
	object.get(entitlement, "standingAccess", true) != false
	violation := {
		"code": "BREAK_GLASS_STANDING_ACCESS",
		"message": sprintf("entitlement %q may grant access only through an approved request", [entitlement_id]),
		"resource": sprintf("entitlements.%s.standingAccess", [entitlement_id]),
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	some entitlement_id, entitlement in input.spec.entitlements
	some role in entitlement.roles
	role in {"roles/owner", "roles/editor", "roles/viewer"}
	violation := {
		"code": "BREAK_GLASS_PRIMITIVE_ROLE",
		"message": sprintf("entitlement %q may not grant primitive role %q", [entitlement_id, role]),
		"resource": sprintf("entitlements.%s.roles", [entitlement_id]),
	}
}

deny contains violation if {
	input.kind == "BreakGlassRoleSet"
	count(input.spec.notificationRecipients) < 1
	violation := {
		"code": "BREAK_GLASS_NOTIFICATION_MISSING",
		"message": "break-glass activation must notify security operations",
		"resource": "notificationRecipients",
	}
}
