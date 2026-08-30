package mindclade.bootstrap.root_separation

import rego.v1

deny contains violation if {
	input.kind == "TrustAnchorSet"
	some left_id, left in input.spec.projects
	some right_id, right in input.spec.projects
	left_id < right_id
	left.projectId.valueFrom.env == right.projectId.valueFrom.env
	violation := {
		"code": "ROOT_PROJECT_COLLISION",
		"message": sprintf("logical projects %q and %q resolve from the same environment variable", [left_id, right_id]),
		"resource": sprintf("projects.%s", [left_id]),
	}
}

deny contains violation if {
	input.kind == "TrustAnchorSet"
	some project_id, project in input.spec.projects
	project_id != "recovery-root"
	project.plane != "root-trust"
	violation := {
		"code": "ROOT_PLANE_MISMATCH",
		"message": sprintf("project %q must remain in the root-trust plane", [project_id]),
		"resource": sprintf("projects.%s", [project_id]),
	}
}

deny contains violation if {
	input.kind == "TrustAnchorSet"
	input.spec.projects["recovery-root"].plane != "recovery"
	violation := {
		"code": "RECOVERY_PLANE_MISMATCH",
		"message": "recovery-root must remain in the recovery plane",
		"resource": "projects.recovery-root",
	}
}

deny contains violation if {
	input.kind == "TrustAnchorSet"
	input.spec.projects["recovery-root"].region == input.spec.geographicalBoundary.defaultLocation
	violation := {
		"code": "RECOVERY_REGION_COLLISION",
		"message": "recovery-root must use a region independent from the default root-trust region",
		"resource": "projects.recovery-root.region",
	}
}

deny contains violation if {
	input.kind == "TrustAnchorSet"
	input.spec.administratorPrincipals.root.valueFrom.env == input.spec.administratorPrincipals.recovery.valueFrom.env
	violation := {
		"code": "ROOT_ADMIN_COLLISION",
		"message": "root-trust and recovery administrators must resolve from different principals",
		"resource": "administratorPrincipals",
	}
}
