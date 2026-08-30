package mindclade.bootstrap.state_protection

import rego.v1

required_boolean_controls := {
	"uniformBucketLevelAccess",
	"versioning",
	"deletionProtection",
	"nativeLocking",
}

deny contains violation if {
	input.kind == "StateBackendSet"
	some backend_id, backend in input.spec.backends
	some control in required_boolean_controls
	object.get(backend.controls, control, false) != true
	violation := {
		"code": "STATE_CONTROL_DISABLED",
		"message": sprintf("backend %q must enable %s", [backend_id, control]),
		"resource": sprintf("backends.%s.controls.%s", [backend_id, control]),
	}
}

deny contains violation if {
	input.kind == "StateBackendSet"
	some backend_id, backend in input.spec.backends
	object.get(backend.controls, "publicAccessPrevention", "") != "enforced"
	violation := {
		"code": "STATE_PUBLIC_ACCESS_NOT_PREVENTED",
		"message": sprintf("backend %q must enforce public-access prevention", [backend_id]),
		"resource": sprintf("backends.%s.controls.publicAccessPrevention", [backend_id]),
	}
}

deny contains violation if {
	input.kind == "StateBackendSet"
	some backend_id, backend in input.spec.backends
	object.get(backend.controls, "softDeleteRetentionDays", 0) < 30
	violation := {
		"code": "STATE_RETENTION_TOO_SHORT",
		"message": sprintf("backend %q must retain soft-deleted state for at least 30 days", [backend_id]),
		"resource": sprintf("backends.%s.controls.softDeleteRetentionDays", [backend_id]),
	}
}

deny contains violation if {
	input.kind == "StateBackendSet"
	some backend_id, backend in input.spec.backends
	backend.encryption.protectionLevel != "HSM"
	violation := {
		"code": "STATE_PRIMARY_KEY_NOT_HSM",
		"message": sprintf("backend %q primary state must use an HSM-protected CMEK", [backend_id]),
		"resource": sprintf("backends.%s.encryption", [backend_id]),
	}
}

deny contains violation if {
	input.kind == "StateBackendSet"
	some backend_id, backend in input.spec.backends
	backend.replica.encryption.protectionLevel != "HSM"
	violation := {
		"code": "STATE_REPLICA_KEY_NOT_HSM",
		"message": sprintf("backend %q replica must use an HSM-protected independent CMEK", [backend_id]),
		"resource": sprintf("backends.%s.replica.encryption", [backend_id]),
	}
}

deny contains violation if {
	input.kind == "StateBackendSet"
	some backend_id, backend in input.spec.backends
	backend.projectRef == backend.replica.projectRef
	violation := {
		"code": "STATE_REPLICA_PROJECT_COLLISION",
		"message": sprintf("backend %q replica must use an independent project", [backend_id]),
		"resource": sprintf("backends.%s.replica.projectRef", [backend_id]),
	}
}

deny contains violation if {
	input.kind == "StateBackendSet"
	some backend_id, backend in input.spec.backends
	backend.location == backend.replica.location
	violation := {
		"code": "STATE_REPLICA_REGION_COLLISION",
		"message": sprintf("backend %q replica must use an independent region", [backend_id]),
		"resource": sprintf("backends.%s.replica.location", [backend_id]),
	}
}

deny contains violation if {
	input.kind == "StateBackendSet"
	some backend_id, backend in input.spec.backends
	backend.bucketName.valueFrom.env == backend.replica.bucketName.valueFrom.env
	violation := {
		"code": "STATE_REPLICA_BUCKET_COLLISION",
		"message": sprintf("backend %q primary and replica bucket references must differ", [backend_id]),
		"resource": sprintf("backends.%s.replica.bucketName", [backend_id]),
	}
}
