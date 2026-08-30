package mindclade.bootstrap.state_protection

import rego.v1

valid_backend := {
	"projectRef": "state-root",
	"bucketName": {"valueFrom": {"env": "STATE_BUCKET"}},
	"location": "us-central1",
	"encryption": {"protectionLevel": "HSM"},
	"replica": {
		"projectRef": "recovery-root",
		"bucketName": {"valueFrom": {"env": "REPLICA_BUCKET"}},
		"location": "us-east4",
		"encryption": {"protectionLevel": "HSM"},
	},
	"controls": {
		"uniformBucketLevelAccess": true,
		"publicAccessPrevention": "enforced",
		"versioning": true,
		"softDeleteRetentionDays": 30,
		"deletionProtection": true,
		"nativeLocking": true,
	},
}

valid_input := {
	"kind": "StateBackendSet",
	"spec": {"backends": {"root-trust": valid_backend}},
}

test_protected_state_is_allowed if {
	violations := deny with input as valid_input
	count(violations) == 0
}

test_disabled_versioning_is_denied if {
	bad_backend := object.union(valid_backend, {"controls": object.union(valid_backend.controls, {"versioning": false})})
	candidate := {"kind": "StateBackendSet", "spec": {"backends": {"root-trust": bad_backend}}}
	violations := deny with input as candidate
	some violation in violations
	violation.code == "STATE_CONTROL_DISABLED"
	violation.resource == "backends.root-trust.controls.versioning"
}

test_short_retention_is_denied if {
	bad_backend := object.union(valid_backend, {"controls": object.union(valid_backend.controls, {"softDeleteRetentionDays": 7})})
	candidate := {"kind": "StateBackendSet", "spec": {"backends": {"root-trust": bad_backend}}}
	violations := deny with input as candidate
	some violation in violations
	violation.code == "STATE_RETENTION_TOO_SHORT"
}

test_same_project_replica_is_denied if {
	bad_backend := object.union(valid_backend, {"replica": object.union(valid_backend.replica, {"projectRef": "state-root"})})
	candidate := {"kind": "StateBackendSet", "spec": {"backends": {"root-trust": bad_backend}}}
	violations := deny with input as candidate
	some violation in violations
	violation.code == "STATE_REPLICA_PROJECT_COLLISION"
}
