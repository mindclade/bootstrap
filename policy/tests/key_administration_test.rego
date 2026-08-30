package mindclade.bootstrap.key_administration

import rego.v1

valid_key := {
	"purpose": "ASYMMETRIC_SIGN",
	"algorithm": "EC_SIGN_P256_SHA256",
	"protectionLevel": "HSM",
	"rotationDays": 90,
	"activeVersionRef": "v20260829",
	"versions": {"v20260829": {
		"activationWindowStart": "2026-08-29T00:00:00Z",
		"rotationDeadline": "2026-11-27T00:00:00Z",
	}},
	"deletionProtection": true,
	"signers": [{"valueFrom": {"env": "SIGNER"}}],
}

valid_input := {
	"kind": "SigningRootSet",
	"spec": {
		"administrators": [
			{"valueFrom": {"env": "KMS_ADMIN_1"}},
			{"valueFrom": {"env": "KMS_ADMIN_2"}},
		],
		"keys": {"bootstrap-handoff": valid_key},
	},
}

test_separated_key_duties_are_allowed if {
	violations := deny with input as valid_input
	count(violations) == 0
}

test_signer_administrator_overlap_is_denied if {
	bad_key := object.union(valid_key, {"signers": [{"valueFrom": {"env": "KMS_ADMIN_1"}}]})
	candidate := object.union(valid_input, {"spec": object.union(valid_input.spec, {"keys": {"bootstrap-handoff": bad_key}})})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "KEY_DUTY_COLLISION"
	violation.resource == "keys.bootstrap-handoff"
}

test_software_key_is_denied if {
	bad_key := object.union(valid_key, {"protectionLevel": "SOFTWARE"})
	candidate := object.union(valid_input, {"spec": object.union(valid_input.spec, {"keys": {"bootstrap-handoff": bad_key}})})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "KEY_NOT_HSM_PROTECTED"
}

test_unprotected_key_is_denied if {
	bad_key := object.union(valid_key, {"deletionProtection": false})
	candidate := object.union(valid_input, {"spec": object.union(valid_input.spec, {"keys": {"bootstrap-handoff": bad_key}})})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "KEY_DELETION_UNPROTECTED"
}

test_non_90_day_cadence_is_denied if {
	bad_key := object.union(valid_key, {"rotationDays": 91})
	candidate := object.union(valid_input, {"spec": object.union(valid_input.spec, {"keys": {"bootstrap-handoff": bad_key}})})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "KEY_ROTATION_CADENCE_MISMATCH"
}

test_undeclared_active_version_is_denied if {
	bad_key := object.union(valid_key, {"activeVersionRef": "v20261127"})
	candidate := object.union(valid_input, {"spec": object.union(valid_input.spec, {"keys": {"bootstrap-handoff": bad_key}})})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "KEY_ACTIVE_VERSION_UNDECLARED"
}

test_non_90_day_window_is_denied if {
	bad_key := object.union(valid_key, {"versions": {"v20260829": {
		"activationWindowStart": "2026-08-29T00:00:00Z",
		"rotationDeadline": "2026-11-26T00:00:00Z",
	}}})
	candidate := object.union(valid_input, {"spec": object.union(valid_input.spec, {"keys": {"bootstrap-handoff": bad_key}})})
	violations := deny with input as candidate
	some violation in violations
	violation.code == "KEY_VERSION_WINDOW_MISMATCH"
}
