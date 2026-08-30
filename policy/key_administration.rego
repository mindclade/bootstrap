package mindclade.bootstrap.key_administration

import rego.v1

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	some administrator in input.spec.administrators
	some signer in key.signers
	administrator.valueFrom.env == signer.valueFrom.env
	violation := {
		"code": "KEY_DUTY_COLLISION",
		"message": sprintf("key %q has a principal that can both administer and sign", [key_id]),
		"resource": sprintf("keys.%s", [key_id]),
	}
}

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	key.protectionLevel != "HSM"
	violation := {
		"code": "KEY_NOT_HSM_PROTECTED",
		"message": sprintf("key %q must use HSM protection", [key_id]),
		"resource": sprintf("keys.%s.protectionLevel", [key_id]),
	}
}

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	key.purpose != "ASYMMETRIC_SIGN"
	violation := {
		"code": "KEY_EXPORTABLE_PURPOSE",
		"message": sprintf("key %q must be an asymmetric signing key", [key_id]),
		"resource": sprintf("keys.%s.purpose", [key_id]),
	}
}

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	key.algorithm != "EC_SIGN_P256_SHA256"
	violation := {
		"code": "KEY_ALGORITHM_MISMATCH",
		"message": sprintf("key %q must use the approved P-256 signing algorithm", [key_id]),
		"resource": sprintf("keys.%s.algorithm", [key_id]),
	}
}

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	object.get(key, "deletionProtection", false) != true
	violation := {
		"code": "KEY_DELETION_UNPROTECTED",
		"message": sprintf("key %q must enable deletion protection", [key_id]),
		"resource": sprintf("keys.%s.deletionProtection", [key_id]),
	}
}

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	rotation_days := object.get(key, "rotationDays", 0)
	rotation_days != 90
	violation := {
		"code": "KEY_ROTATION_CADENCE_MISMATCH",
		"message": sprintf("key %q must use the reviewed 90-day asymmetric rotation cadence", [key_id]),
		"resource": sprintf("keys.%s.rotationDays", [key_id]),
	}
}

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	versions := object.get(key, "versions", {})
	count(versions) == 0
	violation := {
		"code": "KEY_VERSION_DECLARATION_MISSING",
		"message": sprintf("key %q must declare at least one source-controlled key version", [key_id]),
		"resource": sprintf("keys.%s.versions", [key_id]),
	}
}

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	versions := object.get(key, "versions", {})
	active_ref := object.get(key, "activeVersionRef", "")
	not versions[active_ref]
	violation := {
		"code": "KEY_ACTIVE_VERSION_UNDECLARED",
		"message": sprintf("key %q must select one source-declared active version", [key_id]),
		"resource": sprintf("keys.%s.activeVersionRef", [key_id]),
	}
}

deny contains violation if {
	input.kind == "SigningRootSet"
	some key_id, key in input.spec.keys
	some version_ref, version in key.versions
	window_start := time.parse_rfc3339_ns(version.activationWindowStart)
	rotation_deadline := time.parse_rfc3339_ns(version.rotationDeadline)
	rotation_deadline - window_start != (((90 * 24) * 60) * 60) * 1000000000
	violation := {
		"code": "KEY_VERSION_WINDOW_MISMATCH",
		"message": sprintf("key %q version %q must declare exactly a 90-day activation window", [key_id, version_ref]),
		"resource": sprintf("keys.%s.versions.%s", [key_id, version_ref]),
	}
}
