output "project_id" {
  description = "Dedicated signing project ID."
  value       = google_project.signing.project_id
}

output "key_ring" {
  description = "Canonical signing key-ring resource name."
  value       = google_kms_key_ring.signing.id
}

output "keys" {
  description = "Non-secret signing key, active public-version, and append-only declared-version references."
  value = {
    for name, key in google_kms_crypto_key.signing : name => {
      key                = key.id
      active_version_ref = var.keys[name].active_version_ref
      primary_version    = google_kms_crypto_key_version.signing["${name}:${var.keys[name].active_version_ref}"].name
      declared_versions = {
        for version_ref, declaration in var.keys[name].versions : version_ref => {
          name                    = google_kms_crypto_key_version.signing["${name}:${version_ref}"].name
          activation_window_start = declaration.activation_window_start
          rotation_deadline       = declaration.rotation_deadline
        }
      }
      algorithm     = "EC_SIGN_P256_SHA256"
      protection    = "HSM"
      rotation_days = var.keys[name].rotation_days
    }
  }
}
