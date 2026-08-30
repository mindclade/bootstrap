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
      public_key_pem     = google_kms_crypto_key_version.signing["${name}:${var.keys[name].active_version_ref}"].public_key[0].pem
      # Digest is over the exact UTF-8 PEM bytes. Consumers deriving an SPKI
      # DER digest must decode this PEM and verify both representations.
      public_key_pem_sha256 = sha256(google_kms_crypto_key_version.signing["${name}:${var.keys[name].active_version_ref}"].public_key[0].pem)
      declared_versions = {
        for version_ref, declaration in var.keys[name].versions : version_ref => {
          name                    = google_kms_crypto_key_version.signing["${name}:${version_ref}"].name
          activation_window_start = declaration.activation_window_start
          rotation_deadline       = declaration.rotation_deadline
        }
      }
      algorithm        = "EC_SIGN_P256_SHA256"
      protection_level = "HSM"
      rotation_days    = var.keys[name].rotation_days
    }
  }
}
