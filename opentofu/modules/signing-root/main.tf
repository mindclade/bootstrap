terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

locals {
  services = toset([
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "secretmanager.googleapis.com",
    "serviceusage.googleapis.com",
  ])

  signer_bindings = {
    for binding in flatten([
      for key_name, key in var.keys : [
        for principal in key.signer_principals : {
          id                      = "${key_name}:${principal}"
          key_name                = key_name
          principal               = principal
          active_version_key      = "${key_name}:${key.active_version_ref}"
          active_version_ref      = key.active_version_ref
          activation_window_start = key.versions[key.active_version_ref].activation_window_start
          rotation_deadline       = key.versions[key.active_version_ref].rotation_deadline
        } if !contains(var.disabled_signing_keys, key_name)
      ]
    ]) : binding.id => binding
  }

  key_versions = {
    for version in flatten([
      for key_name, key in var.keys : [
        for version_ref, declaration in key.versions : {
          id          = "${key_name}:${version_ref}"
          key_name    = key_name
          version_ref = version_ref
          declaration = declaration
        }
      ]
    ]) : version.id => version
  }
}

resource "google_project" "signing" {
  project_id          = var.project_id
  name                = var.project_name
  org_id              = var.organization_id
  billing_account     = var.billing_account
  auto_create_network = false
  deletion_policy     = "PREVENT"
  labels              = var.labels

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_service" "required" {
  for_each = local.services

  project            = google_project.signing.project_id
  service            = each.value
  disable_on_destroy = false
  deletion_policy    = "PREVENT"
}

resource "google_project_iam_custom_role" "recovery_metadata" {
  project     = google_project.signing.project_id
  role_id     = "bootstrapRecoverySigningMetadata"
  title       = "Bootstrap recovery signing metadata"
  description = "Read only the exact recovery-evidence key and source-selected active version under a conditional binding"
  permissions = [
    "cloudkms.cryptoKeys.get",
    "cloudkms.cryptoKeyVersions.get",
  ]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_key_ring" "signing" {
  project  = google_project.signing.project_id
  name     = var.key_ring_name
  location = var.location

  depends_on = [google_project_service.required["cloudkms.googleapis.com"]]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_secret_manager_secret" "nix_cache_signing" {
  project             = google_project.signing.project_id
  secret_id           = var.nix_cache.secret_id
  deletion_protection = true

  replication {
    user_managed {
      replicas {
        location = var.location
      }
    }
  }

  depends_on = [google_project_service.required["secretmanager.googleapis.com"]]

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        !var.nix_cache.activation_enabled ||
        (
          var.nix_cache_signing_private_key != null &&
          try(startswith(var.nix_cache_signing_private_key, "${split(":", var.nix_cache.public_keys[0])[0]}:"), false)
        )
      )
      error_message = "Activated Nix cache signing requires an ephemeral private key whose name matches the first committed public key."
    }
  }
}

resource "google_secret_manager_secret_version" "nix_cache_signing" {
  for_each = var.nix_cache.activation_enabled ? { active = true } : {}

  secret                 = google_secret_manager_secret.nix_cache_signing.id
  secret_data_wo         = var.nix_cache_signing_private_key
  secret_data_wo_version = var.nix_cache.secret_version_write_only
  deletion_policy        = "DISABLE"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_secret_manager_secret_iam_member" "nix_cache_accessor" {
  for_each = var.nix_cache.activation_enabled ? var.nix_cache.accessor_principals : toset([])

  project   = google_project.signing.project_id
  secret_id = google_secret_manager_secret.nix_cache_signing.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = each.value

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "signing" {
  for_each = var.keys

  name                          = each.key
  key_ring                      = google_kms_key_ring.signing.id
  purpose                       = "ASYMMETRIC_SIGN"
  destroy_scheduled_duration    = "2592000s"
  skip_initial_version_creation = true
  deletion_policy               = "PREVENT"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = length(setintersection(var.administrator_principals, each.value.signer_principals)) == 0
      error_message = "Signing-key administrators and signers must be disjoint."
    }

    precondition {
      condition = try(
        timecmp(plantimestamp(), each.value.versions[each.value.active_version_ref].activation_window_start) >= 0,
        false,
      )
      error_message = "The source-declared active signing version is not yet inside its activation window."
    }

    precondition {
      condition = try(
        timecmp(timeadd(plantimestamp(), "6h"), each.value.versions[each.value.active_version_ref].rotation_deadline) <= 0,
        false,
      )
      error_message = "The source-declared active signing version expires before a new six-hour plan can remain valid."
    }
  }
}

resource "google_kms_crypto_key_version" "signing" {
  for_each = local.key_versions

  crypto_key      = google_kms_crypto_key.signing[each.value.key_name].id
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true

    postcondition {
      condition     = self.algorithm == "EC_SIGN_P256_SHA256"
      error_message = "Every declared signing key version must use the approved P-256 signing algorithm."
    }

    postcondition {
      condition     = self.protection_level == "HSM"
      error_message = "Every declared signing key version must remain non-exportable HSM material."
    }

    postcondition {
      condition = (
        each.value.version_ref != var.keys[each.value.key_name].active_version_ref ||
        self.state == "ENABLED"
      ) && contains(["ENABLED", "DISABLED"], self.state)
      error_message = "The active signing version must be enabled; historical declarations may only be enabled or disabled."
    }
  }
}

data "google_kms_crypto_key_version" "active" {
  for_each = var.keys

  crypto_key = google_kms_crypto_key_version.signing["${each.key}:${each.value.active_version_ref}"].crypto_key
  version    = tonumber(basename(google_kms_crypto_key_version.signing["${each.key}:${each.value.active_version_ref}"].name))
}

resource "google_kms_key_ring_iam_member" "administrator" {
  for_each = var.administrator_principals

  key_ring_id = google_kms_key_ring.signing.id
  role        = "roles/cloudkms.admin"
  member      = each.value
}

resource "google_kms_crypto_key_iam_member" "signer" {
  for_each = local.signer_bindings

  crypto_key_id = google_kms_crypto_key.signing[each.value.key_name].id
  role          = "roles/cloudkms.signerVerifier"
  member        = each.value.principal

  condition {
    title = "sign-${each.value.key_name}-${each.value.active_version_ref}-within-window"
    expression = join(" && ", [
      "resource.type == 'cloudkms.googleapis.com/CryptoKeyVersion'",
      "resource.name == '${google_kms_crypto_key_version.signing[each.value.active_version_key].name}'",
      "request.time >= timestamp('${each.value.activation_window_start}')",
      "request.time < timestamp('${each.value.rotation_deadline}')",
    ])
  }
}

resource "google_kms_crypto_key_iam_member" "recovery_metadata" {
  crypto_key_id = google_kms_crypto_key.signing["recovery-evidence"].id
  role          = "projects/${var.project_id}/roles/${google_project_iam_custom_role.recovery_metadata.role_id}"
  member        = var.recovery_verifier_principal

  condition {
    title       = "read-recovery-evidence-active-key-version-only"
    description = "Permit connected verification to inspect only the recovery-evidence key and its source-selected active version."
    expression = join(" || ", [
      "(resource.type == 'cloudkms.googleapis.com/CryptoKey' && resource.name == '${google_kms_crypto_key.signing["recovery-evidence"].id}')",
      "(resource.type == 'cloudkms.googleapis.com/CryptoKeyVersion' && resource.name == '${google_kms_crypto_key_version.signing["recovery-evidence:${var.keys["recovery-evidence"].active_version_ref}"].name}')",
    ])
  }

  lifecycle {
    prevent_destroy = true
  }
}
