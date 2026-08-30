terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

locals {
  buckets = {
    exports = {
      name              = var.export_bucket_name
      key_name          = var.export_key_name
      retention_seconds = 2592000
    }
    evidence = {
      name              = var.evidence_bucket_name
      key_name          = "recovery-evidence"
      retention_seconds = 220752000
    }
  }

  bucket_access = {
    for binding in flatten([
      for bucket_key in keys(local.buckets) : [
        {
          id     = "${bucket_key}-exporter"
          bucket = bucket_key
          role   = "roles/storage.objectCreator"
          member = var.exporter_principal
        },
        {
          id     = "${bucket_key}-recovery"
          bucket = bucket_key
          role   = "roles/storage.objectViewer"
          member = var.recovery_principal
        },
        {
          id     = "${bucket_key}-recovery-metadata"
          bucket = bucket_key
          role   = "roles/storage.legacyBucketReader"
          member = var.recovery_principal
        },
      ]
    ]) : binding.id => binding
  }

  state_exports = {
    for name, backend in var.source_state_backends : name => merge(backend, {
      object_name           = "${backend.prefix}/default.tfstate"
      service_account_id    = "bootstrap-recovery-export"
      service_account_email = "bootstrap-recovery-export@${backend.project_id}.iam.gserviceaccount.com"
    })
  }

  public_trust_metadata_content = jsonencode(var.public_trust_metadata)
  restore_inventory_content = jsonencode({
    schema_version = 1
    source_state_objects = {
      for name, backend in local.state_exports : name => {
        bucket = backend.bucket
        object = backend.object_name
      }
    }
    export_state_objects = {
      for name, backend in local.state_exports : name => {
        bucket = var.export_bucket_name
        object = backend.object_name
      }
    }
    runtime_selection_required         = ["generation", "sha256"]
    minimum_retained_state_generations = var.minimum_retained_state_generations
    restore_manifest_digest            = var.restore_manifest_digest
    excludes                           = ["kms-private-key-material", "service-account-keys", "credentials"]
  })

  plan_read_permissions = [
    "storage.buckets.get",
    "storage.buckets.getIamPolicy",
  ]

  plan_objects = {
    exports = {
      bucket      = "exports"
      object_name = "restore/inventory.json"
    }
    evidence = {
      bucket      = "evidence"
      object_name = "trust/public-trust-metadata.json"
    }
  }

  plan_object_read_permissions = [
    "storage.objects.get",
  ]
}

resource "google_project_iam_custom_role" "plan_read" {
  project         = var.project_id
  role_id         = "bootstrapRecoveryPlanRead"
  title           = "Bootstrap recovery plan read"
  description     = "Refresh only recovery bucket metadata, IAM, and declared objects during reviewed plans"
  permissions     = local.plan_read_permissions
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_custom_role" "plan_object_read" {
  project         = var.project_id
  role_id         = "bootstrapRecoveryPlanObjectRead"
  title           = "Bootstrap recovery plan object read"
  description     = "Refresh only the two fixed non-state objects declared by the recovery root"
  permissions     = local.plan_object_read_permissions
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_key_ring" "recovery" {
  project  = var.project_id
  name     = var.key_ring_name
  location = var.location

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "recovery" {
  for_each = local.buckets

  name                       = each.value.key_name
  key_ring                   = google_kms_key_ring.recovery.id
  purpose                    = "ENCRYPT_DECRYPT"
  rotation_period            = "7776000s"
  destroy_scheduled_duration = "2592000s"
  deletion_policy            = "PREVENT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

data "google_storage_project_service_account" "recovery" {
  project = var.project_id
}

data "google_storage_project_service_account" "state_export_source" {
  for_each = local.state_exports

  project = each.value.project_id
}

data "google_storage_transfer_project_service_account" "state_export" {
  for_each = local.state_exports

  project = each.value.project_id
}

resource "google_service_account" "state_export" {
  for_each = local.state_exports

  project         = each.value.project_id
  account_id      = each.value.service_account_id
  display_name    = "Bootstrap recovery export (${each.key})"
  description     = "Runs only the ${each.key}/default.tfstate continuous recovery export."
  disabled        = false
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_custom_role" "state_export_source_metadata" {
  for_each = local.state_exports

  project     = each.value.project_id
  role_id     = "bootstrapRecoveryExportSourceMetadata"
  title       = "Bootstrap recovery export source metadata"
  description = "Inspect the source bucket and configure only replication notifications"
  permissions = [
    "storage.buckets.get",
    "storage.buckets.update",
  ]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_custom_role" "state_export_source_object" {
  for_each = local.state_exports

  project         = each.value.project_id
  role_id         = "bootstrapRecoveryExportSourceObject"
  title           = "Bootstrap recovery export source object"
  description     = "Read only one exact default-workspace state object under a conditional bucket binding"
  permissions     = ["storage.objects.get"]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_custom_role" "state_export_transfer_events" {
  for_each = local.state_exports

  project     = each.value.project_id
  role_id     = "bootstrapRecoveryExportTransferEvents"
  title       = "Bootstrap recovery export transfer events"
  description = "Create and consume only the Pub/Sub resources required for continuous recovery export"
  permissions = [
    "pubsub.subscriptions.consume",
    "pubsub.subscriptions.create",
    "pubsub.topics.create",
  ]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_custom_role" "state_export_storage_events" {
  for_each = local.state_exports

  project     = each.value.project_id
  role_id     = "bootstrapRecoveryExportStorageEvents"
  title       = "Bootstrap recovery export storage events"
  description = "Publish and consume only the Cloud Storage notifications required for continuous recovery export"
  permissions = [
    "pubsub.subscriptions.consume",
    "pubsub.subscriptions.create",
    "pubsub.topics.publish",
  ]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_custom_role" "state_export_destination_metadata" {
  project         = var.project_id
  role_id         = "bootstrapRecoveryExportDestinationMetadata"
  title           = "Bootstrap recovery export destination metadata"
  description     = "Inspect only the protected recovery export bucket"
  permissions     = ["storage.buckets.get"]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_custom_role" "state_export_destination_object" {
  project     = var.project_id
  role_id     = "bootstrapRecoveryExportDestinationObject"
  title       = "Bootstrap recovery export destination object"
  description = "Create and compare only exact recovery state objects under conditional bucket bindings"
  permissions = [
    "storage.objects.create",
    "storage.objects.get",
  ]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "storage" {
  for_each = local.buckets

  crypto_key_id = google_kms_crypto_key.recovery[each.key].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.recovery.email_address}"
}

resource "google_storage_bucket" "recovery" {
  for_each = local.buckets

  project                     = var.project_id
  name                        = each.value.name
  location                    = var.location
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  deletion_policy             = "PREVENT"
  labels                      = var.labels

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.recovery[each.key].id
  }

  retention_policy {
    retention_period = tostring(each.value.retention_seconds)
    is_locked        = true
  }

  soft_delete_policy {
    retention_duration_seconds = 2592000
  }

  depends_on = [google_kms_crypto_key_iam_member.storage]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "access" {
  for_each = local.bucket_access

  bucket = google_storage_bucket.recovery[each.value.bucket].name
  role   = each.value.role
  member = each.value.member
}

resource "google_storage_bucket_iam_member" "plan_read" {
  for_each = local.buckets

  bucket = google_storage_bucket.recovery[each.key].name
  role   = "projects/${var.project_id}/roles/bootstrapRecoveryPlanRead"
  member = var.plan_principal

  depends_on = [google_project_iam_custom_role.plan_read]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "plan_object_read" {
  for_each = local.plan_objects

  bucket = google_storage_bucket.recovery[each.value.bucket].name
  role   = "projects/${var.project_id}/roles/bootstrapRecoveryPlanObjectRead"
  member = var.plan_principal

  condition {
    title       = "read-${each.key}-declared-object-only"
    description = "Refresh only ${each.value.object_name}; recovery state exports remain inaccessible."
    expression  = "resource.type == 'storage.googleapis.com/Object' && resource.name == 'projects/_/buckets/${local.buckets[each.value.bucket].name}/objects/${each.value.object_name}'"
  }

  depends_on = [google_project_iam_custom_role.plan_object_read]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account_iam_member" "state_export_apply" {
  for_each = local.state_exports

  service_account_id = "projects/${each.value.project_id}/serviceAccounts/${each.value.service_account_email}"
  role               = "roles/iam.serviceAccountUser"
  member             = var.exporter_principal

  depends_on = [google_service_account.state_export]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account_iam_member" "state_export_transfer" {
  for_each = local.state_exports

  service_account_id = "projects/${each.value.project_id}/serviceAccounts/${each.value.service_account_email}"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = data.google_storage_transfer_project_service_account.state_export[each.key].member

  depends_on = [google_service_account.state_export]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_member" "state_export_transfer_events" {
  for_each = local.state_exports

  project = each.value.project_id
  role    = "projects/${each.value.project_id}/roles/bootstrapRecoveryExportTransferEvents"
  member  = "serviceAccount:${each.value.service_account_email}"

  depends_on = [google_project_iam_custom_role.state_export_transfer_events]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_member" "state_export_storage_events" {
  for_each = local.state_exports

  project = each.value.project_id
  role    = "projects/${each.value.project_id}/roles/bootstrapRecoveryExportStorageEvents"
  member  = "serviceAccount:${data.google_storage_project_service_account.state_export_source[each.key].email_address}"

  depends_on = [google_project_iam_custom_role.state_export_storage_events]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "state_export_source_metadata" {
  for_each = local.state_exports

  bucket = each.value.bucket
  role   = "projects/${each.value.project_id}/roles/bootstrapRecoveryExportSourceMetadata"
  member = "serviceAccount:${each.value.service_account_email}"

  depends_on = [google_project_iam_custom_role.state_export_source_metadata]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "state_export_source_object" {
  for_each = local.state_exports

  bucket = each.value.bucket
  role   = "projects/${each.value.project_id}/roles/bootstrapRecoveryExportSourceObject"
  member = "serviceAccount:${each.value.service_account_email}"

  condition {
    title       = "read-${each.key}-default-state-only"
    description = "Permit only ${each.value.object_name}; lock and workspace objects remain inaccessible."
    expression  = "resource.type == 'storage.googleapis.com/Object' && resource.name == 'projects/_/buckets/${each.value.bucket}/objects/${each.value.object_name}'"
  }

  depends_on = [google_project_iam_custom_role.state_export_source_object]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "state_export_destination_metadata" {
  for_each = local.state_exports

  bucket = google_storage_bucket.recovery["exports"].name
  role   = "projects/${var.project_id}/roles/bootstrapRecoveryExportDestinationMetadata"
  member = "serviceAccount:${each.value.service_account_email}"

  depends_on = [google_project_iam_custom_role.state_export_destination_metadata]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "state_export_destination_object" {
  for_each = local.state_exports

  bucket = google_storage_bucket.recovery["exports"].name
  role   = "projects/${var.project_id}/roles/bootstrapRecoveryExportDestinationObject"
  member = "serviceAccount:${each.value.service_account_email}"

  condition {
    title       = "write-${each.key}-default-state-only"
    description = "Permit only versioned writes to ${each.value.object_name}; deletion is impossible."
    expression  = "resource.type == 'storage.googleapis.com/Object' && resource.name == 'projects/_/buckets/${var.export_bucket_name}/objects/${each.value.object_name}'"
  }

  depends_on = [google_project_iam_custom_role.state_export_destination_object]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_transfer_job" "state_export" {
  for_each = local.state_exports

  project         = each.value.project_id
  description     = "Continuously export ${each.value.object_name} to the protected recovery bucket"
  service_account = each.value.service_account_email
  status          = "ENABLED"
  deletion_policy = "PREVENT"

  replication_spec {
    gcs_data_source {
      bucket_name = each.value.bucket
    }

    gcs_data_sink {
      bucket_name = google_storage_bucket.recovery["exports"].name
    }

    object_conditions {
      # The exact-object IAM condition is the enforcement boundary: this
      # prefix selects default.tfstate while excluding every .tflock and
      # non-default workspace state object.
      include_prefixes = [each.value.object_name]
    }

    transfer_options {
      overwrite_when = "DIFFERENT"

      metadata_options {
        acl           = "ACL_DESTINATION_BUCKET_DEFAULT"
        kms_key       = "KMS_KEY_DESTINATION_BUCKET_DEFAULT"
        storage_class = "STORAGE_CLASS_DESTINATION_BUCKET_DEFAULT"
      }
    }
  }

  depends_on = [
    google_project_iam_member.state_export_storage_events,
    google_project_iam_member.state_export_transfer_events,
    google_service_account_iam_member.state_export_apply,
    google_service_account_iam_member.state_export_transfer,
    google_storage_bucket_iam_member.state_export_destination_metadata,
    google_storage_bucket_iam_member.state_export_destination_object,
    google_storage_bucket_iam_member.state_export_source_metadata,
    google_storage_bucket_iam_member.state_export_source_object,
  ]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_object" "public_trust_metadata" {
  name            = "trust/public-trust-metadata.json"
  bucket          = google_storage_bucket.recovery["evidence"].name
  content         = local.public_trust_metadata_content
  content_type    = "application/json"
  deletion_policy = "ABANDON"
}

resource "google_storage_bucket_object" "restore_inventory" {
  name            = "restore/inventory.json"
  bucket          = google_storage_bucket.recovery["exports"].name
  content         = local.restore_inventory_content
  content_type    = "application/json"
  deletion_policy = "ABANDON"
}
