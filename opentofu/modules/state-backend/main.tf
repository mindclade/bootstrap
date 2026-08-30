terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

locals {
  buckets = {
    primary = {
      name     = var.bucket_name
      location = var.location
      project  = var.project_id
      key      = google_kms_crypto_key.state.id
    }
    replica = {
      name     = var.replica_bucket_name
      location = var.replica_location
      project  = var.replica_project_id
      key      = google_kms_crypto_key.replica.id
    }
  }

  bucket_access = {
    for binding in flatten([
      for bucket_key in keys(local.buckets) : concat(
        [
          {
            key    = "${bucket_key}-plan-state"
            bucket = bucket_key
            role   = "roles/storage.objectViewer"
            member = var.plan_principal
            condition = {
              title      = "bootstrap-plan-${bucket_key}-state-read"
              expression = "resource.name == 'projects/_/buckets/${local.buckets[bucket_key].name}/objects/${var.backend_prefix}/default.tfstate'"
            }
          },
          {
            key       = "${bucket_key}-plan-metadata"
            bucket    = bucket_key
            role      = "roles/storage.legacyBucketReader"
            member    = var.plan_principal
            condition = null
          },
        ],
        bucket_key == "primary" ? [
          {
            key    = "${bucket_key}-plan-lock"
            bucket = bucket_key
            role   = "projects/${var.project_id}/roles/bootstrapStatePlanLock"
            member = var.plan_principal
            condition = {
              title      = "bootstrap-plan-primary-lock"
              expression = "resource.name == 'projects/_/buckets/${local.buckets[bucket_key].name}/objects/${var.backend_prefix}/default.tflock'"
            }
          },
        ] : [],
        [
          {
            key       = "${bucket_key}-apply"
            bucket    = bucket_key
            role      = "roles/storage.objectAdmin"
            member    = var.apply_principal
            condition = null
          },
          {
            key    = "${bucket_key}-recovery"
            bucket = bucket_key
            role   = "roles/storage.objectViewer"
            member = var.recovery_principal
            condition = {
              title      = "bootstrap-recovery-${bucket_key}-state-read"
              expression = "resource.name == 'projects/_/buckets/${local.buckets[bucket_key].name}/objects/${var.backend_prefix}/default.tfstate'"
            }
          },
          {
            key       = "${bucket_key}-recovery-metadata"
            bucket    = bucket_key
            role      = "roles/storage.legacyBucketReader"
            member    = var.recovery_principal
            condition = null
          },
        ],
      )
    ]) : binding.key => binding
  }

  plan_lock_permissions = [
    "storage.objects.create",
    "storage.objects.delete",
    "storage.objects.get",
    "storage.objects.update",
  ]

  replication_roles = {
    source_bucket = {
      project     = var.project_id
      role_id     = "bootstrapStateReplicationSource"
      title       = "Bootstrap state replication source"
      description = "Read only the source state bucket and configure replication notifications"
      permissions = [
        "storage.buckets.get",
        "storage.buckets.update",
        "storage.objects.get",
      ]
    }
    destination_bucket = {
      project     = var.replica_project_id
      role_id     = "bootstrapStateReplicationDestination"
      title       = "Bootstrap state replication destination"
      description = "Create and compare replicated state objects without delete permission"
      permissions = [
        "storage.buckets.get",
        "storage.objects.create",
        "storage.objects.get",
      ]
    }
    transfer_events = {
      project     = var.project_id
      role_id     = "bootstrapStateReplicationTransferEvents"
      title       = "Bootstrap state replication transfer events"
      description = "Create and consume only the Pub/Sub resources required for state replication"
      permissions = [
        "pubsub.subscriptions.consume",
        "pubsub.subscriptions.create",
        "pubsub.topics.create",
      ]
    }
    storage_events = {
      project     = var.project_id
      role_id     = "bootstrapStateReplicationStorageEvents"
      title       = "Bootstrap state replication storage events"
      description = "Publish and consume only the Cloud Storage notifications required for state replication"
      permissions = [
        "pubsub.subscriptions.consume",
        "pubsub.subscriptions.create",
        "pubsub.topics.publish",
      ]
    }
  }

  replication_bucket_access = {
    source = {
      bucket = "primary"
      role   = "projects/${var.project_id}/roles/${local.replication_roles.source_bucket.role_id}"
      member = data.google_storage_transfer_project_service_account.replication.member
      condition = {
        title      = "bootstrap-replication-source-state-only"
        expression = "(resource.type == 'storage.googleapis.com/Bucket' && resource.name == 'projects/_/buckets/${local.buckets.primary.name}') || (resource.type == 'storage.googleapis.com/Object' && resource.name == 'projects/_/buckets/${local.buckets.primary.name}/objects/${var.backend_prefix}/default.tfstate')"
      }
    }
    destination = {
      bucket = "replica"
      role   = "projects/${var.replica_project_id}/roles/${local.replication_roles.destination_bucket.role_id}"
      member = data.google_storage_transfer_project_service_account.replication.member
      condition = {
        title      = "bootstrap-replication-destination-state-only"
        expression = "(resource.type == 'storage.googleapis.com/Bucket' && resource.name == 'projects/_/buckets/${local.buckets.replica.name}') || (resource.type == 'storage.googleapis.com/Object' && resource.name == 'projects/_/buckets/${local.buckets.replica.name}/objects/${var.backend_prefix}/default.tfstate')"
      }
    }
  }

  replication_event_access = {
    transfer = {
      role   = "projects/${var.project_id}/roles/${local.replication_roles.transfer_events.role_id}"
      member = data.google_storage_transfer_project_service_account.replication.member
    }
    storage = {
      role   = "projects/${var.project_id}/roles/${local.replication_roles.storage_events.role_id}"
      member = "serviceAccount:${data.google_storage_project_service_account.primary.email_address}"
    }
  }
}

resource "google_kms_key_ring" "state" {
  project  = var.project_id
  name     = "state-backend"
  location = var.location

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_key_ring" "replica" {
  project  = var.replica_project_id
  name     = "state-replica"
  location = var.replica_location

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "state" {
  name                       = var.key_name
  key_ring                   = google_kms_key_ring.state.id
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

resource "google_kms_crypto_key" "replica" {
  name                       = var.replica_key_name
  key_ring                   = google_kms_key_ring.replica.id
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

data "google_storage_project_service_account" "primary" {
  project = var.project_id
}

data "google_storage_project_service_account" "replica" {
  project = var.replica_project_id
}

data "google_storage_transfer_project_service_account" "replication" {
  project = var.project_id
}

resource "google_project_iam_custom_role" "replication" {
  for_each = local.replication_roles

  project         = each.value.project
  role_id         = each.value.role_id
  title           = each.value.title
  description     = each.value.description
  permissions     = each.value.permissions
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_custom_role" "plan_lock" {
  project         = var.project_id
  role_id         = "bootstrapStatePlanLock"
  title           = "Bootstrap state plan lock"
  description     = "Create, inspect, update, and release only the exact OpenTofu plan lock object"
  permissions     = local.plan_lock_permissions
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "state_service_agent" {
  crypto_key_id = google_kms_crypto_key.state.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.primary.email_address}"
}

resource "google_kms_crypto_key_iam_member" "replica_service_agent" {
  crypto_key_id = google_kms_crypto_key.replica.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.replica.email_address}"
}

resource "google_storage_bucket" "state" {
  for_each = local.buckets

  project                     = each.value.project
  name                        = each.value.name
  location                    = each.value.location
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
    default_kms_key_name = each.value.key
  }

  soft_delete_policy {
    retention_duration_seconds = 2592000
  }

  lifecycle_rule {
    condition {
      days_since_noncurrent_time = 365
      num_newer_versions         = 3
      send_age_if_zero           = false
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [
    google_kms_crypto_key_iam_member.state_service_agent,
    google_kms_crypto_key_iam_member.replica_service_agent,
  ]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "backend_access" {
  for_each = local.bucket_access

  bucket = google_storage_bucket.state[each.value.bucket].name
  role   = each.value.role
  member = each.value.member

  dynamic "condition" {
    for_each = each.value.condition == null ? [] : [each.value.condition]

    content {
      title      = condition.value.title
      expression = condition.value.expression
    }
  }

  depends_on = [google_project_iam_custom_role.plan_lock]
}

resource "google_storage_bucket_iam_member" "replication" {
  for_each = local.replication_bucket_access

  bucket = google_storage_bucket.state[each.value.bucket].name
  role   = each.value.role
  member = each.value.member

  condition {
    title      = each.value.condition.title
    expression = each.value.condition.expression
  }

  depends_on = [google_project_iam_custom_role.replication]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_member" "replication_events" {
  for_each = local.replication_event_access

  project = var.project_id
  role    = each.value.role
  member  = each.value.member

  depends_on = [google_project_iam_custom_role.replication]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_transfer_job" "replication" {
  project         = var.project_id
  description     = "Replicate ${var.backend_prefix}/default.tfstate to the isolated replica bucket"
  status          = "ENABLED"
  deletion_policy = "PREVENT"

  replication_spec {
    gcs_data_source {
      bucket_name = google_storage_bucket.state["primary"].name
    }

    gcs_data_sink {
      bucket_name = google_storage_bucket.state["replica"].name
    }

    object_conditions {
      # Match only the default-workspace state object. GCS backend .tflock
      # objects are deliberately excluded because replication does not copy
      # deletions and a replicated lock could strand the recovery backend.
      include_prefixes = ["${var.backend_prefix}/default.tfstate"]
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
    google_project_iam_member.replication_events,
    google_storage_bucket_iam_member.replication,
  ]

  lifecycle {
    prevent_destroy = true
  }
}
