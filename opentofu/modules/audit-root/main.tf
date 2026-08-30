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
    "logging.googleapis.com",
    "serviceusage.googleapis.com",
  ])

  administrator_roles = toset(["roles/logging.configWriter"])

  administrator_bindings = {
    for pair in setproduct(local.administrator_roles, var.administrator_principals) :
    "${pair[0]}:${pair[1]}" => {
      role   = pair[0]
      member = pair[1]
    }
  }

  reader_bindings = {
    for binding in setproduct(
      toset(keys(var.buckets)),
      var.reader_principals,
      ) : "${binding[0]}:${binding[1]}" => {
      bucket = binding[0]
      member = binding[1]
    }
  }

  plan_read_permissions = [
    "iam.roles.get",
    "logging.buckets.get",
    "logging.cmekSettings.get",
    "logging.views.getIamPolicy",
  ]

  sink_writer_sinks = {
    for bucket_id in keys(var.buckets) :
    bucket_id => sort([
      for sink_id, sink in var.sinks : sink_id
      if sink.bucket_id == bucket_id
    ])[0]
  }
}

resource "google_project" "audit" {
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

  project            = google_project.audit.project_id
  service            = each.value
  disable_on_destroy = false
  deletion_policy    = "PREVENT"
}

resource "google_kms_key_ring" "audit" {
  for_each = var.buckets

  project  = each.value.project_id
  name     = "audit-${each.key}"
  location = each.value.location

  depends_on = [google_project_service.required]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "audit" {
  for_each = var.buckets

  name                       = each.value.key_name
  key_ring                   = google_kms_key_ring.audit[each.key].id
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

data "google_logging_project_cmek_settings" "audit" {
  for_each = var.buckets

  project = each.value.project_id

  depends_on = [google_project_service.required]
}

resource "google_kms_crypto_key_iam_member" "logging" {
  for_each = var.buckets

  crypto_key_id = google_kms_crypto_key.audit[each.key].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_logging_project_cmek_settings.audit[each.key].service_account_id}"
}

resource "google_logging_project_bucket_config" "audit" {
  for_each = var.buckets

  project         = each.value.project_id
  location        = each.value.location
  bucket_id       = each.value.bucket_id
  description     = "Mindclade organization audit evidence (${each.key})"
  retention_days  = var.retention_days
  locked          = var.lock_after_qualification
  deletion_policy = "PREVENT"

  cmek_settings {
    kms_key_name = google_kms_crypto_key.audit[each.key].id
  }

  depends_on = [google_kms_crypto_key_iam_member.logging]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_logging_organization_sink" "audit" {
  for_each = var.sinks

  name               = each.value.name
  org_id             = var.organization_id
  destination        = "logging.googleapis.com/${google_logging_project_bucket_config.audit[each.value.bucket_id].id}"
  filter             = each.value.filter != "" ? each.value.filter : null
  include_children   = true
  intercept_children = false
  disabled           = false
  deletion_policy    = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_member" "sink_writer" {
  for_each = local.sink_writer_sinks

  project = var.buckets[each.key].project_id
  role    = "roles/logging.bucketWriter"
  member  = google_logging_organization_sink.audit[each.value].writer_identity

  condition {
    title       = "bootstrap-audit-${each.key}-bucket-only"
    description = "Permit the shared organization sink writer to write only this exact audit bucket."
    expression  = "resource.type == 'logging.googleapis.com/LogBucket' && resource.name == 'projects/${var.buckets[each.key].project_id}/locations/${var.buckets[each.key].location}/buckets/${var.buckets[each.key].bucket_id}'"
  }
}

resource "google_project_iam_member" "reader" {
  for_each = local.reader_bindings

  project = var.buckets[each.value.bucket].project_id
  role    = "roles/logging.viewAccessor"
  member  = each.value.member

  condition {
    title       = "bootstrap-audit-${each.value.bucket}-all-logs-view"
    description = "Permit this reader to query only the exact protected audit bucket view."
    expression  = "resource.name == 'projects/${var.buckets[each.value.bucket].project_id}/locations/${var.buckets[each.value.bucket].location}/buckets/${var.buckets[each.value.bucket].bucket_id}/views/_AllLogs'"
  }
}

resource "google_project_iam_member" "administrator" {
  for_each = local.administrator_bindings

  project = google_project.audit.project_id
  role    = each.value.role
  member  = each.value.member
}

resource "google_project_iam_custom_role" "plan_read" {
  for_each = var.buckets

  project         = each.value.project_id
  role_id         = "bootstrapAuditPlanRead"
  title           = "Bootstrap audit plan read"
  description     = "Refresh only audit bucket, CMEK, view-policy, and custom-role metadata during reviewed plans"
  permissions     = local.plan_read_permissions
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_member" "plan_read" {
  for_each = var.buckets

  project = each.value.project_id
  role    = "projects/${each.value.project_id}/roles/${google_project_iam_custom_role.plan_read[each.key].role_id}"
  member  = var.plan_principal
}
