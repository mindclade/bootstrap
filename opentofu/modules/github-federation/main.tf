terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

locals {
  repository_owner         = split("/", var.repository_full_name)[0]
  repository_name          = split("/", var.repository_full_name)[1]
  immutable_subject_prefix = "repo:${local.repository_owner}@${var.repository_owner_id}/${local.repository_name}@${var.repository_id}"

  identities = {
    plan = {
      pool_id            = var.pool_ids.plan
      provider_id        = var.provider_ids.plan
      service_account_id = var.service_account_ids.plan
      service_project_id = var.service_account_project_ids.plan
      service_email      = "${var.service_account_ids.plan}@${var.service_account_project_ids.plan}.iam.gserviceaccount.com"
      audience           = var.audiences.plan
      workflow_ref       = var.workflow_refs.plan
      environment        = "infrastructure-plan"
    }
    apply = {
      pool_id            = var.pool_ids.apply
      provider_id        = var.provider_ids.apply
      service_account_id = var.service_account_ids.apply
      service_project_id = var.service_account_project_ids.apply
      service_email      = "${var.service_account_ids.apply}@${var.service_account_project_ids.apply}.iam.gserviceaccount.com"
      audience           = var.audiences.apply
      workflow_ref       = var.workflow_refs.apply
      environment        = "infrastructure-apply"
    }
    recovery = {
      pool_id            = var.pool_ids.recovery
      provider_id        = var.provider_ids.recovery
      service_account_id = var.service_account_ids.recovery
      service_project_id = var.service_account_project_ids.recovery
      service_email      = "${var.service_account_ids.recovery}@${var.service_account_project_ids.recovery}.iam.gserviceaccount.com"
      audience           = var.audiences.recovery
      workflow_ref       = var.workflow_refs.recovery
      environment        = "recovery-verification"
    }
  }
}

resource "google_iam_workload_identity_pool" "github" {
  for_each = local.identities

  project                   = var.project_id
  workload_identity_pool_id = each.value.pool_id
  display_name              = "bootstrap GitHub ${each.key}"
  description               = "Isolated GitHub OIDC trust for bootstrap ${each.key} operations"
  deletion_policy           = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workload_identity_pool_provider" "github" {
  for_each = local.identities

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github[each.key].workload_identity_pool_id
  workload_identity_pool_provider_id = each.value.provider_id
  display_name                       = "bootstrap GitHub ${each.key}"
  description                        = "Claim-restricted GitHub provider for bootstrap ${each.key} operations"
  deletion_policy                    = "PREVENT"

  attribute_mapping = {
    "google.subject"                = "assertion.sub"
    "attribute.repository_id"       = "assertion.repository_id"
    "attribute.repository_owner_id" = "assertion.repository_owner_id"
    "attribute.ref"                 = "assertion.ref"
    "attribute.workflow_ref"        = "assertion.workflow_ref"
    "attribute.environment"         = "assertion.environment"
  }

  attribute_condition = join(" && ", [
    "assertion.sub == '${local.immutable_subject_prefix}:environment:${each.value.environment}'",
    "assertion.repository_id == '${var.repository_id}'",
    "assertion.repository_owner_id == '${var.repository_owner_id}'",
    "assertion.ref == '${var.branch_ref}'",
    "assertion.workflow_ref == '${each.value.workflow_ref}'",
    "assertion.environment == '${each.value.environment}'",
  ])

  oidc {
    issuer_uri        = var.issuer_uri
    allowed_audiences = [each.value.audience]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "github" {
  for_each = local.identities

  project         = each.value.service_project_id
  account_id      = each.value.service_account_id
  display_name    = "bootstrap GitHub ${each.key}"
  description     = "Keyless ${each.key}-only bootstrap identity"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account_iam_member" "github" {
  for_each = local.identities

  service_account_id = "projects/${each.value.service_project_id}/serviceAccounts/${each.value.service_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[each.key].name}/attribute.repository_id/${var.repository_id}"

  depends_on = [
    google_iam_workload_identity_pool_provider.github,
    google_service_account.github,
  ]
}
