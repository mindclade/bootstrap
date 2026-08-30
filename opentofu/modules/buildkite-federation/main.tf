terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_iam_workload_identity_pool" "buildkite" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "bootstrap Buildkite"
  description               = "Isolated Buildkite OIDC trust for signed bootstrap handoff operations"
  disabled                  = false
  deletion_policy           = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workload_identity_pool_provider" "buildkite" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.buildkite.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = "bootstrap Buildkite"
  description                        = "Claim-restricted Buildkite provider"
  disabled                           = false
  deletion_policy                    = "PREVENT"

  attribute_mapping = {
    "google.subject"              = "assertion.sub"
    "attribute.organization_slug" = "assertion.organization_slug"
    "attribute.pipeline_slug"     = "assertion.pipeline_slug"
    "attribute.pipeline_id"       = "assertion.pipeline_id"
    "attribute.build_branch"      = "assertion.build_branch"
    "attribute.step_key"          = "assertion.step_key"
  }

  attribute_condition = join(" && ", [
    "assertion.sub == '${var.pipeline_id}'",
    "assertion.organization_slug == '${var.organization_slug}'",
    "assertion.pipeline_slug == '${var.pipeline_slug}'",
    "assertion.pipeline_id == '${var.pipeline_id}'",
    "assertion.build_branch == '${var.build_branch}'",
    "assertion.step_key == '${var.step_key}'",
  ])

  oidc {
    issuer_uri        = var.issuer_uri
    allowed_audiences = [var.audience]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "buildkite" {
  project         = var.service_account_project_id
  account_id      = var.service_account_id
  display_name    = "bootstrap Buildkite signer"
  description     = "Keyless Buildkite identity; no service-account keys are created"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account_iam_member" "buildkite" {
  service_account_id = "projects/${var.service_account_project_id}/serviceAccounts/${var.service_account_id}@${var.service_account_project_id}.iam.gserviceaccount.com"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.buildkite.name}/attribute.pipeline_id/${var.pipeline_id}"

  depends_on = [
    google_iam_workload_identity_pool_provider.buildkite,
    google_service_account.buildkite,
  ]
}
