terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_iam_workload_identity_pool" "gitops" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "bootstrap GitOps"
  description               = "Isolated GitOps OIDC trust for bootstrap handoff"
  disabled                  = false
  deletion_policy           = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workload_identity_pool_provider" "gitops" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.gitops.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = "bootstrap GitOps"
  description                        = "Claim-restricted GitOps controller provider"
  disabled                           = false
  deletion_policy                    = "PREVENT"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  attribute_condition = join(" && ", [
    "assertion.sub == '${var.subject}'",
    "assertion.repository == '${var.repository}'",
    "assertion.ref == '${var.ref}'",
  ])

  oidc {
    issuer_uri        = var.issuer_uri
    allowed_audiences = [var.audience]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "gitops" {
  project         = var.service_account_project_id
  account_id      = var.service_account_id
  display_name    = "bootstrap GitOps"
  description     = "Keyless GitOps handoff identity; no service-account keys are created"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account_iam_member" "gitops" {
  service_account_id = "projects/${var.service_account_project_id}/serviceAccounts/${var.service_account_id}@${var.service_account_project_id}.iam.gserviceaccount.com"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.gitops.name}/attribute.repository/${var.repository}"

  depends_on = [
    google_iam_workload_identity_pool_provider.gitops,
    google_service_account.gitops,
  ]
}
