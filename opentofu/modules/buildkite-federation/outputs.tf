output "provider_name" {
  description = "Canonical Buildkite workload identity provider name."
  value       = google_iam_workload_identity_pool_provider.buildkite.name
}

output "audience" {
  description = "Explicit Buildkite OIDC audience."
  value       = var.audience
}

output "service_account" {
  description = "Buildkite service-account email address."
  value       = "${var.service_account_id}@${var.service_account_project_id}.iam.gserviceaccount.com"
}

output "principal_member" {
  description = "Canonical Buildkite service-account IAM member string."
  value       = "serviceAccount:${var.service_account_id}@${var.service_account_project_id}.iam.gserviceaccount.com"
}
