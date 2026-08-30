output "provider_name" {
  description = "Canonical GitOps workload identity provider name."
  value       = google_iam_workload_identity_pool_provider.gitops.name
}

output "audience" {
  description = "Explicit GitOps OIDC audience."
  value       = var.audience
}

output "service_account" {
  description = "GitOps service-account email address."
  value       = "${var.service_account_id}@${var.service_account_project_id}.iam.gserviceaccount.com"
}

output "principal_member" {
  description = "Canonical GitOps service-account IAM member string."
  value       = "serviceAccount:${var.service_account_id}@${var.service_account_project_id}.iam.gserviceaccount.com"
}
