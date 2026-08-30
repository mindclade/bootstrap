output "pool_name" {
  description = "Canonical workforce pool resource name."
  value       = google_iam_workforce_pool.workforce.name
}

output "provider_name" {
  description = "Canonical workforce provider resource name."
  value       = google_iam_workforce_pool_provider.oidc.name
}

output "login_audience" {
  description = "STS audience for the configured provider."
  value       = "//iam.googleapis.com/${google_iam_workforce_pool_provider.oidc.name}"
}

output "administrator_group_principal" {
  description = "Canonical workforce principalSet for downstream reviewed bindings; this output grants no authority."
  value       = "principalSet://iam.googleapis.com/locations/global/workforcePools/${var.pool_id}/group/${var.administrator_group}"
}
