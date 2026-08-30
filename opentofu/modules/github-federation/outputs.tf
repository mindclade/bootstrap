output "providers" {
  description = "Canonical provider names keyed by plan, apply, and recovery."
  value       = { for key, provider in google_iam_workload_identity_pool_provider.github : key => provider.name }
}

output "audiences" {
  description = "Explicit OIDC audiences keyed by execution identity."
  value       = { for key, identity in local.identities : key => identity.audience }
}

output "service_accounts" {
  description = "Service-account email addresses keyed by execution identity."
  value       = { for key, identity in local.identities : key => identity.service_email }
}

output "principal_members" {
  description = "Canonical IAM member strings keyed by execution identity."
  value       = { for key, identity in local.identities : key => "serviceAccount:${identity.service_email}" }
}
