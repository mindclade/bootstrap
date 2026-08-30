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

output "ci_evidence" {
  description = "Source-gated CI-evidence federation handoff for downstream bucket IAM."
  value = {
    activation_enabled = var.ci_evidence.activation_enabled
    pool               = var.ci_evidence.activation_enabled ? google_iam_workload_identity_pool.ci_evidence["archive"].name : null
    providers = {
      for key, provider in google_iam_workload_identity_pool_provider.ci_evidence : key => provider.name
    }
    audiences = {
      for key, provider in google_iam_workload_identity_pool_provider.ci_evidence :
      key => "https://iam.googleapis.com/${provider.name}"
    }
    service_accounts = {
      for key, identity in local.ci_evidence_identities : key => identity.service_email
    }
    principal_members = {
      for key, identity in local.ci_evidence_identities : key => "serviceAccount:${identity.service_email}"
    }
    repository_owner_id = var.ci_evidence.repository_owner_id
    repository_ids      = var.ci_evidence.repository_ids
  }
}

output "github_config" {
  description = "Activation-gated github-config identity and signing handoff."
  value = {
    activation_enabled = var.github_config.activation_enabled
    pool               = var.github_config.activation_enabled ? google_iam_workload_identity_pool.github_config["pool"].name : null
    providers = {
      for key, provider in google_iam_workload_identity_pool_provider.github_config : key => provider.name
    }
    expected_provider_ids = {
      for key, identity in local.github_config_identities : key => identity.provider_id
    }
    service_accounts = {
      for key, identity in local.github_config_identities : key => identity.service_email
    }
    repository_owner_id = var.github_config.repository_owner_id
    repository_id       = var.github_config.repository_id
  }
}

output "infrastructure_live" {
  description = "Exact eight-identity infrastructure-live federation handoff."
  value = {
    pool = google_iam_workload_identity_pool.infrastructure_live["pool"].name
    providers = {
      for key, provider in google_iam_workload_identity_pool_provider.infrastructure_live : key => provider.name
    }
    audiences = {
      for key, identity in local.infrastructure_identities : key => identity.audience
    }
    service_accounts = {
      for key, identity in local.infrastructure_identities : key => identity.service_email
    }
    principal_members = {
      for key, identity in local.infrastructure_identities : key => "serviceAccount:${identity.service_email}"
    }
    drift = {
      activation_enabled   = var.infrastructure_live.drift.activation_enabled
      provider             = var.infrastructure_live.drift.activation_enabled ? google_iam_workload_identity_pool_provider.infrastructure_drift["drift"].name : null
      expected_provider_id = var.infrastructure_live.drift.provider_id
      service_account      = local.infrastructure_drift.service_email
    }
    repository_owner_id = var.infrastructure_live.repository_owner_id
    repository_id       = var.infrastructure_live.repository_id
  }
}
