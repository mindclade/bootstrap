output "state_backends" {
  description = "Non-secret backend coordinates created during bootstrap."
  value = {
    root_trust = merge(module.root_state.backend, {
      project_id         = module.root_state.project_ids.primary
      replica_bucket     = module.root_state.replica_bucket
      replica_project_id = module.root_state.project_ids.replica
    })
    recovery_plane = merge(module.recovery_state.backend, {
      project_id         = module.recovery_state.project_ids.primary
      replica_bucket     = module.recovery_state.replica_bucket
      replica_project_id = module.recovery_state.project_ids.replica
    })
  }
}

output "federation" {
  description = "Workforce and workload federation provider references."
  value = {
    workforce = {
      pool                = module.workforce_identity.pool_name
      provider            = module.workforce_identity.provider_name
      audience            = module.workforce_identity.login_audience
      administrator_group = module.workforce_identity.administrator_group_principal
    }
    github = {
      providers        = module.github_federation.providers
      audiences        = module.github_federation.audiences
      service_accounts = module.github_federation.service_accounts
    }
    github_ci_evidence  = module.github_federation.ci_evidence
    github_config       = module.github_federation.github_config
    infrastructure_live = module.github_federation.infrastructure_live
    activation          = var.bootstrap.github_activation
    buildkite = {
      provider        = module.buildkite_federation.provider_name
      audience        = module.buildkite_federation.audience
      service_account = module.buildkite_federation.service_account
    }
    gitops = {
      provider        = module.gitops_federation.provider_name
      audience        = module.gitops_federation.audience
      service_account = module.gitops_federation.service_account
    }
  }
}

output "signing_roots" {
  description = "Public signing key, explicitly active version, and append-only declared-version references."
  value       = module.signing_root.keys
}

output "signing_version_declarations" {
  description = "State-backed append-only ledger of immutable signing-version activation windows."
  value = {
    for key_name, key in var.bootstrap.signing.keys : key_name => key.versions
  }
}

output "audit_destinations" {
  description = "Protected audit bucket and sink references."
  value = {
    buckets = module.audit_root.buckets
    sinks   = module.audit_root.sinks
  }
}

output "break_glass_entitlements" {
  description = "PAM entitlement resource names."
  value       = module.break_glass.entitlements
}
