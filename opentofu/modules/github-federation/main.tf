terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

locals {
  repository_owner     = split("/", var.repository_full_name)[0]
  repository_name      = split("/", var.repository_full_name)[1]
  immutable_repository = "${local.repository_owner}@${var.repository_owner_id}/${local.repository_name}@${var.repository_id}"

  identities = {
    plan = {
      pool_project_id    = var.project_id
      pool_id            = var.pool_ids.plan
      provider_id        = var.provider_ids.plan
      service_account_id = var.service_account_ids.plan
      service_project_id = var.service_account_project_ids.plan
      service_email      = "${var.service_account_ids.plan}@${var.service_account_project_ids.plan}.iam.gserviceaccount.com"
      audience           = var.audiences.plan
      workflow_ref       = var.workflow_refs.plan
      environment        = "trusted-build"
    }
    apply = {
      pool_project_id    = var.project_id
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
      # Recovery federation is deliberately owned by the recovery project.
      # The standing bootstrap apply identity administers the identity project,
      # but has no administration authority over this trust perimeter.
      pool_project_id    = var.service_account_project_ids.recovery
      pool_id            = var.pool_ids.recovery
      provider_id        = var.provider_ids.recovery
      service_account_id = var.service_account_ids.recovery
      service_project_id = var.service_account_project_ids.recovery
      service_email      = "${var.service_account_ids.recovery}@${var.service_account_project_ids.recovery}.iam.gserviceaccount.com"
      audience           = var.audiences.recovery
      workflow_ref       = var.workflow_refs.recovery
      environment        = "infrastructure-apply"
    }
  }

  ci_evidence_identities = {
    writer = {
      provider_id        = var.ci_evidence.writer.provider_id
      service_account_id = var.ci_evidence.writer.service_account_id
      service_email      = "${var.ci_evidence.writer.service_account_id}@${var.project_id}.iam.gserviceaccount.com"
    }
    verifier = {
      provider_id        = var.ci_evidence.verifier.provider_id
      service_account_id = var.ci_evidence.verifier.service_account_id
      service_email      = "${var.ci_evidence.verifier.service_account_id}@${var.project_id}.iam.gserviceaccount.com"
    }
  }

  github_config_federation_state = contains(["FOUNDER_BOOTSTRAPPED", "CONNECTED_QUALIFIED"], var.activation.state)
  connected_federation_state     = var.activation.state == "CONNECTED_QUALIFIED"
  activation_flags_valid = (
    var.github_config.activation_enabled == local.github_config_federation_state &&
    var.infrastructure_live.drift.activation_enabled == local.connected_federation_state &&
    var.ci_evidence.activation_enabled == local.connected_federation_state
  )
  active_ci_evidence_identities = local.connected_federation_state && var.ci_evidence.activation_enabled ? local.ci_evidence_identities : {}
  ci_evidence_repository_ids    = join(", ", [for repository_id in sort(values(var.ci_evidence.repository_ids)) : "'${repository_id}'"])
  ci_evidence_writer_sha        = split("@", var.ci_evidence.writer.job_workflow_ref)[1]

  infrastructure_identities = {
    for key, identity in var.infrastructure_live.identities : key => merge(identity, {
      service_email = "${identity.service_account_id}@${var.project_id}.iam.gserviceaccount.com"
    })
  }

  github_config_identities = {
    for key, identity in var.github_config.identities : key => merge(identity, {
      service_email = "${identity.service_account_id}@${var.project_id}.iam.gserviceaccount.com"
    })
  }
  github_config_subject_conditions = {
    for key, identity in local.github_config_identities : key => [
      for subject in identity.subjects : join(" && ", [
        "assertion.sub == 'repo:${var.github_config.immutable_repository}:${subject.context_type}:${subject.context_value}:workflow_ref:${subject.workflow_ref}:workflow_sha:' + assertion.workflow_sha",
        "assertion.workflow_ref == '${subject.workflow_ref}'",
        "assertion.workflow_sha == assertion.sha",
        subject.context_type == "environment" ? "assertion.environment == '${subject.context_value}'" : "assertion.ref == '${subject.context_value}'",
      ]) if contains(var.activation.active_subject_ids, subject.id)
    ]
  }
  active_github_config_identities = local.github_config_federation_state && var.github_config.activation_enabled ? {
    for key, identity in local.github_config_identities : key => identity
    if length(local.github_config_subject_conditions[key]) > 0
  } : {}
  infrastructure_drift = merge(var.infrastructure_live.drift, {
    service_email = "${var.infrastructure_live.drift.service_account_id}@${var.project_id}.iam.gserviceaccount.com"
  })
}

resource "google_iam_workload_identity_pool" "github" {
  for_each = local.identities

  project                   = each.value.pool_project_id
  workload_identity_pool_id = each.value.pool_id
  display_name              = "bootstrap GitHub ${each.key}"
  description               = "Isolated GitHub OIDC trust for bootstrap ${each.key} operations"
  disabled                  = false
  deletion_policy           = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workload_identity_pool_provider" "github" {
  for_each = local.identities

  project                            = each.value.pool_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github[each.key].workload_identity_pool_id
  workload_identity_pool_provider_id = each.value.provider_id
  display_name                       = "bootstrap GitHub ${each.key}"
  description                        = "Claim-restricted GitHub provider for bootstrap ${each.key} operations"
  disabled                           = false
  deletion_policy                    = "PREVENT"

  attribute_mapping = {
    "google.subject"                  = "'bootstrap-${each.key}:' + assertion.repository_id"
    "attribute.repository_id"         = "assertion.repository_id"
    "attribute.repository_owner_id"   = "assertion.repository_owner_id"
    "attribute.ref"                   = "assertion.ref"
    "attribute.workflow_ref"          = "assertion.workflow_ref"
    "attribute.workflow_sha"          = "assertion.workflow_sha"
    "attribute.environment"           = "assertion.environment"
    "attribute.event_name"            = "assertion.event_name"
    "attribute.repository_visibility" = "assertion.repository_visibility"
    "attribute.runner_environment"    = "assertion.runner_environment"
  }

  attribute_condition = join(" && ", [
    "assertion.sub == 'repo:${local.immutable_repository}:environment:${each.value.environment}:workflow_ref:${each.value.workflow_ref}:workflow_sha:' + assertion.workflow_sha",
    "assertion.repository == '${var.repository_full_name}'",
    "assertion.repository_owner == 'mindclade'",
    "assertion.repository_id == '${var.repository_id}'",
    "assertion.repository_owner_id == '${var.repository_owner_id}'",
    "assertion.repository_visibility == 'public'",
    "assertion.ref == '${var.branch_ref}'",
    "assertion.workflow_ref == '${each.value.workflow_ref}'",
    "assertion.workflow_sha == assertion.sha",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.environment == '${each.value.environment}'",
    "assertion.runner_environment == 'self-hosted'",
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

resource "google_iam_workload_identity_pool" "github_config" {
  for_each = local.github_config_federation_state && var.github_config.activation_enabled ? { pool = true } : {}

  project                   = var.project_id
  workload_identity_pool_id = var.github_config.pool_id
  display_name              = "github-config GitHub"
  description               = "Activation-gated GitHub OIDC trust for github-config"
  disabled                  = false
  deletion_policy           = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workload_identity_pool_provider" "github_config" {
  for_each = local.active_github_config_identities

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_config["pool"].workload_identity_pool_id
  workload_identity_pool_provider_id = each.value.provider_id
  display_name                       = "github-config ${each.key}"
  description                        = "Exact lifecycle-controlled GitHub trust for github-config ${each.key}"
  disabled                           = false
  deletion_policy                    = "PREVENT"

  attribute_mapping = {
    "google.subject"                   = "'github-config-${each.key}:' + assertion.repository_id"
    "attribute.github_config_identity" = "'${each.key}'"
    "attribute.repository_id"          = "assertion.repository_id"
    "attribute.repository_owner_id"    = "assertion.repository_owner_id"
    "attribute.ref"                    = "assertion.ref"
    "attribute.workflow_ref"           = "assertion.workflow_ref"
    "attribute.workflow_sha"           = "assertion.workflow_sha"
    "attribute.repository_visibility"  = "assertion.repository_visibility"
    "attribute.runner_environment"     = "assertion.runner_environment"
  }

  attribute_condition = join(" && ", [
    "assertion.repository == '${var.github_config.repository_full_name}'",
    "assertion.repository_owner == 'mindclade'",
    "assertion.repository_owner_id == '${var.github_config.repository_owner_id}'",
    "assertion.repository_id == '${var.github_config.repository_id}'",
    "assertion.repository_visibility == 'public'",
    "assertion.runner_environment == 'github-hosted'",
    "(${join(" || ", [for condition in local.github_config_subject_conditions[each.key] : "(${condition})"])})",
  ])

  oidc {
    issuer_uri        = var.github_config.issuer_uri
    allowed_audiences = ["sts.googleapis.com"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "github_config" {
  for_each = local.github_config_identities

  project         = var.project_id
  account_id      = each.value.service_account_id
  display_name    = "github-config ${each.key}"
  description     = "Role-separated github-config ${each.key} identity; federation is lifecycle-controlled"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = local.activation_flags_valid
      error_message = "Conditional federation activation flags must exactly match the declared lifecycle state."
    }
  }
}

resource "google_service_account_iam_member" "github_config" {
  for_each = local.active_github_config_identities

  service_account_id = "projects/${var.project_id}/serviceAccounts/${each.value.service_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_config["pool"].name}/attribute.github_config_identity/${each.key}"

  depends_on = [
    google_iam_workload_identity_pool_provider.github_config,
    google_service_account.github_config,
  ]
}

resource "google_iam_workload_identity_pool" "infrastructure_live" {
  for_each = { pool = true }

  project                   = var.project_id
  workload_identity_pool_id = var.infrastructure_live.pool_id
  display_name              = "infrastructure-live GitHub"
  description               = "Environment and role separated GitHub OIDC trust for infrastructure-live"
  disabled                  = false
  deletion_policy           = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workload_identity_pool_provider" "infrastructure_live" {
  for_each = local.infrastructure_identities

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.infrastructure_live["pool"].workload_identity_pool_id
  workload_identity_pool_provider_id = each.value.provider_id
  display_name                       = "infra-live ${each.key}"
  description                        = "Exact immutable GitHub trust for infrastructure-live ${each.key}"
  disabled                           = false
  deletion_policy                    = "PREVENT"

  attribute_mapping = {
    "google.subject"                    = "'infrastructure-live-${each.key}:' + assertion.repository_id"
    "attribute.infrastructure_identity" = "'${each.key}'"
    "attribute.repository_id"           = "assertion.repository_id"
    "attribute.repository_owner_id"     = "assertion.repository_owner_id"
    "attribute.workflow_ref"            = "assertion.workflow_ref"
    "attribute.workflow_sha"            = "assertion.workflow_sha"
    "attribute.environment"             = "assertion.environment"
  }

  attribute_condition = join(" && ", [
    "assertion.sub == 'repo:${var.infrastructure_live.immutable_repository}:environment:${each.value.environment}:workflow_ref:${var.infrastructure_live.workflow_ref}:workflow_sha:' + assertion.workflow_sha",
    "assertion.repository == '${var.infrastructure_live.repository_full_name}'",
    "assertion.repository_owner == 'mindclade'",
    "assertion.repository_owner_id == '${var.infrastructure_live.repository_owner_id}'",
    "assertion.repository_id == '${var.infrastructure_live.repository_id}'",
    "assertion.repository_visibility == 'public'",
    "assertion.ref == '${var.infrastructure_live.branch_ref}'",
    "assertion.workflow_ref == '${var.infrastructure_live.workflow_ref}'",
    "assertion.workflow_sha == assertion.sha",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.environment == '${each.value.environment}'",
    "assertion.runner_environment == 'github-hosted'",
  ])

  oidc {
    issuer_uri        = var.infrastructure_live.issuer_uri
    allowed_audiences = [each.value.audience]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "infrastructure_live" {
  for_each = local.infrastructure_identities

  project         = var.project_id
  account_id      = each.value.service_account_id
  display_name    = "infrastructure-live ${each.key}"
  description     = "Keyless ${each.key} handoff identity; environment authority is bound downstream"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account_iam_member" "infrastructure_live" {
  for_each = local.infrastructure_identities

  service_account_id = "projects/${var.project_id}/serviceAccounts/${each.value.service_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.infrastructure_live["pool"].name}/attribute.infrastructure_identity/${each.key}"

  depends_on = [
    google_iam_workload_identity_pool_provider.infrastructure_live,
    google_service_account.infrastructure_live,
  ]
}

resource "google_iam_workload_identity_pool_provider" "infrastructure_drift" {
  for_each = local.connected_federation_state && var.infrastructure_live.drift.activation_enabled ? { drift = local.infrastructure_drift } : {}

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.infrastructure_live["pool"].workload_identity_pool_id
  workload_identity_pool_provider_id = each.value.provider_id
  display_name                       = "infrastructure-live drift plan"
  description                        = "Exact lifecycle-controlled GitHub trust for infrastructure-live drift observation"
  disabled                           = false
  deletion_policy                    = "PREVENT"

  attribute_mapping = {
    "google.subject"                    = "'infrastructure-live-drift-plan:' + assertion.repository_id"
    "attribute.infrastructure_identity" = "'drift-plan'"
    "attribute.repository_id"           = "assertion.repository_id"
    "attribute.repository_owner_id"     = "assertion.repository_owner_id"
    "attribute.workflow_ref"            = "assertion.workflow_ref"
    "attribute.workflow_sha"            = "assertion.workflow_sha"
    "attribute.environment"             = "assertion.environment"
  }

  attribute_condition = join(" && ", [
    "assertion.sub == 'repo:${var.infrastructure_live.immutable_repository}:environment:${each.value.environment}:workflow_ref:${each.value.workflow_ref}:workflow_sha:' + assertion.workflow_sha",
    "assertion.repository == '${var.infrastructure_live.repository_full_name}'",
    "assertion.repository_owner == 'mindclade'",
    "assertion.repository_owner_id == '${var.infrastructure_live.repository_owner_id}'",
    "assertion.repository_id == '${var.infrastructure_live.repository_id}'",
    "assertion.repository_visibility == 'public'",
    "assertion.ref == '${var.infrastructure_live.branch_ref}'",
    "assertion.workflow_ref == '${each.value.workflow_ref}'",
    "assertion.workflow_sha == assertion.sha",
    "assertion.environment == '${each.value.environment}'",
    "assertion.runner_environment == 'github-hosted'",
  ])

  oidc {
    issuer_uri        = var.infrastructure_live.issuer_uri
    allowed_audiences = [each.value.audience]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "infrastructure_drift" {
  for_each = { drift = local.infrastructure_drift }

  project         = var.project_id
  account_id      = each.value.service_account_id
  display_name    = "infrastructure-live drift plan"
  description     = "Roleless infrastructure drift identity; federation is lifecycle-controlled"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account_iam_member" "infrastructure_drift" {
  for_each = local.connected_federation_state && var.infrastructure_live.drift.activation_enabled ? { drift = local.infrastructure_drift } : {}

  service_account_id = google_service_account.infrastructure_drift["drift"].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.infrastructure_live["pool"].name}/attribute.infrastructure_identity/drift-plan"

  depends_on = [google_iam_workload_identity_pool_provider.infrastructure_drift]
}

resource "google_iam_workload_identity_pool" "ci_evidence" {
  for_each = local.connected_federation_state && var.ci_evidence.activation_enabled ? { archive = true } : {}

  project                   = var.project_id
  workload_identity_pool_id = var.ci_evidence.pool_id
  display_name              = "GitHub CI evidence"
  description               = "Dedicated GitHub OIDC trust for immutable CI evidence archival and verification"
  disabled                  = false
  deletion_policy           = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workload_identity_pool_provider" "ci_evidence" {
  for_each = local.active_ci_evidence_identities

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.ci_evidence["archive"].workload_identity_pool_id
  workload_identity_pool_provider_id = each.value.provider_id
  display_name                       = "GitHub CI evidence ${each.key}"
  description                        = "Claim-restricted GitHub CI evidence ${each.key} identity"
  disabled                           = false
  deletion_policy                    = "PREVENT"

  attribute_mapping = merge(
    {
      "google.subject"                  = "'ci-evidence-${each.key}:' + assertion.repository_id"
      "attribute.evidence_role"         = "'${each.key}'"
      "attribute.repository_id"         = "assertion.repository_id"
      "attribute.repository_owner_id"   = "assertion.repository_owner_id"
      "attribute.ref"                   = "assertion.ref"
      "attribute.event_name"            = "assertion.event_name"
      "attribute.repository_visibility" = "assertion.repository_visibility"
      "attribute.runner_environment"    = "assertion.runner_environment"
    },
    each.key == "writer" ? {
      "attribute.job_workflow_ref" = "assertion.job_workflow_ref"
      "attribute.job_workflow_sha" = "assertion.job_workflow_sha"
      } : {
      "attribute.workflow_ref" = "assertion.workflow_ref"
      "attribute.workflow_sha" = "assertion.workflow_sha"
      "attribute.environment"  = "assertion.environment"
    },
  )

  attribute_condition = each.key == "writer" ? join(" && ", [
    "assertion.repository_owner_id == '${var.ci_evidence.repository_owner_id}'",
    "assertion.repository_id in [${local.ci_evidence_repository_ids}]",
    "assertion.repository_visibility == 'public'",
    "assertion.runner_environment == 'github-hosted'",
    "assertion.job_workflow_ref == '${var.ci_evidence.writer.job_workflow_ref}'",
    "assertion.job_workflow_sha == '${local.ci_evidence_writer_sha}'",
    "((assertion.event_name == 'push' && assertion.ref == 'refs/heads/main') || (assertion.event_name == 'release' && assertion.ref.startsWith('refs/tags/v')))",
    ]) : join(" && ", [
    "assertion.repository_owner_id == '${var.ci_evidence.repository_owner_id}'",
    "assertion.repository_id == '${var.ci_evidence.verifier.repository_id}'",
    "assertion.repository_visibility == 'public'",
    "assertion.runner_environment == 'github-hosted'",
    "assertion.workflow_ref == '${var.ci_evidence.verifier.workflow_ref}'",
    "assertion.workflow_sha == '${var.ci_evidence.verifier.workflow_sha}'",
    "assertion.ref == 'refs/heads/main'",
    "assertion.event_name == 'workflow_dispatch'",
    "assertion.environment == '${var.ci_evidence.verifier.environment}'",
  ])

  oidc {
    # Omitting allowed_audiences makes Google accept only this provider's two
    # canonical resource-name audiences. google-github-actions/auth requests
    # the HTTPS-prefixed canonical form by default.
    issuer_uri = var.issuer_uri
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "ci_evidence" {
  for_each = local.ci_evidence_identities

  project         = var.project_id
  account_id      = each.value.service_account_id
  display_name    = "CI evidence ${each.key}"
  description     = "Keyless CI evidence ${each.key} identity; bucket authority is bound downstream"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account_iam_member" "ci_evidence" {
  for_each = local.active_ci_evidence_identities

  service_account_id = "projects/${var.project_id}/serviceAccounts/${each.value.service_email}"
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.ci_evidence["archive"].name}/attribute.evidence_role/${each.key}"

  depends_on = [
    google_iam_workload_identity_pool_provider.ci_evidence,
    google_service_account.ci_evidence,
  ]
}
