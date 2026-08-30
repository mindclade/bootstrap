variable "bootstrap" {
  description = "Resolved, non-secret bootstrap configuration compiled from the versioned manifests."
  type = object({
    organization_id                  = string
    billing_account                  = string
    default_region                   = string
    recovery_region                  = string
    root_administrator_principal     = string
    recovery_administrator_principal = string
    labels                           = optional(map(string), {})

    projects = object({
      root_state = object({
        id   = string
        name = string
      })
      recovery = object({
        id   = string
        name = string
      })
      audit = object({
        id   = string
        name = string
      })
      identity = object({
        id   = string
        name = string
      })
      signing = object({
        id   = string
        name = string
      })
    })

    state_backends = object({
      root_trust = object({
        bucket_name         = string
        replica_bucket_name = string
        key_name            = string
        replica_key_name    = string
        prefix              = string
      })
      recovery_plane = object({
        bucket_name         = string
        replica_bucket_name = string
        key_name            = string
        replica_key_name    = string
        prefix              = string
      })
    })

    audit = object({
      buckets = map(object({
        bucket_id = string
        location  = string
        key_name  = string
      }))
      sinks = map(object({
        bucket_id = string
        name      = string
        filter    = optional(string, "")
      }))
      retention_days           = number
      lock_after_qualification = bool
      qualification_evidence = optional(object({
        artifact_sha256      = string
        signature_sha256     = string
        signing_key_ref      = string
        qualified_source_sha = string
        qualified_at         = string
      }))
      reader_principals        = set(string)
      administrator_principals = set(string)
    })

    workforce = object({
      pool_id             = string
      provider_id         = string
      issuer_uri          = string
      client_id           = string
      administrator_group = string
      attribute_mapping   = map(string)
      attribute_condition = string
      additional_scopes   = optional(set(string), ["groups"])
    })

    github = object({
      issuer_uri           = string
      repository_full_name = string
      repository_id        = string
      repository_owner_id  = string
      branch_ref           = string
      pool_ids = object({
        plan     = string
        apply    = string
        recovery = string
      })
      provider_ids = object({
        plan     = string
        apply    = string
        recovery = string
      })
      service_account_ids = object({
        plan     = string
        apply    = string
        recovery = string
      })
      audiences = object({
        plan     = string
        apply    = string
        recovery = string
      })
      workflow_refs = object({
        plan     = string
        apply    = string
        recovery = string
      })
    })

    github_ci_evidence = object({
      activation_enabled  = bool
      pool_id             = string
      repository_owner_id = string
      repository_ids      = map(string)
      writer = object({
        provider_id        = string
        service_account_id = string
        job_workflow_ref   = string
      })
      verifier = object({
        provider_id        = string
        service_account_id = string
        repository_id      = string
        workflow_ref       = string
        workflow_sha       = string
        environment        = string
      })
    })

    github_config = object({
      activation_enabled   = bool
      pool_id              = string
      issuer_uri           = string
      repository_owner_id  = string
      repository_id        = string
      immutable_repository = string
      repository_full_name = string
      branch_ref           = string
      identities = map(object({
        provider_id        = string
        service_account_id = string
        subjects = list(object({
          id            = string
          workflow_ref  = string
          context_type  = string
          context_value = string
          audience      = string
        }))
      }))
    })

    github_infrastructure = object({
      pool_id              = string
      issuer_uri           = string
      repository_owner_id  = string
      repository_id        = string
      immutable_repository = string
      repository_full_name = string
      branch_ref           = string
      workflow_ref         = string
      drift = object({
        activation_enabled = bool
        subject_id         = string
        provider_id        = string
        service_account_id = string
        workflow_ref       = string
        environment        = string
        audience           = string
      })
      identities = map(object({
        provider_id        = string
        service_account_id = string
        environment        = string
        audience           = string
      }))
    })

    github_activation = object({
      state              = string
      active_subject_ids = list(string)
      gated_subject_ids  = list(string)
      blockers           = list(string)
    })

    buildkite = object({
      pool_id            = string
      provider_id        = string
      service_account_id = string
      issuer_uri         = string
      audience           = string
      organization_slug  = string
      pipeline_slug      = string
      pipeline_id        = string
      build_branch       = string
      step_key           = string
    })

    gitops = object({
      pool_id            = string
      provider_id        = string
      service_account_id = string
      issuer_uri         = string
      audience           = string
      subject            = string
      repository         = string
      ref                = string
    })

    signing = object({
      location       = string
      key_ring_name  = string
      administrators = set(string)
      keys = map(object({
        signer_principals  = set(string)
        rotation_days      = number
        active_version_ref = string
        versions = map(object({
          activation_window_start = string
          rotation_deadline       = string
        }))
      }))
    })

    break_glass = object({
      requester_principals    = set(string)
      approver_principals     = set(string)
      notification_recipients = set(string)
      entitlements = map(object({
        target_project_id = string
        roles             = set(string)
      }))
    })
  })

  validation {
    condition = length(distinct([
      var.bootstrap.projects.root_state.id,
      var.bootstrap.projects.recovery.id,
      var.bootstrap.projects.audit.id,
      var.bootstrap.projects.identity.id,
      var.bootstrap.projects.signing.id,
    ])) == 5
    error_message = "State, recovery, audit, identity, and signing roots must use distinct projects."
  }

  validation {
    condition     = var.bootstrap.default_region != var.bootstrap.recovery_region
    error_message = "The primary and recovery regions must be independent."
  }

  validation {
    condition     = can(regex("^group:[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.bootstrap.root_administrator_principal))
    error_message = "root_administrator_principal must be one explicit group email principal."
  }

  validation {
    condition     = can(regex("^group:[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.bootstrap.recovery_administrator_principal))
    error_message = "recovery_administrator_principal must be one explicit group email principal."
  }

  validation {
    condition     = var.bootstrap.root_administrator_principal != var.bootstrap.recovery_administrator_principal
    error_message = "Root and recovery administrator principals must remain distinct."
  }

  validation {
    condition = length(distinct([
      var.bootstrap.state_backends.root_trust.bucket_name,
      var.bootstrap.state_backends.root_trust.replica_bucket_name,
      var.bootstrap.state_backends.recovery_plane.bucket_name,
      var.bootstrap.state_backends.recovery_plane.replica_bucket_name,
    ])) == 4
    error_message = "Every primary and replica state bucket must have a distinct global name."
  }
}

variable "workforce_oidc_client_secret" {
  description = "Required OIDC secret supplied only at runtime and sent through a write-only provider field."
  type        = string
  sensitive   = true
  ephemeral   = true
  nullable    = false

  validation {
    condition     = length(var.workforce_oidc_client_secret) >= 32 && !can(regex("[\\r\\n]", var.workforce_oidc_client_secret))
    error_message = "workforce_oidc_client_secret must be a high-entropy single-line value of at least 32 characters."
  }
}

variable "workforce_oidc_client_secret_version" {
  description = "Monotonic revision for the write-only OIDC secret."
  type        = number

  validation {
    condition     = var.workforce_oidc_client_secret_version >= 1 && floor(var.workforce_oidc_client_secret_version) == var.workforce_oidc_client_secret_version
    error_message = "workforce_oidc_client_secret_version must be a positive integer."
  }
}

locals {
  identity_services = toset([
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "serviceusage.googleapis.com",
    "sts.googleapis.com",
  ])

  state_services = toset([
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
    "storagetransfer.googleapis.com",
  ])

  workload_identity_project_services = {
    root_state = toset([
      "iamcredentials.googleapis.com",
    ])
    recovery = toset([
      "iamcredentials.googleapis.com",
      "sts.googleapis.com",
    ])
  }

  state_projects = {
    root_state = {
      id   = var.bootstrap.projects.root_state.id
      name = var.bootstrap.projects.root_state.name
    }
    recovery = {
      id   = var.bootstrap.projects.recovery.id
      name = var.bootstrap.projects.recovery.name
    }
  }

  state_project_services = merge({
    for binding in setproduct(keys(local.state_projects), local.state_services) :
    "${binding[0]}:${binding[1]}" => {
      project_key = binding[0]
      service     = binding[1]
    }
    }, {
    for binding in flatten([
      for project_key, services in local.workload_identity_project_services : [
        for service in services : {
          key         = "${project_key}:${service}"
          project_key = project_key
          service     = service
        }
      ]
    ]) : binding.key => binding
  })

  plan_principal     = module.github_federation.principal_members["plan"]
  apply_principal    = module.github_federation.principal_members["apply"]
  recovery_principal = module.github_federation.principal_members["recovery"]

  audit_buckets = {
    for name, bucket in var.bootstrap.audit.buckets : name => merge(bucket, {
      project_id = name == "primary" ? var.bootstrap.projects.audit.id : var.bootstrap.projects.recovery.id
    })
  }

  signing_keys = {
    for name, key in var.bootstrap.signing.keys : name => {
      signer_principals = setunion(
        key.signer_principals,
        name == "bootstrap-handoff" || name == "audit-anchor" ? [module.buildkite_federation.principal_member] : [],
        name == "recovery-evidence" ? [local.recovery_principal] : [],
      )
      rotation_days      = key.rotation_days
      active_version_ref = key.active_version_ref
      versions           = key.versions
    }
  }

  recovery_administration_roles = toset([
    "roles/cloudkms.admin",
    "roles/iam.roleAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/logging.admin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/storage.admin",
    "roles/storagetransfer.user",
  ])

  project_administration = merge(
    {
      for role in [
        "roles/iam.workloadIdentityPoolAdmin",
        "roles/privilegedaccessmanager.admin",
        "roles/resourcemanager.projectIamAdmin",
        "roles/serviceusage.serviceUsageAdmin",
        ] : "identity:${role}" => {
        project = var.bootstrap.projects.identity.id
        role    = role
      }
    },
    {
      for role in [
        "roles/cloudkms.admin",
        "roles/resourcemanager.projectIamAdmin",
        "roles/serviceusage.serviceUsageAdmin",
        ] : "audit:${role}" => {
        project = var.bootstrap.projects.audit.id
        role    = role
      }
    },
  )

  plan_project_roles = {
    identity = {
      project = var.bootstrap.projects.identity.id
      roles = toset([
        "roles/browser",
        "roles/iam.securityReviewer",
        "roles/iam.serviceAccountViewer",
        "roles/iam.workloadIdentityPoolViewer",
        "roles/privilegedaccessmanager.viewer",
        "roles/serviceusage.serviceUsageViewer",
      ])
    }
    state = {
      project = var.bootstrap.projects.root_state.id
      roles = toset([
        "roles/browser",
        "roles/cloudkms.viewer",
        "roles/iam.roleViewer",
        "roles/iam.securityReviewer",
        "roles/iam.serviceAccountViewer",
        "roles/privilegedaccessmanager.viewer",
        "roles/serviceusage.serviceUsageViewer",
        "roles/storagetransfer.viewer",
      ])
    }
    recovery = {
      project = var.bootstrap.projects.recovery.id
      roles = toset([
        "roles/browser",
        "roles/cloudkms.viewer",
        "roles/iam.roleViewer",
        "roles/iam.securityReviewer",
        "roles/iam.serviceAccountViewer",
        "roles/iam.workloadIdentityPoolViewer",
        "roles/privilegedaccessmanager.viewer",
        "roles/serviceusage.serviceUsageViewer",
        "roles/storagetransfer.viewer",
      ])
    }
    audit = {
      project = var.bootstrap.projects.audit.id
      roles = toset([
        "roles/browser",
        "roles/cloudkms.viewer",
        "roles/iam.securityReviewer",
        "roles/serviceusage.serviceUsageViewer",
      ])
    }
    signing = {
      project = var.bootstrap.projects.signing.id
      roles = toset([
        "roles/browser",
        "roles/cloudkms.viewer",
        "roles/iam.roleViewer",
        "roles/iam.securityReviewer",
        "roles/privilegedaccessmanager.viewer",
        "roles/serviceusage.serviceUsageViewer",
      ])
    }
  }

  plan_project_access = {
    for binding in flatten([
      for project_name, config in local.plan_project_roles : [
        for role in config.roles : {
          key     = "${project_name}:${role}"
          project = config.project
          role    = role
        }
      ]
      ]) : binding.key => {
      project = binding.project
      role    = binding.role
    }
  }

}

resource "google_project" "identity" {
  project_id          = var.bootstrap.projects.identity.id
  name                = var.bootstrap.projects.identity.name
  org_id              = var.bootstrap.organization_id
  billing_account     = var.bootstrap.billing_account
  auto_create_network = false
  deletion_policy     = "PREVENT"
  labels              = var.bootstrap.labels

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project" "state" {
  for_each = local.state_projects

  project_id          = each.value.id
  name                = each.value.name
  org_id              = var.bootstrap.organization_id
  billing_account     = var.bootstrap.billing_account
  auto_create_network = false
  deletion_policy     = "PREVENT"
  labels              = var.bootstrap.labels

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_service" "identity" {
  for_each = local.identity_services

  project            = google_project.identity.project_id
  service            = each.value
  disable_on_destroy = false
  deletion_policy    = "PREVENT"
}

resource "google_project_service" "state" {
  for_each = local.state_project_services

  project            = google_project.state[each.value.project_key].project_id
  service            = each.value.service
  disable_on_destroy = false
  deletion_policy    = "PREVENT"
}

module "github_federation" {
  source = "../../modules/github-federation"

  project_id = var.bootstrap.projects.identity.id
  service_account_project_ids = {
    plan     = var.bootstrap.projects.root_state.id
    apply    = var.bootstrap.projects.root_state.id
    recovery = var.bootstrap.projects.recovery.id
  }
  issuer_uri           = var.bootstrap.github.issuer_uri
  repository_full_name = var.bootstrap.github.repository_full_name
  repository_id        = var.bootstrap.github.repository_id
  repository_owner_id  = var.bootstrap.github.repository_owner_id
  branch_ref           = var.bootstrap.github.branch_ref
  pool_ids             = var.bootstrap.github.pool_ids
  provider_ids         = var.bootstrap.github.provider_ids
  service_account_ids  = var.bootstrap.github.service_account_ids
  audiences            = var.bootstrap.github.audiences
  workflow_refs        = var.bootstrap.github.workflow_refs
  github_config        = var.bootstrap.github_config
  infrastructure_live  = var.bootstrap.github_infrastructure
  ci_evidence          = var.bootstrap.github_ci_evidence

  depends_on = [google_project_service.identity, google_project_service.state]
}

module "buildkite_federation" {
  source = "../../modules/buildkite-federation"

  project_id                 = var.bootstrap.projects.identity.id
  service_account_project_id = var.bootstrap.projects.root_state.id
  pool_id                    = var.bootstrap.buildkite.pool_id
  provider_id                = var.bootstrap.buildkite.provider_id
  service_account_id         = var.bootstrap.buildkite.service_account_id
  issuer_uri                 = var.bootstrap.buildkite.issuer_uri
  audience                   = var.bootstrap.buildkite.audience
  organization_slug          = var.bootstrap.buildkite.organization_slug
  pipeline_slug              = var.bootstrap.buildkite.pipeline_slug
  pipeline_id                = var.bootstrap.buildkite.pipeline_id
  build_branch               = var.bootstrap.buildkite.build_branch
  step_key                   = var.bootstrap.buildkite.step_key

  depends_on = [google_project_service.identity, google_project_service.state]
}

module "gitops_federation" {
  source = "../../modules/gitops-federation"

  project_id                 = var.bootstrap.projects.identity.id
  service_account_project_id = var.bootstrap.projects.recovery.id
  pool_id                    = var.bootstrap.gitops.pool_id
  provider_id                = var.bootstrap.gitops.provider_id
  service_account_id         = var.bootstrap.gitops.service_account_id
  issuer_uri                 = var.bootstrap.gitops.issuer_uri
  audience                   = var.bootstrap.gitops.audience
  subject                    = var.bootstrap.gitops.subject
  repository                 = var.bootstrap.gitops.repository
  ref                        = var.bootstrap.gitops.ref

  depends_on = [google_project_service.identity, google_project_service.state]
}

module "root_state" {
  source = "../../modules/state-backend"

  project_id          = var.bootstrap.projects.root_state.id
  replica_project_id  = var.bootstrap.projects.recovery.id
  backend_prefix      = var.bootstrap.state_backends.root_trust.prefix
  bucket_name         = var.bootstrap.state_backends.root_trust.bucket_name
  replica_bucket_name = var.bootstrap.state_backends.root_trust.replica_bucket_name
  key_name            = var.bootstrap.state_backends.root_trust.key_name
  replica_key_name    = var.bootstrap.state_backends.root_trust.replica_key_name
  location            = var.bootstrap.default_region
  replica_location    = var.bootstrap.recovery_region
  plan_principal      = local.plan_principal
  apply_principal     = local.apply_principal
  recovery_principal  = local.recovery_principal
  labels              = var.bootstrap.labels

  depends_on = [
    google_project_iam_member.apply_administration,
    google_project_service.state,
  ]
}

module "recovery_state" {
  source = "../../modules/state-backend"

  project_id          = var.bootstrap.projects.recovery.id
  replica_project_id  = var.bootstrap.projects.root_state.id
  backend_prefix      = var.bootstrap.state_backends.recovery_plane.prefix
  bucket_name         = var.bootstrap.state_backends.recovery_plane.bucket_name
  replica_bucket_name = var.bootstrap.state_backends.recovery_plane.replica_bucket_name
  key_name            = var.bootstrap.state_backends.recovery_plane.key_name
  replica_key_name    = var.bootstrap.state_backends.recovery_plane.replica_key_name
  location            = var.bootstrap.recovery_region
  replica_location    = var.bootstrap.default_region
  plan_principal      = local.plan_principal
  # Recovery-plane state mutation is deliberately excluded from the standing
  # GitHub apply identity. Independently authenticated recovery custodians own
  # the only backend-writer path until a separately qualified JIT grant exists.
  apply_principal    = var.bootstrap.recovery_administrator_principal
  recovery_principal = local.recovery_principal
  labels             = var.bootstrap.labels

  depends_on = [
    google_project_iam_member.apply_administration,
    google_project_service.state,
  ]
}

module "audit_root" {
  source = "../../modules/audit-root"

  organization_id           = var.bootstrap.organization_id
  billing_account           = var.bootstrap.billing_account
  project_id                = var.bootstrap.projects.audit.id
  project_name              = var.bootstrap.projects.audit.name
  buckets                   = local.audit_buckets
  sinks                     = var.bootstrap.audit.sinks
  retention_days            = var.bootstrap.audit.retention_days
  lock_after_qualification  = var.bootstrap.audit.lock_after_qualification
  reader_principals         = var.bootstrap.audit.reader_principals
  recovery_reader_principal = local.recovery_principal
  administrator_principals = setunion(
    var.bootstrap.audit.administrator_principals,
    [local.apply_principal],
  )
  plan_principal = local.plan_principal
  labels         = var.bootstrap.labels

  depends_on = [google_project_service.state]
}

resource "google_organization_iam_audit_config" "storage_data_access" {
  org_id  = var.bootstrap.organization_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

module "workforce_identity" {
  source = "../../modules/workforce-identity"

  organization_id       = var.bootstrap.organization_id
  pool_id               = var.bootstrap.workforce.pool_id
  provider_id           = var.bootstrap.workforce.provider_id
  issuer_uri            = var.bootstrap.workforce.issuer_uri
  client_id             = var.bootstrap.workforce.client_id
  administrator_group   = var.bootstrap.workforce.administrator_group
  client_secret         = var.workforce_oidc_client_secret
  client_secret_version = var.workforce_oidc_client_secret_version
  attribute_mapping     = var.bootstrap.workforce.attribute_mapping
  attribute_condition   = var.bootstrap.workforce.attribute_condition
  additional_scopes     = var.bootstrap.workforce.additional_scopes

  depends_on = [google_project_service.identity]
}

module "signing_root" {
  source = "../../modules/signing-root"

  organization_id             = var.bootstrap.organization_id
  billing_account             = var.bootstrap.billing_account
  project_id                  = var.bootstrap.projects.signing.id
  project_name                = var.bootstrap.projects.signing.name
  location                    = var.bootstrap.signing.location
  key_ring_name               = var.bootstrap.signing.key_ring_name
  administrator_principals    = var.bootstrap.signing.administrators
  recovery_verifier_principal = local.recovery_principal
  keys                        = local.signing_keys
  disabled_signing_keys       = toset(["infrastructure-export"])
  labels                      = var.bootstrap.labels

  depends_on = [module.github_federation]
}

module "break_glass" {
  source = "../../modules/break-glass"

  requester_principals    = var.bootstrap.break_glass.requester_principals
  approver_principals     = var.bootstrap.break_glass.approver_principals
  notification_recipients = var.bootstrap.break_glass.notification_recipients
  entitlements            = var.bootstrap.break_glass.entitlements

  depends_on = [
    google_project.identity,
    google_project.state,
    module.audit_root,
    module.recovery_state,
    module.root_state,
    module.signing_root,
  ]
}

resource "google_project_iam_member" "apply_administration" {
  for_each = local.project_administration

  project = each.value.project
  role    = each.value.role
  member  = local.apply_principal

  depends_on = [module.audit_root, module.signing_root]
}

resource "google_project_iam_member" "plan_read" {
  for_each = local.plan_project_access

  project = each.value.project
  role    = each.value.role
  member  = local.plan_principal

  depends_on = [module.audit_root, module.signing_root]
}

resource "google_project_iam_member" "recovery_administration" {
  for_each = local.recovery_administration_roles

  project = google_project.state["recovery"].project_id
  role    = each.value
  member  = var.bootstrap.recovery_administrator_principal
}

resource "google_organization_iam_custom_role" "plan_read" {
  org_id      = var.bootstrap.organization_id
  role_id     = "bootstrapOrganizationPlanRead"
  title       = "Bootstrap organization plan read"
  description = "Refresh only organization, IAM-policy, custom-role, and exact sink metadata during reviewed plans"
  permissions = [
    "iam.roles.get",
    "logging.sinks.get",
    "resourcemanager.organizations.get",
    "resourcemanager.organizations.getIamPolicy",
  ]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_organization_iam_custom_role" "recovery_sink_read" {
  org_id      = var.bootstrap.organization_id
  role_id     = "bootstrapRecoverySinkRead"
  title       = "Bootstrap recovery sink read"
  description = "Describe fixed organization audit sinks and verify the Storage Data Access audit configuration"
  permissions = [
    "logging.sinks.get",
    "resourcemanager.organizations.getIamPolicy",
  ]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_organization_iam_custom_role" "apply_iam" {
  org_id      = var.bootstrap.organization_id
  role_id     = "bootstrapOrganizationIamApply"
  title       = "Bootstrap organization IAM apply"
  description = "Read-modify-write only the source-managed organization IAM bindings during protected apply"
  permissions = [
    "resourcemanager.organizations.getIamPolicy",
    "resourcemanager.organizations.setIamPolicy",
  ]
  stage           = "GA"
  deletion_policy = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_organization_iam_member" "plan_read" {
  org_id = var.bootstrap.organization_id
  role   = "organizations/${var.bootstrap.organization_id}/roles/${google_organization_iam_custom_role.plan_read.role_id}"
  member = local.plan_principal
}

resource "google_organization_iam_member" "recovery_sink_read" {
  org_id = var.bootstrap.organization_id
  role   = "organizations/${var.bootstrap.organization_id}/roles/${google_organization_iam_custom_role.recovery_sink_read.role_id}"
  member = local.recovery_principal
}

resource "google_organization_iam_member" "apply_iam" {
  org_id = var.bootstrap.organization_id
  role   = "organizations/${var.bootstrap.organization_id}/roles/${google_organization_iam_custom_role.apply_iam.role_id}"
  member = var.bootstrap.root_administrator_principal
}

resource "google_organization_iam_member" "plan_workforce_viewer" {
  org_id = var.bootstrap.organization_id
  role   = "roles/iam.workforcePoolViewer"
  member = local.plan_principal
}

resource "google_organization_iam_member" "apply_logging_config_writer" {
  org_id = var.bootstrap.organization_id
  role   = "roles/logging.configWriter"
  member = var.bootstrap.root_administrator_principal
}

resource "google_organization_iam_member" "apply_workforce_admin" {
  org_id = var.bootstrap.organization_id
  role   = "roles/iam.workforcePoolAdmin"
  member = var.bootstrap.root_administrator_principal
}

resource "google_organization_iam_member" "apply_organization_role_admin" {
  org_id = var.bootstrap.organization_id
  role   = "roles/iam.organizationRoleAdmin"
  member = var.bootstrap.root_administrator_principal
}
