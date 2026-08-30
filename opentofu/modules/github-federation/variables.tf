variable "project_id" {
  description = "Identity project that owns the GitHub federation resources."
  type        = string
}

variable "service_account_project_ids" {
  description = "Manifest-selected projects that own the isolated execution service accounts."
  type = object({
    plan     = string
    apply    = string
    recovery = string
  })
}

variable "issuer_uri" {
  description = "Resolved GitHub Actions OIDC issuer; restricted to the canonical endpoint."
  type        = string

  validation {
    condition     = var.issuer_uri == "https://token.actions.githubusercontent.com"
    error_message = "GitHub federation must use the canonical token.actions.githubusercontent.com issuer."
  }
}

variable "repository_full_name" {
  description = "Exact owner/name of the bootstrap repository."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.repository_full_name))
    error_message = "repository_full_name must use the owner/name form."
  }

  validation {
    condition     = var.repository_full_name == "mindclade/bootstrap"
    error_message = "Bootstrap GitHub federation must bind the exact canonical repository."
  }
}

variable "repository_id" {
  description = "Immutable numeric GitHub repository ID."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.repository_id))
    error_message = "repository_id must be GitHub's immutable numeric ID."
  }


  validation {
    condition     = var.repository_id == "1350991612"
    error_message = "Bootstrap GitHub federation must bind the immutable bootstrap repository ID."
  }
}

variable "repository_owner_id" {
  description = "Immutable numeric GitHub repository-owner ID."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.repository_owner_id))
    error_message = "repository_owner_id must be GitHub's immutable numeric ID."
  }


  validation {
    condition     = var.repository_owner_id == "316676129"
    error_message = "Bootstrap GitHub federation must bind Mindclade's immutable organization ID."
  }
}

variable "branch_ref" {
  description = "Protected Git ref authorized for privileged workflows."
  type        = string
  default     = "refs/heads/main"

  validation {
    condition     = startswith(var.branch_ref, "refs/heads/")
    error_message = "branch_ref must be a fully qualified branch ref."
  }


  validation {
    condition     = var.branch_ref == "refs/heads/main"
    error_message = "Bootstrap GitHub federation must bind only protected main."
  }
}

variable "pool_ids" {
  description = "Distinct workload identity pool IDs for plan, apply, and recovery."
  type = object({
    plan     = string
    apply    = string
    recovery = string
  })

  validation {
    condition     = length(distinct(values(var.pool_ids))) == 3
    error_message = "Plan, apply, and recovery must use distinct workload identity pools."
  }
}

variable "provider_ids" {
  description = "Provider IDs keyed by plan, apply, and recovery."
  type = object({
    plan     = string
    apply    = string
    recovery = string
  })
}

variable "service_account_ids" {
  description = "Distinct service-account IDs for plan, apply, and recovery."
  type = object({
    plan     = string
    apply    = string
    recovery = string
  })

  validation {
    condition     = length(distinct(values(var.service_account_ids))) == 3
    error_message = "Plan, apply, and recovery must use distinct service accounts."
  }
}

variable "audiences" {
  description = "Distinct, explicitly allowed OIDC audiences."
  type = object({
    plan     = string
    apply    = string
    recovery = string
  })

  validation {
    condition     = alltrue([for value in values(var.audiences) : value == "sts.googleapis.com"])
    error_message = "Plan, apply, and recovery must use only the organization-approved sts.googleapis.com audience."
  }
}

variable "workflow_refs" {
  description = "Exact immutable workflow_ref claims, including repository, path, and protected ref."
  type = object({
    plan     = string
    apply    = string
    recovery = string
  })

  validation {
    condition = alltrue([
      for value in values(var.workflow_refs) :
      startswith(value, "${var.repository_full_name}/.github/workflows/") &&
      endswith(value, "@${var.branch_ref}") &&
      can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/.github/workflows/[A-Za-z0-9_.-]+@refs/heads/[A-Za-z0-9._/-]+$", value))
    ])
    error_message = "Every workflow_ref must name a workflow in this repository at branch_ref."
  }


  validation {
    condition = (
      var.workflow_refs.plan == "mindclade/bootstrap/.github/workflows/protected-apply.yml@refs/heads/main" &&
      var.workflow_refs.apply == "mindclade/bootstrap/.github/workflows/protected-apply.yml@refs/heads/main" &&
      var.workflow_refs.recovery == "mindclade/bootstrap/.github/workflows/recovery-verification.yml@refs/heads/main"
    )
    error_message = "Bootstrap execution identities must bind only their exact canonical protected workflows."
  }
}

variable "github_config" {
  description = "Source-complete, activation-gated GitHub governance identities."
  type = object({
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

  validation {
    condition = (
      var.github_config.activation_enabled == false &&
      var.github_config.pool_id == "github-config" &&
      var.github_config.issuer_uri == "https://token.actions.githubusercontent.com" &&
      var.github_config.repository_owner_id == "316676129" &&
      var.github_config.repository_id == "1350986053" &&
      var.github_config.immutable_repository == "mindclade@316676129/github-config@1350986053" &&
      var.github_config.repository_full_name == "mindclade/github-config" &&
      var.github_config.branch_ref == "refs/heads/main" &&
      toset(keys(var.github_config.identities)) == toset(["plan", "apply"]) &&
      var.github_config.identities.plan.provider_id == "github-config-plan" &&
      var.github_config.identities.plan.service_account_id == "github-config-plan" &&
      var.github_config.identities.apply.provider_id == "github-config-apply" &&
      var.github_config.identities.apply.service_account_id == "github-config-apply"
    )
    error_message = "GitHub-config identities must remain source-complete, disabled, and bound to the exact immutable repository and role-separated IDs."
  }

  validation {
    condition = (
      jsonencode(var.github_config.identities.plan.subjects) == jsonencode([
        {
          id            = "github-config-drift-plan"
          workflow_ref  = "mindclade/github-config/.github/workflows/drift-detection.yml@refs/heads/main"
          context_type  = "ref"
          context_value = "refs/heads/main"
          audience      = "sts.googleapis.com"
        },
        {
          id            = "github-config-protected-plan"
          workflow_ref  = "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main"
          context_type  = "environment"
          context_value = "trusted-build"
          audience      = "sts.googleapis.com"
        },
      ]) &&
      jsonencode(var.github_config.identities.apply.subjects) == jsonencode([
        {
          id            = "github-config-protected-apply"
          workflow_ref  = "mindclade/github-config/.github/workflows/protected-apply.yml@refs/heads/main"
          context_type  = "environment"
          context_value = "infrastructure-apply"
          audience      = "sts.googleapis.com"
        },
      ])
    )
    error_message = "GitHub-config provider subjects must equal the exact drift, protected-plan, and protected-apply custom-subject contracts."
  }
}

variable "ci_evidence" {
  description = "Source-gated, dedicated GitHub trust boundary for immutable CI-evidence archival and recovery verification."
  type = object({
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

  validation {
    condition     = var.ci_evidence.pool_id == "github-ci-evidence"
    error_message = "CI evidence must use the dedicated github-ci-evidence workload identity pool."
  }

  validation {
    condition     = var.ci_evidence.repository_owner_id == "316676129"
    error_message = "CI evidence must bind Mindclade's immutable GitHub organization ID."
  }

  validation {
    condition = var.ci_evidence.repository_ids == tomap({
      bootstrap           = "1350991612"
      dot-github          = "1350980188"
      github-config       = "1350986053"
      gitops              = "1350991963"
      infrastructure-live = "1350992171"
      mindclade           = "1351193819"
    })
    error_message = "CI evidence writer repository IDs must equal the exact six-repository Mindclade estate."
  }

  validation {
    condition = (
      var.ci_evidence.writer.provider_id == "writer" &&
      var.ci_evidence.verifier.provider_id == "verifier" &&
      var.ci_evidence.writer.service_account_id == "ci-evidence-writer" &&
      var.ci_evidence.verifier.service_account_id == "ci-evidence-verifier" &&
      var.ci_evidence.writer.provider_id != var.ci_evidence.verifier.provider_id &&
      var.ci_evidence.writer.service_account_id != var.ci_evidence.verifier.service_account_id
    )
    error_message = "CI evidence writer and verifier providers and service accounts must remain distinct and canonical."
  }

  validation {
    condition = (
      can(regex("^mindclade/\\.github/\\.github/workflows/reusable-required-check\\.yml@[0-9a-f]{40}$", var.ci_evidence.writer.job_workflow_ref)) &&
      var.ci_evidence.verifier.repository_id == var.ci_evidence.repository_ids["infrastructure-live"] &&
      var.ci_evidence.verifier.workflow_ref == "mindclade/infrastructure-live/.github/workflows/disaster-recovery.yml@refs/heads/main" &&
      can(regex("^[0-9a-f]{40}$", var.ci_evidence.verifier.workflow_sha)) &&
      var.ci_evidence.verifier.environment == "infrastructure-apply"
    )
    error_message = "CI evidence workflows must bind the exact central reusable workflow and recovery workflow at immutable commits."
  }

}

variable "infrastructure_live" {
  description = "Exact environment/role-separated GitHub trust handoff for infrastructure-live."
  type = object({
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

  validation {
    condition = (
      var.infrastructure_live.pool_id == "infrastructure-live" &&
      var.infrastructure_live.issuer_uri == "https://token.actions.githubusercontent.com" &&
      var.infrastructure_live.repository_owner_id == "316676129" &&
      var.infrastructure_live.repository_id == "1350992171" &&
      var.infrastructure_live.immutable_repository == "mindclade@316676129/infrastructure-live@1350992171" &&
      var.infrastructure_live.repository_full_name == "mindclade/infrastructure-live" &&
      var.infrastructure_live.branch_ref == "refs/heads/main" &&
      var.infrastructure_live.workflow_ref == "mindclade/infrastructure-live/.github/workflows/protected-apply.yml@refs/heads/main"
    )
    error_message = "Infrastructure-live federation must bind the exact immutable repository, main workflow, pool, and GitHub issuer."
  }

  validation {
    condition = (
      var.infrastructure_live.drift.activation_enabled == false &&
      var.infrastructure_live.drift.subject_id == "infrastructure-drift-plan" &&
      var.infrastructure_live.drift.provider_id == "infrastructure-plan" &&
      var.infrastructure_live.drift.service_account_id == "infrastructure-plan" &&
      var.infrastructure_live.drift.workflow_ref == "mindclade/infrastructure-live/.github/workflows/drift-detection.yml@refs/heads/main" &&
      var.infrastructure_live.drift.environment == "trusted-build" &&
      var.infrastructure_live.drift.audience == "sts.googleapis.com"
    )
    error_message = "Infrastructure drift identity must remain source-complete, disabled, and bound to its exact workflow, account, context, and audience."
  }

  validation {
    condition = toset(keys(var.infrastructure_live.identities)) == toset([
      "development-plan", "development-apply",
      "staging-plan", "staging-apply",
      "production-plan", "production-apply",
      "restricted-plan", "restricted-apply",
      ]) && alltrue([
      for key, identity in var.infrastructure_live.identities :
      identity.provider_id == key &&
      identity.service_account_id == key &&
      identity.environment == (endswith(key, "-plan") ? "trusted-build" : "infrastructure-apply") &&
      identity.audience == "https://github.mindclade.io/oidc/infrastructure-live/${split("-", key)[0]}/${split("-", key)[1]}"
    ]) && length(distinct([for identity in values(var.infrastructure_live.identities) : identity.audience])) == 8
    error_message = "Infrastructure-live must expose exactly the eight unique environment/role providers, accounts, environments, and audiences."
  }
}
