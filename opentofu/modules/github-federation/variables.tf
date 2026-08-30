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
}

variable "repository_id" {
  description = "Immutable numeric GitHub repository ID."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.repository_id))
    error_message = "repository_id must be GitHub's immutable numeric ID."
  }
}

variable "repository_owner_id" {
  description = "Immutable numeric GitHub repository-owner ID."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.repository_owner_id))
    error_message = "repository_owner_id must be GitHub's immutable numeric ID."
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
    condition     = length(distinct(values(var.audiences))) == 3 && alltrue([for value in values(var.audiences) : trimspace(value) != ""])
    error_message = "Plan, apply, and recovery audiences must be non-empty and distinct."
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
}

variable "ci_evidence" {
  description = "Source-gated, dedicated GitHub trust boundary for immutable CI-evidence archival and recovery verification."
  type = object({
    activation_enabled    = bool
    pool_id               = string
    repository_owner_id   = string
    repository_ids        = map(string)
    writer = object({
      provider_id       = string
      service_account_id = string
      audience          = string
      job_workflow_ref  = string
    })
    verifier = object({
      provider_id        = string
      service_account_id = string
      audience           = string
      repository_id      = string
      workflow_ref       = string
      workflow_sha       = string
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
    condition = var.ci_evidence.repository_ids == {
      bootstrap                     = "1350991612"
      dot-github                    = "1350980188"
      github-config                 = "1350986053"
      gitops                        = "1350991963"
      infrastructure-live           = "1350992171"
      mindclade-internal-monorepo   = "1350990078"
    }
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
      can(regex("^[0-9a-f]{40}$", var.ci_evidence.verifier.workflow_sha))
    )
    error_message = "CI evidence workflows must bind the exact central reusable workflow and recovery workflow at immutable commits."
  }

  validation {
    condition = (
      var.ci_evidence.writer.audience != var.ci_evidence.verifier.audience &&
      alltrue([
        for audience in [var.ci_evidence.writer.audience, var.ci_evidence.verifier.audience] :
        startswith(audience, "https://") || startswith(audience, "//iam.googleapis.com/")
      ])
    )
    error_message = "CI evidence audiences must be distinct explicit HTTPS or canonical IAM audiences."
  }
}
