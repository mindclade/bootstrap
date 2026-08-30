variable "project_id" {
  description = "Identity project that owns the GitOps federation resources."
  type        = string
}

variable "service_account_project_id" {
  description = "Manifest-selected recovery project that owns the GitOps service account."
  type        = string
}

variable "pool_id" {
  description = "GitOps workload identity pool ID."
  type        = string
}

variable "provider_id" {
  description = "GitOps OIDC provider ID."
  type        = string
}

variable "service_account_id" {
  description = "Keyless GitOps service-account ID."
  type        = string
}

variable "issuer_uri" {
  description = "Exact HTTPS issuer URI for the GitOps controller."
  type        = string

  validation {
    condition     = startswith(var.issuer_uri, "https://")
    error_message = "issuer_uri must use HTTPS."
  }
}

variable "audience" {
  description = "Single explicitly allowed GitOps OIDC audience."
  type        = string
}

variable "subject" {
  description = "Exact immutable subject authorized to exchange GitOps tokens."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.:/@-]+$", var.subject))
    error_message = "subject contains unsupported claim characters."
  }
}

variable "repository" {
  description = "Exact GitOps repository claim."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.:/@-]+$", var.repository))
    error_message = "repository contains unsupported claim characters."
  }
}

variable "ref" {
  description = "Exact protected Git ref claim."
  type        = string

  validation {
    condition     = can(regex("^refs/heads/[A-Za-z0-9._/-]+$", var.ref))
    error_message = "GitOps ref must be a fully qualified branch ref."
  }
}
