variable "project_id" {
  description = "Identity project that owns the Buildkite federation resources."
  type        = string
}

variable "service_account_project_id" {
  description = "Manifest-selected project that owns the Buildkite service account."
  type        = string
}

variable "pool_id" {
  description = "Buildkite workload identity pool ID."
  type        = string
}

variable "provider_id" {
  description = "Buildkite OIDC provider ID."
  type        = string
}

variable "service_account_id" {
  description = "Keyless Buildkite service-account ID."
  type        = string
}

variable "issuer_uri" {
  description = "Exact HTTPS issuer URI used by Buildkite agents."
  type        = string
  default     = "https://agent.buildkite.com"

  validation {
    condition     = var.issuer_uri == "https://agent.buildkite.com"
    error_message = "Buildkite federation must use the canonical agent.buildkite.com issuer."
  }
}

variable "audience" {
  description = "Single explicitly allowed Buildkite OIDC audience."
  type        = string
}

variable "organization_slug" {
  description = "Exact Buildkite organization slug claim."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.organization_slug))
    error_message = "organization_slug contains unsupported claim characters."
  }
}

variable "pipeline_slug" {
  description = "Exact Buildkite pipeline slug claim."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.pipeline_slug))
    error_message = "pipeline_slug contains unsupported claim characters."
  }
}

variable "pipeline_id" {
  description = "Immutable Buildkite pipeline UUID claim."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.pipeline_id))
    error_message = "pipeline_id must be an immutable UUID."
  }
}

variable "build_branch" {
  description = "Exact protected Buildkite branch allowed to request the signing identity."
  type        = string

  validation {
    condition     = var.build_branch == "main"
    error_message = "Buildkite signing federation is restricted to the main branch."
  }
}

variable "step_key" {
  description = "Exact dedicated Buildkite step key allowed to request the signing identity."
  type        = string

  validation {
    condition     = var.step_key == "bootstrap-ring0-signing"
    error_message = "Buildkite signing federation requires the dedicated bootstrap-ring0-signing step."
  }
}
