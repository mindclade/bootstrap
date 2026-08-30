variable "organization_id" {
  description = "Numeric organization ID whose logs are aggregated."
  type        = string
}

variable "billing_account" {
  description = "Billing account associated with the audit project."
  type        = string
}

variable "project_id" {
  description = "Dedicated audit project ID."
  type        = string
}

variable "project_name" {
  description = "Human-readable audit project name."
  type        = string
}

variable "buckets" {
  description = "Logging buckets and their independently located CMEKs."
  type = map(object({
    project_id = string
    bucket_id  = string
    location   = string
    key_name   = string
  }))

  validation {
    condition     = length(var.buckets) == 2 && contains(keys(var.buckets), "primary") && contains(keys(var.buckets), "recovery")
    error_message = "Exactly the primary and recovery audit buckets are required."
  }
  validation {
    condition = alltrue([
      for bucket in values(var.buckets) :
      can(regex("^[A-Za-z0-9_-]{1,63}$", bucket.key_name)) &&
      can(regex("^[A-Za-z][A-Za-z0-9_.-]{0,99}$", bucket.bucket_id))
    ])
    error_message = "Audit bucket and KMS key IDs contain unsupported characters."
  }

  validation {
    condition = (
      var.buckets.primary.project_id != var.buckets.recovery.project_id &&
      var.buckets.primary.location != var.buckets.recovery.location
    )
    error_message = "Primary and recovery audit buckets must use independent projects and regions."
  }
}

variable "sinks" {
  description = "Organization sinks keyed by logical ID."
  type = map(object({
    bucket_id = string
    name      = string
    filter    = optional(string, "")
  }))

  validation {
    condition     = alltrue([for sink in values(var.sinks) : contains(keys(var.buckets), sink.bucket_id)])
    error_message = "Every audit sink must reference a declared bucket ID."
  }

  validation {
    condition     = alltrue([for sink in values(var.sinks) : can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$", sink.name))])
    error_message = "Audit sink names contain unsupported characters."
  }
}

variable "retention_days" {
  description = "Immutable log retention period."
  type        = number

  validation {
    condition     = var.retention_days >= 2555
    error_message = "Audit logs must be retained for at least seven years (2555 days)."
  }
}

variable "lock_after_qualification" {
  description = "Locks retention after qualification; changing back to false is not supported by Cloud Logging."
  type        = bool
}

variable "reader_principals" {
  description = "Narrow set of principals allowed to read audit evidence."
  type        = set(string)

  validation {
    condition = alltrue([
      for principal in var.reader_principals :
      can(regex("^group:[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", principal))
    ])
    error_message = "Audit readers must be explicit Google-group email principals."
  }
}

variable "administrator_principals" {
  description = "Principals allowed to administer logging configuration but not KMS keys."
  type        = set(string)

  validation {
    condition = alltrue([
      for principal in var.administrator_principals :
      can(regex("^((user|group):[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+|serviceAccount:[a-z][a-z0-9-]{1,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com)$", principal))
    ])
    error_message = "Audit administrators must be canonical user, group, or service-account principals."
  }
}

variable "plan_principal" {
  description = "Dedicated plan identity granted configuration metadata only, never log-content access."
  type        = string

  validation {
    condition     = can(regex("^serviceAccount:bootstrap-plan@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.plan_principal))
    error_message = "plan_principal must be the explicit bootstrap-plan service account."
  }
}

variable "labels" {
  description = "Non-sensitive labels applied to audit resources."
  type        = map(string)
  default     = {}
}
