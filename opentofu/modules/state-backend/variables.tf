variable "project_id" {
  description = "Pre-created project ID for the primary state bucket and CMEK."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid Google Cloud project ID."
  }
}

variable "replica_project_id" {
  description = "Pre-created, independently administered project ID for the replica bucket and CMEK."
  type        = string

  validation {
    condition     = var.replica_project_id != var.project_id
    error_message = "Primary and replica state resources must use distinct projects."
  }

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.replica_project_id))
    error_message = "replica_project_id must be a valid Google Cloud project ID."
  }
}

variable "backend_prefix" {
  description = "Remote-state object prefix used by the corresponding live root."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9/_-]*$", var.backend_prefix)) && !endswith(var.backend_prefix, "/")
    error_message = "backend_prefix must be a relative, normalized object prefix."
  }
}

variable "bucket_name" {
  description = "Globally unique name of the primary state bucket."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", var.bucket_name)) && !startswith(var.bucket_name, "goog") && !strcontains(var.bucket_name, "google")
    error_message = "bucket_name must be a valid non-Google-reserved Cloud Storage bucket name."
  }
}

variable "replica_bucket_name" {
  description = "Globally unique name of the independently encrypted replica bucket."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", var.replica_bucket_name)) && !startswith(var.replica_bucket_name, "goog") && !strcontains(var.replica_bucket_name, "google")
    error_message = "replica_bucket_name must be a valid non-Google-reserved Cloud Storage bucket name."
  }

  validation {
    condition     = var.replica_bucket_name != var.bucket_name
    error_message = "Primary and replica buckets must have distinct names."
  }
}

variable "key_name" {
  description = "Resolved short HSM CMEK name for primary state."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,63}$", var.key_name))
    error_message = "key_name must be a short Cloud KMS key ID."
  }
}

variable "replica_key_name" {
  description = "Resolved short HSM CMEK name for replica state."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,63}$", var.replica_key_name))
    error_message = "replica_key_name must be a short Cloud KMS key ID."
  }
}

variable "location" {
  description = "Primary state and KMS region."
  type        = string
}

variable "replica_location" {
  description = "Recovery state and KMS region."
  type        = string

  validation {
    condition     = var.replica_location != var.location
    error_message = "replica_location must differ from location."
  }
}

variable "plan_principal" {
  description = "IAM member used only for reviewed state reads and backend locking during plans."
  type        = string

  validation {
    condition     = can(regex("^serviceAccount:bootstrap-plan@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.plan_principal))
    error_message = "plan_principal must be the canonical bootstrap-plan service account."
  }
}

variable "apply_principal" {
  description = "IAM member used only for protected root-trust applies or independently administered recovery-plane writes."
  type        = string

  validation {
    condition = (
      var.backend_prefix == "root-trust" &&
      can(regex("^serviceAccount:bootstrap-apply@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.apply_principal))
      ) || (
      var.backend_prefix == "recovery-plane" &&
      can(regex("^group:[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.apply_principal))
    )
    error_message = "apply_principal must be the canonical bootstrap-apply service account for root-trust or one explicit recovery-administrator group for recovery-plane."
  }
}

variable "recovery_principal" {
  description = "IAM member used only for read-only recovery verification."
  type        = string

  validation {
    condition = length(distinct([
      var.plan_principal,
      var.apply_principal,
      var.recovery_principal,
    ])) == 3
    error_message = "Plan, apply, and recovery principals must be distinct."
  }

  validation {
    condition     = can(regex("^serviceAccount:bootstrap-recovery@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.recovery_principal))
    error_message = "recovery_principal must be the canonical bootstrap-recovery service account."
  }
}

variable "labels" {
  description = "Non-sensitive labels applied to protected resources."
  type        = map(string)
  default     = {}
}
