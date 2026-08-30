variable "project_id" {
  description = "Pre-created recovery project ID."
  type        = string
}

variable "location" {
  description = "Independent recovery region."
  type        = string
}

variable "key_ring_name" {
  description = "Recovery export key-ring name."
  type        = string
}

variable "export_key_name" {
  description = "Resolved short HSM CMEK name for recoverable state exports."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,63}$", var.export_key_name))
    error_message = "export_key_name must be a short Cloud KMS key ID."
  }

  validation {
    condition     = var.export_key_name != "recovery-evidence"
    error_message = "export_key_name must be distinct from the fixed recovery-evidence key."
  }
}

variable "export_bucket_name" {
  description = "Bucket for recoverable state-generation exports."
  type        = string
}

variable "evidence_bucket_name" {
  description = "Bucket for public trust metadata and recovery evidence."
  type        = string
}

variable "exporter_principal" {
  description = "IAM member allowed only to create recovery exports."
  type        = string

  validation {
    condition     = can(regex("^serviceAccount:bootstrap-apply@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.exporter_principal))
    error_message = "exporter_principal must be the canonical bootstrap-apply service account."
  }
}

variable "recovery_principal" {
  description = "Distinct IAM member allowed only to verify recovery exports."
  type        = string

  validation {
    condition     = var.recovery_principal != var.exporter_principal
    error_message = "Exporter and recovery-verifier principals must be distinct."
  }

  validation {
    condition     = can(regex("^serviceAccount:bootstrap-recovery@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.recovery_principal))
    error_message = "recovery_principal must be the canonical bootstrap-recovery service account."
  }
}

variable "plan_principal" {
  description = "Distinct plan identity granted only the metadata and object reads required to refresh recovery exports."
  type        = string

  validation {
    condition = !contains([
      var.exporter_principal,
      var.recovery_principal,
    ], var.plan_principal)
    error_message = "Plan, exporter, and recovery-verifier principals must be distinct."
  }

  validation {
    condition     = can(regex("^serviceAccount:bootstrap-plan@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.plan_principal))
    error_message = "plan_principal must be the canonical bootstrap-plan service account."
  }
}

variable "source_state_backends" {
  description = "Exact primary backend coordinates used for continuous default-workspace state export."
  type = map(object({
    project_id = string
    bucket     = string
    prefix     = string
  }))

  validation {
    condition = length(var.source_state_backends) == 2 && alltrue([
      for name in ["root-trust", "recovery-plane"] : contains(keys(var.source_state_backends), name)
    ])
    error_message = "source_state_backends must contain exactly root-trust and recovery-plane."
  }

  validation {
    condition = alltrue([
      for backend in values(var.source_state_backends) :
      can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", backend.project_id))
    ]) && length(distinct([for backend in values(var.source_state_backends) : backend.project_id])) == 2
    error_message = "Source state backends must use two distinct valid Google Cloud project IDs."
  }

  validation {
    condition = alltrue([
      for backend in values(var.source_state_backends) :
      can(regex("^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", backend.bucket)) &&
      !startswith(backend.bucket, "goog") &&
      !strcontains(backend.bucket, "google")
    ]) && length(distinct([for backend in values(var.source_state_backends) : backend.bucket])) == 2
    error_message = "Source state backends must use two distinct valid Cloud Storage bucket names."
  }

  validation {
    condition = alltrue([
      for name, backend in var.source_state_backends : backend.prefix == name
    ])
    error_message = "Each source state prefix must exactly equal its root-trust or recovery-plane logical ID."
  }

  validation {
    condition = try(
      var.source_state_backends["recovery-plane"].project_id == var.project_id &&
      var.source_state_backends["root-trust"].project_id != var.project_id,
      false,
    )
    error_message = "The recovery-plane state must be in the recovery project and root-trust must be independently isolated."
  }
}

variable "minimum_retained_state_generations" {
  description = "Manifest-required minimum number of recoverable versions; the destination retains all generations."
  type        = number

  validation {
    condition     = var.minimum_retained_state_generations >= 3 && floor(var.minimum_retained_state_generations) == var.minimum_retained_state_generations
    error_message = "minimum_retained_state_generations must be an integer of at least three."
  }
}

variable "restore_manifest_digest" {
  description = "Digest of the reviewed restore manifest."
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.restore_manifest_digest))
    error_message = "restore_manifest_digest must be a lowercase sha256 digest."
  }
}

variable "public_trust_metadata" {
  description = "Strictly allowlisted public trust references; arbitrary JSON and credential-shaped fields are impossible."
  type = object({
    schema_version       = number
    manifest_digests     = map(string)
    signing_key_versions = map(string)
    signing_windows = map(object({
      active_version_ref      = string
      activation_window_start = string
      rotation_deadline       = string
    }))
    federation_providers = map(string)
    federation_audiences = map(string)
    state_backends = map(object({
      bucket         = string
      prefix         = string
      replica_bucket = string
    }))
  })

  validation {
    condition     = var.public_trust_metadata.schema_version == 1
    error_message = "public_trust_metadata.schema_version must be 1."
  }

  validation {
    condition     = alltrue([for digest in values(var.public_trust_metadata.manifest_digests) : can(regex("^sha256:[0-9a-f]{64}$", digest))])
    error_message = "Every public manifest digest must be a lowercase sha256 digest."
  }

  validation {
    condition = alltrue([
      for name in values(var.public_trust_metadata.signing_key_versions) :
      can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+/cryptoKeyVersions/[0-9]+$", name))
    ])
    error_message = "Signing references must be canonical public CryptoKeyVersion names."
  }

  validation {
    condition = length(var.public_trust_metadata.signing_windows) == 3 && alltrue([
      for name in ["audit-anchor", "bootstrap-handoff", "recovery-evidence"] :
      contains(keys(var.public_trust_metadata.signing_windows), name)
      ]) && alltrue([
      for window in values(var.public_trust_metadata.signing_windows) :
      can(regex("^v[0-9]{8}$", window.active_version_ref)) &&
      try(formatdate("YYYYMMDD", window.activation_window_start) == substr(window.active_version_ref, 1, 8), false) &&
      try(timecmp(timeadd(window.activation_window_start, "2160h"), window.rotation_deadline) == 0, false)
    ])
    error_message = "Signing windows must declare the exact three active vYYYYMMDD versions and canonical 90-day UTC intervals."
  }

  validation {
    condition = alltrue([
      for name in values(var.public_trust_metadata.federation_providers) :
      can(regex("^projects/[0-9]+/locations/global/workloadIdentityPools/[a-z0-9-]+/providers/[a-z0-9-]+$", name))
    ])
    error_message = "Federation providers must be canonical project-number-based resource names."
  }

  validation {
    condition = alltrue([
      for audience in values(var.public_trust_metadata.federation_audiences) :
      startswith(audience, "https://") || startswith(audience, "//iam.googleapis.com/")
    ])
    error_message = "Federation audiences must be HTTPS or canonical IAM audiences."
  }

  validation {
    condition = alltrue([
      for backend in values(var.public_trust_metadata.state_backends) :
      can(regex("^[a-z0-9][a-z0-9._-]{2,62}$", backend.bucket)) &&
      can(regex("^[a-z0-9][a-z0-9._-]{2,62}$", backend.replica_bucket)) &&
      backend.bucket != backend.replica_bucket &&
      can(regex("^[a-z0-9][a-z0-9/_-]*$", backend.prefix))
    ])
    error_message = "State backend metadata must contain normalized, distinct bucket names and prefixes."
  }

  validation {
    condition = try(
      length(var.public_trust_metadata.state_backends) == 2 &&
      alltrue([
        for name in ["root-trust", "recovery-plane"] : contains(keys(var.public_trust_metadata.state_backends), name)
      ]) &&
      alltrue([
        for name, backend in var.public_trust_metadata.state_backends :
        backend.bucket == var.source_state_backends[name].bucket &&
        backend.prefix == var.source_state_backends[name].prefix
      ]),
      false,
    )
    error_message = "Public state metadata must exactly match the two non-public source backend bucket/prefix coordinates."
  }

  validation {
    condition = try(length(distinct(concat(
      [var.export_bucket_name, var.evidence_bucket_name],
      flatten([
        for backend in values(var.public_trust_metadata.state_backends) : [
          backend.bucket,
          backend.replica_bucket,
        ]
      ]),
    ))) == 6, false)
    error_message = "Recovery export, evidence, primary-state, and replica-state buckets must all be distinct."
  }
}

variable "labels" {
  description = "Non-sensitive labels applied to recovery resources."
  type        = map(string)
  default     = {}
}
