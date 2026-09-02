variable "organization_id" {
  description = "Numeric organization ID that owns the signing project."
  type        = string
}

variable "billing_account" {
  description = "Billing account associated with the signing project."
  type        = string
}

variable "project_id" {
  description = "Dedicated signing project ID."
  type        = string
}

variable "project_name" {
  description = "Human-readable signing project name."
  type        = string
}

variable "location" {
  description = "Cloud KMS location for the HSM-backed signing root."
  type        = string
}

variable "key_ring_name" {
  description = "Signing key-ring name."
  type        = string
}

variable "administrator_principals" {
  description = "Principals that administer key metadata and versions but never sign."
  type        = set(string)

  validation {
    condition     = length(var.administrator_principals) >= 2
    error_message = "At least two signing-root administrators are required."
  }

  validation {
    condition = alltrue([
      for principal in var.administrator_principals :
      can(regex("^((user|group):[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+|serviceAccount:[a-z][a-z0-9-]{1,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com)$", principal))
    ])
    error_message = "Signing-root administrators must be canonical user, group, or service-account principals."
  }
}

variable "recovery_verifier_principal" {
  description = "Dedicated recovery workflow identity allowed to inspect only the active recovery-evidence key and version."
  type        = string

  validation {
    condition     = can(regex("^serviceAccount:bootstrap-recovery@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.recovery_verifier_principal))
    error_message = "recovery_verifier_principal must be the explicit bootstrap-recovery service account."
  }
}

variable "keys" {
  description = "Required signing roots and their narrowly scoped signer principals."
  type = map(object({
    signer_principals  = set(string)
    rotation_days      = number
    active_version_ref = string
    versions = map(object({
      activation_window_start = string
      rotation_deadline       = string
    }))
  }))

  validation {
    condition = length(var.keys) == 7 && length(setsubtract(toset(keys(var.keys)), toset([
      "audit-anchor",
      "bootstrap-handoff",
      "connected-observation-evidence",
      "github-config-plan-evidence",
      "infrastructure-export",
      "recovery-evidence",
      "supply-chain-provenance",
    ]))) == 0
    error_message = "keys must define exactly the six evidence roots plus the separate HSM P-256 supply-chain-provenance authority."
  }

  validation {
    condition     = alltrue([for key in values(var.keys) : length(key.signer_principals) > 0])
    error_message = "Every signing key requires at least one explicit signer principal."
  }

  validation {
    condition = alltrue(flatten([
      for key in values(var.keys) : [
        for principal in key.signer_principals :
        can(regex("^serviceAccount:[a-z][a-z0-9-]{1,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", principal))
      ]
    ]))
    error_message = "Signing-key signers must be canonical service-account principals."
  }

  validation {
    condition     = alltrue([for key in values(var.keys) : key.rotation_days == 90])
    error_message = "Every asymmetric signing key must declare the reviewed 90-day version-rotation cadence."
  }

  validation {
    condition = alltrue([
      for key in values(var.keys) :
      length(key.versions) > 0 &&
      can(regex("^v[0-9]{8}$", key.active_version_ref)) &&
      contains(keys(key.versions), key.active_version_ref) &&
      alltrue([
        for version_ref, version in key.versions :
        can(regex("^v[0-9]{8}$", version_ref)) &&
        endswith(version.activation_window_start, "T00:00:00Z") &&
        try(formatdate("YYYYMMDD", version.activation_window_start) == substr(version_ref, 1, 8), false) &&
        try(timecmp(timeadd(version.activation_window_start, "2160h"), version.rotation_deadline) == 0, false)
      ])
    ])
    error_message = "Every signing key requires source-declared vYYYYMMDD versions with canonical 90-day activation windows and one declared active version."
  }
}

variable "disabled_signing_keys" {
  description = "Source-complete signing keys whose IAM signer grants remain absent until connected qualification."
  type        = set(string)
  default     = []

  validation {
    condition = var.disabled_signing_keys == toset([
      "connected-observation-evidence",
      "infrastructure-export",
      "supply-chain-provenance",
    ])
    error_message = "Connected observation, infrastructure export, and supply-chain provenance signer IAM must remain disabled pending connected qualification."
  }
}

variable "nix_cache" {
  description = "Dedicated Nix Ed25519 signing-root contract; private material is never accepted through ordinary stateful inputs."
  type = object({
    state                     = string
    activation_enabled        = bool
    secret_id                 = string
    algorithm                 = string
    secret_storage            = string
    secret_version_write_only = optional(number)
    public_keys               = list(string)
    public_key_digest         = optional(string)
    accessor_principals       = set(string)
    required_reviewer_gates   = list(string)
    reviewer_evidence_digest  = optional(string)
    blockers                  = list(string)
  })

  validation {
    condition = (
      var.nix_cache.secret_id == "nix-cache-signing-key" &&
      var.nix_cache.algorithm == "ED25519" &&
      var.nix_cache.secret_storage == "SECRET_MANAGER_WRITE_ONLY" &&
      length(var.nix_cache.required_reviewer_gates) == 2 &&
      var.nix_cache.required_reviewer_gates[0] == "security" &&
      var.nix_cache.required_reviewer_gates[1] == "platform" &&
      (
        (
          var.nix_cache.state == "DISABLED" &&
          !var.nix_cache.activation_enabled &&
          var.nix_cache.secret_version_write_only == null &&
          length(var.nix_cache.public_keys) == 0 &&
          var.nix_cache.public_key_digest == null &&
          length(var.nix_cache.accessor_principals) == 0 &&
          var.nix_cache.reviewer_evidence_digest == null &&
          length(var.nix_cache.blockers) > 0
        ) ||
        (
          var.nix_cache.state == "ACTIVATED" &&
          var.nix_cache.activation_enabled &&
          var.nix_cache.secret_version_write_only != null &&
          var.nix_cache.secret_version_write_only > 0 &&
          length(var.nix_cache.public_keys) > 0 &&
          can(regex("^sha256:[0-9a-f]{64}$", var.nix_cache.public_key_digest)) &&
          length(var.nix_cache.accessor_principals) > 0 &&
          can(regex("^[0-9a-f]{64}$", var.nix_cache.reviewer_evidence_digest)) &&
          can(regex("[1-9a-f]", var.nix_cache.reviewer_evidence_digest)) &&
          length(var.nix_cache.blockers) == 0
        )
      )
    )
    error_message = "Nix cache signing remains fail closed until a public key, write-only Secret Manager version, explicit accessors, and reviewer evidence are source-bound."
  }
}

variable "nix_cache_signing_private_key" {
  description = "Ephemeral Nix Ed25519 private key used only by Secret Manager's write-only provider field."
  type        = string
  sensitive   = true
  ephemeral   = true
  default     = null
  nullable    = true
}

variable "labels" {
  description = "Non-sensitive labels applied to signing resources."
  type        = map(string)
  default     = {}
}
