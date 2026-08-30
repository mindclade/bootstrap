variable "recovery" {
  description = "Resolved, non-secret recovery-plane configuration compiled from the versioned manifests."
  type = object({
    project_id                         = string
    location                           = string
    key_ring_name                      = string
    export_key_name                    = string
    export_bucket_name                 = string
    evidence_bucket_name               = string
    exporter_principal                 = string
    recovery_principal                 = string
    plan_principal                     = string
    minimum_retained_state_generations = number
    source_state_backends = map(object({
      project_id = string
      bucket     = string
      prefix     = string
    }))
    restore_manifest_digest = string
    public_trust_metadata = object({
      schema_version                = number
      manifest_digests              = map(string)
      signing_key_versions          = map(string)
      signing_public_key_pem_sha256 = map(string)
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
    labels = optional(map(string), {})
  })

  validation {
    condition     = var.recovery.export_bucket_name != var.recovery.evidence_bucket_name
    error_message = "Recovery export and evidence buckets must be distinct."
  }

  validation {
    condition     = var.recovery.export_key_name != "recovery-evidence"
    error_message = "Recovery export and evidence KMS key names must be distinct."
  }

  validation {
    condition = try(length(distinct(concat(
      [var.recovery.export_bucket_name, var.recovery.evidence_bucket_name],
      flatten([
        for backend in values(var.recovery.public_trust_metadata.state_backends) : [
          backend.bucket,
          backend.replica_bucket,
        ]
      ]),
    ))) == 6, false)
    error_message = "Recovery export, evidence, primary-state, and replica-state buckets must all be distinct."
  }
}

module "recovery_exports" {
  source = "../../modules/recovery-exports"

  project_id                         = var.recovery.project_id
  location                           = var.recovery.location
  key_ring_name                      = var.recovery.key_ring_name
  export_key_name                    = var.recovery.export_key_name
  export_bucket_name                 = var.recovery.export_bucket_name
  evidence_bucket_name               = var.recovery.evidence_bucket_name
  exporter_principal                 = var.recovery.exporter_principal
  recovery_principal                 = var.recovery.recovery_principal
  plan_principal                     = var.recovery.plan_principal
  minimum_retained_state_generations = var.recovery.minimum_retained_state_generations
  source_state_backends              = var.recovery.source_state_backends
  restore_manifest_digest            = var.recovery.restore_manifest_digest
  public_trust_metadata              = var.recovery.public_trust_metadata
  labels                             = var.recovery.labels
}
