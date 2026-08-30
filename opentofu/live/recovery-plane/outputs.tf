output "recovery_exports" {
  description = "Protected export/evidence destinations and their CMEKs."
  value = {
    buckets                            = module.recovery_exports.buckets
    kms_keys                           = module.recovery_exports.kms_keys
    minimum_retained_state_generations = module.recovery_exports.minimum_retained_state_generations
    transfer_jobs                      = module.recovery_exports.state_export_jobs
    objects = {
      public_trust_metadata = module.recovery_exports.public_trust_metadata_object
      restore_inventory     = module.recovery_exports.restore_inventory_object
    }
  }
}
