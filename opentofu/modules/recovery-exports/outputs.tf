output "buckets" {
  description = "Protected recovery bucket names keyed by purpose."
  value       = { for key, bucket in google_storage_bucket.recovery : key => bucket.name }
}

output "kms_keys" {
  description = "Independent recovery CMEK names keyed by purpose."
  value       = { for key, crypto_key in google_kms_crypto_key.recovery : key => crypto_key.id }
}

output "public_trust_metadata_object" {
  description = "Immutable-generation reference for public trust metadata."
  value = {
    name       = google_storage_bucket_object.public_trust_metadata.name
    generation = google_storage_bucket_object.public_trust_metadata.generation
    sha256     = "sha256:${sha256(local.public_trust_metadata_content)}"
  }
}

output "restore_inventory_object" {
  description = "Immutable-generation reference for the non-secret restore inventory."
  value = {
    name       = google_storage_bucket_object.restore_inventory.name
    generation = google_storage_bucket_object.restore_inventory.generation
    sha256     = "sha256:${sha256(local.restore_inventory_content)}"
  }
}

output "state_export_jobs" {
  description = "Continuous exact-object recovery export jobs and their non-secret verification coordinates."
  value = {
    for name, job in google_storage_transfer_job.state_export : name => {
      name               = job.name
      project_id         = local.state_exports[name].project_id
      status             = job.status
      service_account    = local.state_exports[name].service_account_email
      source_bucket      = local.state_exports[name].bucket
      source_object      = local.state_exports[name].object_name
      destination_bucket = google_storage_bucket.recovery["exports"].name
      destination_object = local.state_exports[name].object_name
    }
  }
}

output "minimum_retained_state_generations" {
  description = "Manifest-required minimum recoverable generations; the bucket has no generation-deleting lifecycle."
  value       = var.minimum_retained_state_generations
}
