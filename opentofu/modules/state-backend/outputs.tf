output "project_ids" {
  description = "Independent primary and replica project IDs."
  value = {
    primary = var.project_id
    replica = var.replica_project_id
  }
}

output "backend" {
  description = "Non-secret backend coordinates for the live root."
  value = {
    bucket = google_storage_bucket.state["primary"].name
    prefix = var.backend_prefix
  }
}

output "replica_bucket" {
  description = "Protected recovery replica bucket name."
  value       = google_storage_bucket.state["replica"].name
}

output "kms_keys" {
  description = "CMEK resource names for primary and replica state."
  value = {
    primary = google_kms_crypto_key.state.id
    replica = google_kms_crypto_key.replica.id
  }
}
