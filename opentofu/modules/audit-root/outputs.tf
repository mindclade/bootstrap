output "project_id" {
  description = "Dedicated audit project ID."
  value       = google_project.audit.project_id
}

output "buckets" {
  description = "Logging bucket resource names keyed by logical ID."
  value       = { for key, bucket in google_logging_project_bucket_config.audit : key => bucket.id }
}

output "sinks" {
  description = "Organization sink resource names keyed by logical ID."
  value       = { for key, sink in google_logging_organization_sink.audit : key => sink.id }
}

output "kms_keys" {
  description = "Audit CMEK names keyed by bucket logical ID."
  value       = { for key, crypto_key in google_kms_crypto_key.audit : key => crypto_key.id }
}
