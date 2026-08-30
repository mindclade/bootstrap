output "entitlements" {
  description = "Canonical PAM entitlement names keyed by logical ID."
  value       = { for key, entitlement in google_privileged_access_manager_entitlement.break_glass : key => entitlement.name }
}

output "maximum_duration_seconds" {
  description = "Maximum emergency grant duration enforced by every entitlement."
  value       = 7200
}

output "required_approvals" {
  description = "Number of serial, distinct human approvals required."
  value       = 2
}
