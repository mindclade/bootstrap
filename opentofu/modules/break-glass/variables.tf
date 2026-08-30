variable "requester_principals" {
  description = "Named human principals eligible to request emergency access."
  type        = set(string)

  validation {
    condition     = length(var.requester_principals) > 0 && alltrue([for principal in var.requester_principals : can(regex("^user:[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", principal))])
    error_message = "Break-glass requesters must be explicit user: principals."
  }
}

variable "approver_principals" {
  description = "Named security principals that approve emergency access."
  type        = set(string)

  validation {
    condition     = length(var.approver_principals) >= 2 && alltrue([for principal in var.approver_principals : can(regex("^user:[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", principal))])
    error_message = "At least two explicit user: approver principals are required."
  }
}

variable "notification_recipients" {
  description = "Independent security mailbox recipients for all break-glass events."
  type        = set(string)

  validation {
    condition     = length(var.notification_recipients) > 0 && alltrue([for email in var.notification_recipients : can(regex("^[^@[:space:]]+@[^@[:space:]]+$", email))])
    error_message = "notification_recipients must contain valid email addresses."
  }
}

variable "entitlements" {
  description = "Emergency entitlements keyed by stable logical ID."
  type = map(object({
    target_project_id = string
    roles             = set(string)
  }))

  validation {
    condition = alltrue(flatten([
      for entitlement in values(var.entitlements) : [
        for role in entitlement.roles :
        startswith(role, "roles/") && !contains(["owner", "editor", "viewer"], trimprefix(role, "roles/"))
      ]
    ]))
    error_message = "Entitlement roles must be predefined roles and must never include Owner, Editor, or Viewer."
  }
}
