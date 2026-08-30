variable "organization_id" {
  description = "Numeric organization ID that owns the workforce pool."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.organization_id))
    error_message = "organization_id must contain only decimal digits."
  }
}

variable "pool_id" {
  description = "Globally unique workforce pool ID."
  type        = string
}

variable "provider_id" {
  description = "OIDC workforce provider ID."
  type        = string
}

variable "issuer_uri" {
  description = "Exact HTTPS issuer URI of the enterprise identity provider."
  type        = string

  validation {
    condition     = startswith(var.issuer_uri, "https://")
    error_message = "issuer_uri must use HTTPS."
  }
}

variable "client_id" {
  description = "OIDC client ID; this is an identifier, not a credential."
  type        = string
}

variable "administrator_group" {
  description = "Exact external IdP group claim designated for workforce administration."
  type        = string

  validation {
    condition     = trimspace(var.administrator_group) != "" && !strcontains(var.administrator_group, "*")
    error_message = "administrator_group must be one explicit group claim."
  }
}

variable "client_secret" {
  description = "Required runtime-supplied OIDC secret written through the provider's write-only field."
  type        = string
  sensitive   = true
  ephemeral   = true
  nullable    = false

  validation {
    condition     = length(var.client_secret) >= 32 && !can(regex("[\\r\\n]", var.client_secret))
    error_message = "client_secret must be a high-entropy single-line value of at least 32 characters."
  }
}

variable "client_secret_version" {
  description = "Monotonic write-only secret revision; increment when the runtime secret changes."
  type        = number

  validation {
    condition     = var.client_secret_version >= 1 && floor(var.client_secret_version) == var.client_secret_version
    error_message = "client_secret_version must be a positive integer."
  }
}

variable "attribute_mapping" {
  description = "Explicit OIDC claim mappings; must map subject, user, and groups."
  type        = map(string)

  validation {
    condition = alltrue([
      contains(keys(var.attribute_mapping), "google.subject"),
      contains(keys(var.attribute_mapping), "google.display_name"),
      contains(keys(var.attribute_mapping), "google.groups"),
    ])
    error_message = "attribute_mapping must include google.subject, google.display_name, and google.groups."
  }
}

variable "attribute_condition" {
  description = "Fail-closed CEL restriction applied to all workforce assertions."
  type        = string

  validation {
    condition     = trimspace(var.attribute_condition) != "" && trimspace(var.attribute_condition) != "true"
    error_message = "attribute_condition must be an explicit restriction, not an unconditional expression."
  }
}

variable "additional_scopes" {
  description = "Additional OIDC scopes required for mapped group claims."
  type        = set(string)
  default     = ["groups"]
}
