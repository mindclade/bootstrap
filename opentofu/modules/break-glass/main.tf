terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

locals {
  target_projects   = toset([for entitlement in values(var.entitlements) : entitlement.target_project_id])
  approvers         = sort(tolist(var.approver_principals))
  approver_midpoint = ceil(length(local.approvers) / 2)
  first_approvers   = slice(local.approvers, 0, local.approver_midpoint)
  second_approvers  = slice(local.approvers, local.approver_midpoint, length(local.approvers))
}

resource "google_project_service" "pam" {
  for_each = local.target_projects

  project            = each.value
  service            = "privilegedaccessmanager.googleapis.com"
  disable_on_destroy = false
  deletion_policy    = "PREVENT"
}

resource "google_privileged_access_manager_entitlement" "break_glass" {
  for_each = var.entitlements

  entitlement_id       = each.key
  location             = "global"
  parent               = "projects/${each.value.target_project_id}"
  max_request_duration = "7200s"
  deletion_policy      = "PREVENT"

  requester_justification_config {
    unstructured {}
  }

  eligible_users {
    principals = sort(tolist(var.requester_principals))
  }

  privileged_access {
    gcp_iam_access {
      resource      = "//cloudresourcemanager.googleapis.com/projects/${each.value.target_project_id}"
      resource_type = "cloudresourcemanager.googleapis.com/Project"

      dynamic "role_bindings" {
        for_each = each.value.roles

        content {
          role = role_bindings.value
        }
      }
    }
  }

  approval_workflow {
    manual_approvals {
      require_approver_justification = true

      steps {
        approvals_needed          = 1
        approver_email_recipients = sort([for principal in var.approver_principals : trimprefix(principal, "user:")])

        approvers {
          principals = local.first_approvers
        }
      }

      steps {
        approvals_needed          = 1
        approver_email_recipients = sort([for principal in var.approver_principals : trimprefix(principal, "user:")])

        approvers {
          principals = local.second_approvers
        }
      }
    }
  }

  additional_notification_targets {
    admin_email_recipients     = sort(tolist(var.notification_recipients))
    requester_email_recipients = sort(tolist(var.notification_recipients))
  }

  depends_on = [google_project_service.pam]

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = length(setintersection(var.requester_principals, var.approver_principals)) == 0
      error_message = "Break-glass requesters may not approve their own grants."
    }
  }
}
