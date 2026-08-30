terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_iam_workforce_pool" "workforce" {
  workforce_pool_id = var.pool_id
  parent            = "organizations/${var.organization_id}"
  location          = "global"
  display_name      = "Mindclade workforce"
  description       = "Federated human authentication anchor; resource authorization is granted separately"
  deletion_policy   = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_iam_workforce_pool_provider" "oidc" {
  workforce_pool_id      = google_iam_workforce_pool.workforce.workforce_pool_id
  location               = google_iam_workforce_pool.workforce.location
  provider_id            = var.provider_id
  display_name           = "Mindclade workforce OIDC"
  description            = "Enterprise workforce identity provider"
  attribute_mapping      = var.attribute_mapping
  attribute_condition    = var.attribute_condition
  detailed_audit_logging = true
  deletion_policy        = "PREVENT"

  oidc {
    issuer_uri = var.issuer_uri
    client_id  = var.client_id

    client_secret {
      value {
        plain_text_wo         = var.client_secret
        plain_text_wo_version = var.client_secret_version
      }
    }

    web_sso_config {
      response_type             = "CODE"
      assertion_claims_behavior = "MERGE_USER_INFO_OVER_ID_TOKEN_CLAIMS"
      additional_scopes         = sort(tolist(var.additional_scopes))
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}
