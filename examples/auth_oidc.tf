# OpenID Connect Authentication
# Enterprise OIDC and SaaS OIDC.

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.0.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# --- Enterprise OIDC ---
# For enterprise apps: set app_auth="OpenID Connect 1.0" in advanced_settings.
# The oidc_settings block is optional. If omitted, the API uses its defaults.
resource "eaa_application" "oidc_enterprise" {
  name            = "OIDC Enterprise App"
  description     = "Enterprise app with OpenID Connect authentication"
  host            = "oidc-basic.example.com"
  app_profile     = "http"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"
  popregion       = "us-east-1"
  agents          = ["EAA_DC1_US1_Access_01"]

  servers {
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }

  auth_enabled = "true"

  app_authentication {
    app_idp = "employees-idp"

    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Engineering"
      }
      app_groups {
        name = "SQA"
      }
    }
  }

  advanced_settings = {
    app_auth = "OpenID Connect 1.0"
  }
}

# --- SaaS OIDC ---
# SaaS apps use the top-level "protocol" field instead of advanced_settings.app_auth.
resource "eaa_application" "saas_oidc" {
  name        = "SaaS OIDC App"
  description = "SaaS application with OpenID Connect authentication"
  host        = "saas-oidc.example.com"
  app_profile = "http"
  app_type    = "saas"
  protocol    = "OpenID Connect 1.0"
}
