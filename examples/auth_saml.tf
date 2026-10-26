# SAML Authentication
# Enterprise SAML (basic and custom settings) and SaaS SAML.

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.1.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# --- Enterprise SAML with minimal settings ---
# For enterprise apps: set app_auth="SAML2.0" (or "saml") in advanced_settings.
# The saml_settings block is optional; if omitted, the API uses defaults.
resource "eaa_application" "saml_basic" {
  name            = "SAML Basic App"
  description     = "Enterprise app with default SAML settings"
  host            = "saml-basic.example.com"
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
    }
  }

  advanced_settings = {
    app_auth = "SAML2.0"
  }

  saml_settings {
    idp {
      self_signed = true
    }
  }
}

# --- Enterprise SAML with full custom SP, IDP, subject, and attribute mapping ---
resource "eaa_application" "saml_custom" {
  name            = "SAML Custom App"
  description     = "Enterprise app with fully customized SAML configuration"
  host            = "saml-custom.example.com"
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
    }
  }

  advanced_settings = {
    app_auth = "SAML2.0"
  }

  saml_settings {
    sp {
      entity_id  = "https://saml-custom.example.com/sp"
      acs_url    = "https://saml-custom.example.com/acs"
      slo_url    = "https://saml-custom.example.com/slo"
      dst_url    = "https://saml-custom.example.com/destination"
      resp_bind  = "post"
      token_life = 3600
      encr_algo  = "aes256-cbc"
    }

    idp {
      entity_id   = "https://idp.example.com/metadata"
      sign_algo   = "SHA256"
      sign_cert   = "<YOUR_SIGNING_CERTIFICATE>"
      sign_key    = "<YOUR_PRIVATE_KEY>"
      self_signed = true
    }

    subject {
      fmt = "email"
      src = "user.email"
    }

    attrmap {
      name  = "name"
      fname = "name"
      fmt   = "basic"
      src   = "user.email"
    }
  }
}

# --- SaaS SAML ---
# SaaS apps use the top-level "protocol" field instead of advanced_settings.app_auth.
resource "eaa_application" "saas_saml" {
  name        = "SaaS SAML App"
  description = "SaaS application with SAML authentication"
  host        = "saas-saml.example.com"
  app_profile = "http"
  app_type    = "saas"
  protocol    = "SAML2.0"

  saml_settings {
    sp {
      entity_id  = "https://saas-saml.example.com/sp"
      acs_url    = "https://saas-saml.example.com/acs"
      slo_url    = "https://saas-saml.example.com/slo"
      dst_url    = "https://saas-saml.example.com/dashboard"
      resp_bind  = "post"
      token_life = 3600
      encr_algo  = "aes256-cbc"
    }

    idp {
      entity_id = "https://idp.example.com/metadata"
      sign_algo = "SHA256"
    }

    subject {
      fmt = "email"
      src = "user.email"
    }

    attrmap {
      name  = "name"
      fname = "name"
      fmt   = "basic"
      src   = "user.email"
    }
  }
}
