# WS-Federation Authentication
# Enterprise WS-Fed (basic and custom) and SaaS WS-Fed.

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

# --- Enterprise WS-Fed with minimal settings ---
# app_auth accepts "WS-Federation" or "wsfed" (both case-sensitive).
resource "eaa_application" "wsfed_basic" {
  name            = "WS-Fed Basic App"
  description     = "Enterprise app with default WS-Federation settings"
  host            = "wsfed-basic.example.com"
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
    app_auth = "WS-Federation"
  }

  wsfed_settings {
    idp {
      self_signed = true
    }
  }
}

# --- Enterprise WS-Fed with full custom settings ---
resource "eaa_application" "wsfed_custom" {
  name            = "WS-Fed Custom App"
  description     = "Enterprise app with fully customized WS-Federation"
  host            = "wsfed-custom.example.com"
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
    app_auth = "WS-Federation"
  }

  wsfed_settings {
    sp {
      entity_id  = "https://wsfed-custom.example.com"
      slo_url    = "https://wsfed-custom.example.com/wsfed/slo"
      dst_url    = "https://wsfed-custom.example.com/wsfed/dst"
      resp_bind  = "post"
      token_life = 7200
      encr_algo  = "aes128-cbc"
    }

    idp {
      entity_id   = "https://idp.example.com/wsfed/idp/sso"
      sign_algo   = "SHA1"
      sign_key    = ""
      self_signed = true
    }

    subject {
      fmt        = "persistent"
      custom_fmt = ""
      src        = "user.persistentId"
      val        = ""
      rule       = ""
    }

    attrmap {
      name       = "email"
      fmt        = "email"
      custom_fmt = ""
      val        = ""
      src        = "user.email"
      rule       = ""
    }

    attrmap {
      name       = "firstName"
      fmt        = "firstName"
      custom_fmt = ""
      val        = ""
      src        = "user.firstName"
      rule       = ""
    }

    attrmap {
      name       = "lastName"
      fmt        = "lastName"
      custom_fmt = ""
      val        = ""
      src        = "user.lastName"
      rule       = ""
    }
  }
}

# --- SaaS WS-Fed ---
# SaaS apps use the top-level "protocol" field instead of advanced_settings.app_auth.
resource "eaa_application" "saas_wsfed" {
  name        = "SaaS WS-Fed App"
  description = "SaaS application with WS-Federation authentication"
  host        = "saas-wsfed.example.com"
  app_profile = "http"
  app_type    = "saas"
  protocol    = "WS-Federation"

  wsfed_settings {
    sp {
      entity_id  = "https://saas-wsfed.example.com"
      slo_url    = "https://saas-wsfed.example.com/wsfed/slo"
      dst_url    = "https://saas-wsfed.example.com/wsfed/dst"
      resp_bind  = "post"
      token_life = 3600
      encr_algo  = "aes128-cbc"
    }

    idp {
      entity_id   = "https://idp.example.com/wsfed/idp/sso"
      sign_algo   = "SHA1"
      sign_key    = ""
      self_signed = true
    }

    subject {
      fmt        = "email"
      custom_fmt = ""
      src        = "user.email"
      val        = ""
      rule       = ""
    }

    attrmap {
      name       = "email"
      fmt        = "email"
      custom_fmt = ""
      val        = ""
      src        = "user.email"
      rule       = ""
    }

    attrmap {
      name       = "firstName"
      fmt        = "firstName"
      custom_fmt = ""
      val        = ""
      src        = "user.firstName"
      rule       = ""
    }

    attrmap {
      name       = "lastName"
      fmt        = "lastName"
      custom_fmt = ""
      val        = ""
      src        = "user.lastName"
      rule       = ""
    }
  }
}
