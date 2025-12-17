terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# WS-Federation Authentication Application Example
# This example demonstrates how to create an EAA application with WS-Federation authentication


# Basic WS-Federation Application with Default Settings
resource "eaa_application" "wsfed_basic" {
  name            = "wsfed-basic-app"
  description     = "WS-Federation application with default settings"
  host            = "wsfed-basic.example.com"
  app_profile     = "http"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"

  advanced_settings = jsonencode({
    app_auth = "WS-Federation"
  })
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }

  popregion    = "us-east-1"
  agents       = ["EAA_DC1_US1_Access_01"]
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
  wsfed_settings {
    idp {
      self_signed = true
    }


  }


  # No app_authentication block needed for first-time creation
  # API will automatically assign default IDP and create default WS-Federation settings
}

# WS-Federation Application with Custom Settings
resource "eaa_application" "wsfed_custom" {
  name            = "wsfed-custom-apps"
  description     = "WS-Federation application with custom settings"
  host            = "wsfed-custom.example.com"
  app_profile     = "http"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"
  advanced_settings = jsonencode({
    app_auth = "WS-Federation"
  })

  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }

  popregion    = "us-east-1"
  agents       = ["EAA_DC1_US1_Access_01"]
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


  # WS-Federation settings using Terraform resource schema
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
      entity_id   = "https://test-idp.example.com/wsfed/idp/sso"
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

# SaaS Application with WS-Federation Authentication
resource "eaa_application" "saas_wsfed" {
  name        = "saas-wsfed-test"
  description = "SaaS application with WS-Federation authentication"
  host        = "saas-wsfed.example.com"
  app_profile = "http"
  app_type    = "saas"

  # Protocol determines authentication method for SaaS apps
  protocol = "WS-Federation"

  # WS-Federation Settings (from saas.tf)
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
      entity_id   = "https://test-idp.example.com/wsfed/idp/sso"
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
