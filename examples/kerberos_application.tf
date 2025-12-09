# Kerberos Authentication Application Example
# This example demonstrates how to create an EAA application with Kerberos authentication

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
  # Configuration options
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# Basic Kerberos Authentication Application
resource "eaa_application" "kerberos_basic" {
  name            = "kerberos-basic-app"
  description     = "Kerberos authentication application"
  host            = "kerberos-basic.example.com"
  app_profile     = "http"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"

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

  advanced_settings = jsonencode({
    app_auth                       = "kerberos"
    app_auth_domain                = "EXAMPLE.COM"
    app_client_cert_auth           = "false"
    forward_ticket_granting_ticket = "false"
    keytab                         = ""
    service_principal_name         = "HTTP/kerberos-basic.example.com"
  })
}

# Kerberos Authentication Application with Client Certificate Auth
resource "eaa_application" "kerberos_client_cert" {
  name            = "kerberos-client-cert-app"
  description     = "Kerberos authentication application with client certificate auth"
  host            = "kerberos-client-cert.example.com"
  app_profile     = "http"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"

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
    app_idp = "employees-id"

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

  advanced_settings = jsonencode({
    app_auth                       = "kerberos"
    app_auth_domain                = "EXAMPLE.COM"
    app_client_cert_auth           = "true"
    forward_ticket_granting_ticket = "true"
    keytab                         = ""
    service_principal_name         = "HTTP/kerberos-client-cert.example.com"
  })
}
