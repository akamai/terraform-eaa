# Kerberos Authentication
# Basic Kerberos and Kerberos with client certificate and TGT forwarding.

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.2.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# --- Basic Kerberos ---
resource "eaa_application" "kerberos_basic" {
  name            = "Kerberos Basic App"
  description     = "Enterprise app with Kerberos authentication"
  host            = "kerberos-basic.example.com"
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
    app_auth                       = "kerberos"
    app_auth_domain                = "EXAMPLE.COM" # Must be uppercase (Kerberos realm convention)
    app_client_cert_auth           = "false"
    forward_ticket_granting_ticket = "false"
    keytab                         = ""
    service_principle_name         = "HTTP/kerberos-basic.example.com"
  }
}

# --- Kerberos with client certificate and TGT forwarding ---
resource "eaa_application" "kerberos_delegated" {
  name            = "Kerberos Delegated App"
  description     = "Kerberos with client cert auth and TGT forwarding"
  host            = "kerberos-delegated.example.com"
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
    app_auth             = "kerberos"
    app_auth_domain      = "EXAMPLE.COM"
    app_client_cert_auth = "true"
    # When true, the user's TGT is forwarded to the connector for Kerberos delegation.
    forward_ticket_granting_ticket = "true"
    keytab                         = ""
    service_principle_name         = "HTTP/kerberos-delegated.example.com"
  }
}
