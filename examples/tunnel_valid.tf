terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
  contractid       = "XXXXXXX"
  edgerc           = ".edgerc"
}

resource "eaa_application" "tunnel_valid" {
  provider    = eaa

  app_profile     = "tcp"
  app_type        = "tunnel"
  client_app_mode = "tunnel"

  domain          = "wapp"
  popregion       = "us-west-1"

  name        = "tunnel-valid-app"
  description = "Tunnel app created using terraform"
  host        = "tunnel.example.com"

  agents = ["EAA_DC1_US1_TCP_01"]

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "8080"
    host       = "internal.example.com"
  }

  advanced_settings = jsonencode({
    is_ssl_verification_enabled = "false"
    ip_access_allow = "false"
    x_wapp_read_timeout = "300"
    health_check_type = "TCP"
    websocket_enabled = "true"
  })

  auth_enabled = "true"

  app_authentication {
    app_idp = "employees-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "SAP-Admins"
      }
    }
  }
}