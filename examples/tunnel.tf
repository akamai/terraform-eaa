# Tunnel Applications
# TCP tunnel with internal hosts and TCP client-mode tunnel.

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

# --- Full tunnel with multiple internal hosts ---
# Tunnels require websocket_enabled=true and health_check_type=TCP.
# client_app_mode "tunnel" exposes tunnel_internal_hosts to the EAA Client.
resource "eaa_application" "sap_tunnel" {
  name            = "SAP Production"
  description     = "Full tunnel to SAP backend services"
  host            = "sap-prod-dc1"
  app_profile     = "tcp"
  app_type        = "tunnel"
  client_app_mode = "tunnel"
  domain          = "wapp"
  popregion       = "us-west-1"
  agents          = ["EAA_DC1_US1_TCP_01"]

  # proto_type: 1 = TCP, 2 = UDP, 3 = ALL (per EAA API)
  tunnel_internal_hosts {
    proto_type = 1
    port_range = "3200-6000"
    host       = "192.168.2.1"
  }

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "40199"
    host       = "192.168.2.2"
  }

  advanced_settings = {
    is_ssl_verification_enabled = "false"
    ip_access_allow             = "false"
    x_wapp_read_timeout         = "300"
    health_check_type           = "TCP"
    websocket_enabled           = "true"
  }

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

# --- TCP client-mode tunnel ---
# client_app_mode "tcp" uses a servers block instead of tunnel_internal_hosts.
# Traffic is forwarded to a single origin (like a traditional reverse proxy over TCP).
resource "eaa_application" "sql_tcp" {
  name            = "SQL Lab Instance"
  description     = "TCP tunnel to SQL database"
  host            = "sql-lab-dc1"
  app_profile     = "tcp"
  app_type        = "tunnel"
  client_app_mode = "tcp"
  domain          = "wapp"
  popregion       = "us-west-1"
  agents          = ["EAA_DC1_US1_TCP_01"]

  servers {
    origin_protocol = "tcp"
    origin_port     = 3200
    origin_host     = "192.168.2.1"
  }

  advanced_settings = {
    is_ssl_verification_enabled = "false"
    ip_access_allow             = "false"
    x_wapp_read_timeout         = "300"
    internal_host_port          = "300"
    internal_hostname           = "sql-lab.internal.example.com"
    health_check_type           = "TCP"
    websocket_enabled           = "true"
  }

  auth_enabled = "true"

  app_authentication {
    app_idp = "employees-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "DBA-Team"
      }
    }
  }
}
