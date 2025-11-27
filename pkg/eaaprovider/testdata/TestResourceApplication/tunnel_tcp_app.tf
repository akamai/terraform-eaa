# This test file is based on examples/tcp_app.tf
# Differences: Uses test values (test-agent-01) instead of real values
# Purpose: Unit test fixture for TCP tunnel application scenarios


provider "eaa" {
  contractid = "test-contract-123"

}

# TCP Tunnel Application with Single Host
resource "eaa_application" "tunnel_tcp_single" {
  name        = "tunnel-tcp-single"
  description = "TCP tunnel application with single host"
  host        = "tunnel-tcp-single"
  app_profile = "tcp"
  app_type    = "tunnel"
  domain      = "wapp"
  client_app_mode = "tcp"

  servers {
    orig_tls        = true
    origin_protocol = "tcp"
    origin_port     = 3200
    origin_host     = "192.168.2.1"
  }

  popregion = "us-west-1"
  agents = ["test-agent-01"]
  auth_enabled = "true"
  app_authentication {
    app_idp = "test-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Engineering"
      }
    }
  }

  advanced_settings = jsonencode({
    is_ssl_verification_enabled = "false"
    ip_access_allow = "false"
    x_wapp_read_timeout = "300"
    internal_host_port = "3200"
    internal_hostname = "internal.example.com"
    health_check_type = "TCP"
    websocket_enabled = "true"
  })
}

# TCP Tunnel Application with Multiple Internal Hosts
resource "eaa_application" "tunnel_tcp_multiple" {
  name        = "tunnel-tcp-multiple"
  description = "TCP tunnel application with multiple internal hosts"
  host        = "tunnel-tcp-multiple"
  app_profile = "tcp"
  app_type    = "tunnel"
  domain      = "wapp"
  client_app_mode = "tunnel"

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

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "8080-8090"
    host       = "192.168.2.3"
  }

  popregion = "us-west-1"
  agents = ["test-agent-01"]
  auth_enabled = "true"
  app_authentication {
    app_idp = "test-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Engineering"
      }
    }
  }

  advanced_settings = jsonencode({
    is_ssl_verification_enabled = "false"
    ip_access_allow = "false"
    x_wapp_read_timeout = "300"
    health_check_type = "TCP"
    websocket_enabled = "true"
  })
}

