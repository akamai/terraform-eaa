# This test file is based on examples/tunnel_app.tf
# Differences: Uses test values (test-agent-01, test-idp) instead of real values
# Purpose: Unit test fixture for tunnel application scenarios


provider "eaa" {
  contractid = "test-contract-123"

}

# Tunnel Application - Basic Configuration
resource "eaa_application" "test" {
  name            = "test-tunnel-app"
  description     = "Test tunnel application"
  app_profile     = "tcp"
  app_type        = "tunnel"
  client_app_mode = "tunnel"
  domain          = "wapp"
  popregion       = "us-west-1"
  host            = "test-tunnel-app"

  agents = ["test-agent-01"]

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

  advanced_settings = jsonencode({
    is_ssl_verification_enabled = "false"
    ip_access_allow            = "false"
    x_wapp_read_timeout        = "300"
    health_check_type          = "TCP"
    websocket_enabled          = "true"
  })

  auth_enabled = "true"

  app_authentication {
    app_idp = "test-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Test-Group"
      }
    }
  }
}

