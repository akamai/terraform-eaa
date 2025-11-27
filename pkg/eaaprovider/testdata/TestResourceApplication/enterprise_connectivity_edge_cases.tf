
provider "eaa" {
  contractid = "test-contract-123"

}

# Application with Custom Idle Connection Settings
resource "eaa_application" "idle_conn_custom" {
  name        = "idle-conn-custom-app"
  description = "Application with custom idle connection settings"
  host        = "idle-conn-custom.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
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
    app_auth = "none"
    idle_conn_floor = "10"
    idle_conn_ceil = "100"
    idle_conn_step = "10"
    idle_close_time_seconds = "300"
    app_server_read_timeout = "120"
  })
}

# Application with HSTS Configuration
resource "eaa_application" "hsts_enabled" {
  name        = "hsts-enabled-app"
  description = "Application with HSTS enabled"
  host        = "hsts-enabled.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
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
    app_auth = "none"
    hsts_age = "31536000"
    http_only_cookie = "true"
    https_sslv3 = "false"
  })
}

# Application with WebSocket Enabled
resource "eaa_application" "websocket_enabled" {
  name        = "websocket-enabled-app"
  description = "Application with WebSocket support enabled"
  host        = "websocket-enabled.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
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
    app_auth = "none"
    websocket_enabled = "true"
  })
}


