
provider "eaa" {
  contractid = "test-contract-123"

}

# Application with HTTP Health Check
resource "eaa_application" "health_check_http" {
  name        = "health-check-http-app"
  description = "Application with HTTP health check configuration"
  host        = "health-check-http.example.com"
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
    health_check_type = "HTTP"
    health_check_http_url = "/health"
    health_check_http_version = "HTTP/1.1"
    health_check_http_host_header = "health-check-http.example.com"
    health_check_interval = "30000"
    health_check_timeout = "50000"
    health_check_rise = "2"
    health_check_fall = "3"
  })
}

# Application with TCP Health Check
resource "eaa_application" "health_check_tcp" {
  name        = "health-check-tcp-app"
  description = "Application with TCP health check configuration"
  host        = "health-check-tcp.example.com"
  app_profile = "tcp"
  app_type    = "tunnel"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "tcp"
    origin_port     = 3306
    origin_host     = "192.168.2.1"
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
    health_check_type = "TCP"
  })
}

# Application with Minimal Health Check
resource "eaa_application" "health_check_minimal" {
  name        = "health-check-minimal-app"
  description = "Application with minimal health check configuration"
  host        = "health-check-minimal.example.com"
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
    health_check_type = "HTTP"
    health_check_http_url = "/"
    health_check_http_version = "HTTP/1.1"
    health_check_http_host_header = "health-check-minimal.example.com"
  })
}

