
provider "eaa" {
  contractid = "test-contract-123"

}

# Application with Round-Robin Load Balancing
resource "eaa_application" "lb_round_robin" {
  name        = "lb-round-robin-app"
  description = "Application with round-robin load balancing"
  host        = "lb-round-robin.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend1.example.com"
  }
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend2.example.com"
  }
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend3.example.com"
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
    load_balancing_metric = "round-robin"
    session_sticky = "false"
  })
}

# Application with Session Sticky Load Balancing
resource "eaa_application" "lb_session_sticky" {
  name        = "lb-session-sticky-app"
  description = "Application with session sticky load balancing"
  host        = "lb-session-sticky.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend1.example.com"
  }
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend2.example.com"
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
    load_balancing_metric = "round-robin"
    session_sticky = "true"
    session_sticky_cookie_maxage = "3600"
    session_sticky_server_cookie = "JSESSIONID"
  })
}

# Application with Least Connections Load Balancing
resource "eaa_application" "lb_least_connections" {
  name        = "lb-least-connections-app"
  description = "Application with least connections load balancing"
  host        = "lb-least-connections.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend1.example.com"
  }
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend2.example.com"
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
    load_balancing_metric = "least-conn"
    session_sticky = "false"
  })
}

