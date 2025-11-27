# This test file is based on examples/wsfederation_application.tf
# Differences: Uses test values (test-agent-01, test-idp) instead of real values
# Purpose: Unit test fixture for WS-Federation authentication scenarios


provider "eaa" {
  contractid = "test-contract-123"

}

# Enterprise Application with WS-Federation Authentication
resource "eaa_application" "test" {
  name            = "test-wsfed-app"
  description     = "Test enterprise application with WS-Federation authentication"
  host            = "wsfed-app.example.com"
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

  popregion = "us-east-1"
  agents    = ["test-agent-01"]
  
  auth_enabled = "true"
  
  app_authentication {
    app_idp = "test-idp"
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
    app_auth = "WS-Federation"
  })

  wsfed_settings {
    idp {
      self_signed = true
    }
  }
}

