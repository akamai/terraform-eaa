# This test file is based on examples/oidc_application.tf
# Differences: Uses test values (test-agent-01, test-idp) instead of real values
# Purpose: Unit test fixture for OIDC authentication scenarios


provider "eaa" {
  contractid = "test-contract-123"

}

# Enterprise Application with OIDC Authentication
resource "eaa_application" "test" {
  name            = "test-oidc-app"
  description     = "Test enterprise application with OIDC authentication"
  host            = "oidc-app.example.com"
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
    app_auth = "OpenID Connect 1.0"
  })
}

