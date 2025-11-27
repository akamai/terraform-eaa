# This test file is based on examples/saml_application.tf
# Differences: Simplified version with test values (test-agent-01, test-idp)
# Examples has 3 configurations (basic, custom, SaaS), this is the basic version
# Purpose: Unit test fixture for SAML authentication scenarios


provider "eaa" {
  contractid = "test-contract-123"
}

# Enterprise Application with SAML Authentication
resource "eaa_application" "test" {
  name            = "test-saml-app"
  description     = "Test enterprise application with SAML authentication"
  host            = "saml-app.example.com"
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
    app_auth = "SAML2.0"
  })

  saml_settings {
    idp {
      self_signed = true
    }
  }
}

