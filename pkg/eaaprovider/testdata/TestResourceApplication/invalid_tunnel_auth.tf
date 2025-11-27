provider "eaa" {
  contractid = "test-contract"
}

# Test error scenario - tunnel app cannot have SAML enabled
resource "eaa_application" "test" {
  name            = "test-tunnel-app"
  app_type        = "tunnel"
  app_profile     = "tcp"
  client_app_mode = "tunnel"
  host            = "test-tunnel.example.com"

  # SAML settings not allowed for tunnel apps
  saml_settings {
    idp {
      self_signed = true
    }
  }
}

