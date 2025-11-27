provider "eaa" {
  contractid = "test-contract-123"
}

resource "eaa_application" "test" {
  name         = "updated-corporate-portal"
  description  = "Updated test application for corporate portal access"
  app_profile  = "http"
  app_type     = "enterprise"
  client_app_mode = "tcp"
  
  host         = "updated-portal.example.com"
  domain       = "wapp"
  
  agents = ["test-agent-01", "test-agent-02"]

  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 8443
    origin_host     = "updated-internal-portal.corp.local"
  }

  advanced_settings = jsonencode({
    app_auth = "saml"
    allow_cors = "true"
    cors_method_list = "GET,POST,PUT,DELETE"
    cors_origin_list = "https://updated-portal.example.com"
    cors_header_list = "Content-Type,Authorization,X-Custom-Header"
    cors_max_age = 172800
    cors_support_credential = "off"
    sticky_agent = "true"
    websocket_enabled = "true"
    sentry_redirect_401 = "false"
  })
}
