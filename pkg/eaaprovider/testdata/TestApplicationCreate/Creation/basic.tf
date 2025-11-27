provider "eaa" {
  contractid = "test-contract-123"
}

resource "eaa_application" "test" {
  name         = "test-corporate-portal"
  description  = "Test application for corporate portal access"
  app_profile  = "http"
  app_type     = "enterprise"
  client_app_mode = "tcp"
  
  host         = "portal.example.com"
  domain       = "wapp"
  popregion    = "us-east-1"
  
  agents = ["test-agent-01"]

  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "internal-portal.corp.local"
  }

  advanced_settings = jsonencode({
    app_auth = "basic"
    allow_cors = "true"
    cors_method_list = "GET,POST,PUT"
    cors_origin_list = "https://portal.example.com"
    cors_header_list = "Content-Type,Authorization"
    cors_max_age = 86400
    cors_support_credential = "off"
    sticky_agent = "false"
    websocket_enabled = "false"
    sentry_redirect_401 = "false"
  })
}
