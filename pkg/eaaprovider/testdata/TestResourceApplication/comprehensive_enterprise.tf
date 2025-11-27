
provider "eaa" {
  contractid = "test-contract-123"

}

# Comprehensive Enterprise Application with All Features
resource "eaa_application" "test" {
  name            = "test-comprehensive-enterprise"
  description     = "Comprehensive enterprise application with all supported features"
  host            = "comprehensive.example.com"
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

  advanced_settings = jsonencode({
    # Authentication
    app_auth = "none"

    # Health Check Configuration
    health_check_type              = "HTTP"
    health_check_http_url          = "/health"
    health_check_http_version      = "HTTP/1.1"
    health_check_http_host_header  = "comprehensive.example.com"
    health_check_interval          = "30"
    health_check_timeout           = "10"
    health_check_rise              = "3"
    health_check_fall              = "3"

    # Server Load Balancing
    load_balancing_metric = "round-robin"
    session_sticky       = "true"
    cookie_age           = 3600

    # Custom Headers
    custom_headers = [
      {
        attribute_type = "custom"
        header         = "myheader"
        attribute      = "value"
      },
      {
        attribute_type = "user"
        header         = "myuser"
        attribute      = ""
      }
    ]

    # Enterprise Connectivity Parameters
    idle_conn_floor          = "10"
    idle_conn_ceil           = "100"
    idle_conn_step           = "10"
    idle_close_time_seconds  = "300"
    app_server_read_timeout   = "120"
    hsts_age                  = "31536000"

    # Miscellaneous Parameters
    proxy_buffer_size_kb      = "64"
    allow_cors                = "true"
    cors_origin_list          = "https://app.example.com"
    cors_header_list          = "Content-Type,Authorization"
    cors_method_list          = "GET,POST,PUT,DELETE"
    cors_max_age              = "3600"
    cors_support_credential    = "on"
    websocket_enabled         = "true"
    logging_enabled           = "true"
    hidden_app                = "false"
    saas_enabled              = "false"
    sticky_agent              = "true"
    offload_onpremise_traffic = "true"
  })
}

