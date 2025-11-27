
provider "eaa" {
  contractid = "test-contract-123"

}

# Enterprise Application with RDP Profile
resource "eaa_application" "test" {
  name            = "test-rdp-app"
  description     = "Test enterprise RDP application"
  host            = "rdp-app.example.com"
  app_profile     = "rdp"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"

  servers {
    orig_tls        = false
    origin_protocol = "rdp"
    origin_port     = 3389
    origin_host     = "rdp-backend.example.com"
  }

  popregion = "us-east-1"
  agents    = ["test-agent-01"]

  service {
    service_type = "access"
    status       = "on"
    access_rule {
      name   = "Allow All Users"
      status = "on"
      rule {
        operator = "=="
        type     = "user"
        value    = "*"
      }
    }
  }

  advanced_settings = jsonencode({
    app_auth = "none"
    
    # Health Check Configuration (TCP for RDP)
    health_check_type     = "TCP"
    health_check_interval = "30"
    health_check_timeout  = "10"
    health_check_rise     = "3"
    health_check_fall      = "3"
    
    # RDP Configuration
    rdp_initial_program     = "notepad.exe"
    remote_app             = "Calculator"
    remote_app_args        = "/s"
    remote_app_dir         = "C:\\Windows\\System32"
    rdp_tls1               = "true"
    remote_spark_recording = "true"
    
    # Enterprise Connectivity Parameters
    idle_conn_floor          = "10"
    idle_conn_ceil           = "100"
    idle_conn_step           = "10"
    idle_close_time_seconds  = "300"
    
    # Miscellaneous Parameters
    proxy_buffer_size_kb = "64"
    logging_enabled      = "true"
    hidden_app          = "false"
    saas_enabled        = "false"
    sticky_agent        = "true"
  })
}

