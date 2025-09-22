terraform {
    required_providers {
        eaa = {
            source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
            version = "1.0.0"
        }
    }
}

provider "eaa" {
  # Configuration options
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# Invalid Enterprise Application - SSH with app_auth (should be disabled)
resource "eaa_application" "enterprise_ssh_invalid_app_auth" {
  name        = "enterprise-ssh-invalid-app-auth"
  description = "Invalid enterprise application with SSH profile and app_auth (should fail validation)"
  host        = "ssh-invalid-auth.example.com"
  app_profile = "ssh"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = false
    origin_protocol = "ssh"
    origin_port     = 22
    origin_host     = "ssh-backend.example.com"
  }
  
  popregion = "us-east-1"
  agents    = ["EAA_DC1_US1_Access_01"]
  
  advanced_settings = jsonencode({
    # This will cause a validation error: app_auth is disabled for enterprise SSH
    app_auth = "kerberos"
    
    health_check_type = "TCP"
    health_check_interval = "30"
    health_check_timeout = "10"
    health_check_rise = "3"
    health_check_fall = "3"
  })
}

# Invalid Enterprise Application - SSH audit for non-SSH profile
resource "eaa_application" "enterprise_invalid_ssh_audit_non_ssh" {
  name        = "enterprise-invalid-ssh-audit-non-ssh"
  description = "Invalid enterprise application with SSH audit for non-SSH profile (should fail validation)"
  host        = "invalid-ssh-audit-non-ssh.example.com"
  app_profile = "http"  # Not SSH profile
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
  agents    = ["EAA_DC1_US1_Access_01"]
  
  advanced_settings = jsonencode({
    app_auth = "none"
    
    # SSH audit enabled for non-SSH profile - should fail
    ssh_audit_enabled = true
    
    health_check_type = "HTTP"
    health_check_http_url = "/health"
    health_check_http_version = "HTTP/1.1"
    health_check_http_host_header = "invalid-ssh-audit-non-ssh.example.com"
    health_check_interval = "30"
    health_check_timeout = "10"
    health_check_rise = "3"
    health_check_fall = "3"
  })
}

# Invalid Enterprise Application - CORS for tunnel app
resource "eaa_application" "enterprise_invalid_cors_tunnel" {
  name        = "enterprise-invalid-cors-tunnel"
  description = "Invalid enterprise application with CORS for tunnel app (should fail validation)"
  host        = "invalid-cors-tunnel.example.com"
  app_profile = "tcp"
  app_type    = "tunnel"  # Tunnel app type
  domain      = "wapp"
  client_app_mode = "tunnel"
  
  servers {
    orig_tls        = false
    origin_protocol = "tcp"
    origin_port     = 80
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
  agents    = ["EAA_DC1_US1_Access_01"]
  
  advanced_settings = jsonencode({
    app_auth = "none"
    
    # CORS not available for tunnel apps - should fail
    allow_cors = true
    cors_origin_list = "https://app.example.com"
    cors_header_list = "Content-Type,Authorization"
    cors_method_list = "GET,POST,PUT,DELETE"
    cors_max_age = "3600"
    cors_support_credential = true
    
    health_check_type = "TCP"
    health_check_interval = "30"
    health_check_timeout = "10"
    health_check_rise = "3"
    health_check_fall = "3"
  })
}

# Invalid Enterprise Application - RDP configuration for non-RDP profile
resource "eaa_application" "enterprise_valid_saml_config" {
  name        = "enterprise-invalid-rdp-config-non-rdp"
  description = "Invalid enterprise application with RDP configuration for non-RDP profile (should fail validation)"
  host        = "invalid-rdp-config-non-rdp.example.com"
  app_profile = "http"  # Not RDP profile
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
  agents    = ["EAA_DC1_US1_Access_01"]
  
  advanced_settings = jsonencode({
    # SAML Settings Block
    saml_settings = {
      idp = {
        self_signed = false
        sign_cert = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/Ovj8WQOMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\naWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF\n-----END CERTIFICATE-----"
        #sign_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\nwT5OKqQHJx8E3P1S0+xP3V6X8jH8cKBwT5OKqQHJx8E3P1S0+xP3V6X8jH8cKBwT5\n-----END PRIVATE KEY-----"
      }
    }
    
    # Authentication (app_auth must be "none" when SAML is enabled)
    app_auth = "none"
    wapp_auth = "basic"
    login_url = "/login"
    logout_url = "/logout"
    
    # Health Check Configuration
    health_check_type = "HTTP"
    health_check_http_url = "/health"
    health_check_http_version = "HTTP/1.1"
    health_check_http_host_header = "valid-saml-settings.example.com"
    health_check_interval = "30"
    health_check_timeout = "10"
    health_check_rise = "3"
    health_check_fall = "3"
    
    # Server Load Balancing
    load_balancing_metric = "round-robin"
    session_sticky = "true"
    session_sticky_cookie_maxage = "3600"
    
    # Enterprise Connectivity Parameters
    idle_conn_floor = "10"
    idle_conn_ceil = "100"
    idle_conn_step = "10"
    idle_close_time_seconds = "300"
    app_server_read_timeout = "60"
    hsts_age = "31536000"
    
    # Miscellaneous Parameters
    proxy_buffer_size_kb = "64"
    logging_enabled = "true"
    hidden_app = "false"
    saas_enabled = "false"
    sticky_agent = "true"
  })
}
