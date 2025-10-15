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
  contractid       = "XXXXXXX"
  edgerc           = ".edgerc"
}

# ========================================
# VALID ENTERPRISE SCENARIOS
# ========================================

# Valid Enterprise Application - Basic HTTP with all features
resource "eaa_application" "enterprise_valid_comprehensive" {
  name        = "enterprise-valid-comprehensive"
  description = "Valid comprehensive enterprise application with all supported features"
  host        = "valid-comprehensive.example.com"
  app_profile = "http"
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
    # Authentication
    app_auth = "none"
    
    # Health Check Configuration (Enterprise supported)
    health_check_type = "HTTP"
    health_check_http_url = "/health"
    health_check_http_version = "HTTP/1.1"
    health_check_http_host_header = "valid-comprehensive.example.com"
    health_check_interval = "30"
    health_check_timeout = "10"
    health_check_rise = "3"
    health_check_fall = "3"
    
    # Server Load Balancing (Enterprise supported)
    load_balancing_metric = "round-robin"
    session_sticky = "true"
    cookie_age = 3600
    
    # Custom Headers (Enterprise supported)
    custom_headers = [
            {
                attribute_type = "custom"
                header = "myheader"
                attribute = "value"
                
            },
            {
                attribute_type = "user"
                header = "myuser"
                attribute = ""
                
            }
        ]
    
    # Enterprise Connectivity Parameters (Enterprise supported)
    idle_conn_floor = "10"
    idle_conn_ceil = "100"
    idle_conn_step = "10"
    idle_close_time_seconds = "300"
    app_server_read_timeout = "120"
    hsts_age = "31536000"
    
    # Miscellaneous Parameters (Enterprise supported)
    proxy_buffer_size_kb = "64"
    allow_cors = "true"
    cors_origin_list = "https://app.example.com"
    cors_header_list = "Content-Type,Authorization"
    cors_method_list = "GET,POST,PUT,DELETE"
    cors_max_age = "3600"
    cors_support_credential = "true"
    websocket_enabled = "true"
    logging_enabled = "true"
    hidden_app = "false"
    saas_enabled = "false"
    sticky_agent = "true"
    offload_onpremise_traffic = "true"
  })
}



# Valid Enterprise Application - RDP Profile
resource "eaa_application" "enterprise_valid_rdp" {
  name        = "enterprise-valid-rdp-v2"
  description = "Valid enterprise RDP application"
  host        = "valid-rdp-v2.example.com"
  app_profile = "rdp"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = false
    origin_protocol = "rdp"
    origin_port     = 3389
    origin_host     = "rdp-backend.example.com"
  }
  
  popregion = "us-east-1"
  agents    = ["EAA_DC1_US1_Access_01"]
  
  # Service configuration for RDP
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
    health_check_type = "TCP"
    health_check_interval = "30"
    health_check_timeout = "10"
    health_check_rise = "3"
    health_check_fall = "3"
    
    # RDP Configuration (Enterprise RDP supported)
    rdp_initial_program = "notepad.exe"
    remote_app = "Calculator"
    remote_app_args = "/s"
    remote_app_dir = "C:\\Windows\\System32"
    rdp_tls1 = "true"
    remote_spark_recording = "true"
    
    # Enterprise Connectivity Parameters
    idle_conn_floor = "10"
    idle_conn_ceil = "100"
    idle_conn_step = "10"
    idle_close_time_seconds = "300"
    
    # Miscellaneous Parameters
    proxy_buffer_size_kb = "64"
    logging_enabled = "true"
    hidden_app = "false"
    saas_enabled = "false"
    sticky_agent = "true"
  })
}

# Valid Enterprise Application - Kerberos Authentication
resource "eaa_application" "enterprise_valid_kerberos" {
  name        = "enterprise-valid-kerberos"
  description = "Valid enterprise application with Kerberos authentication"
  host        = "valid-kerberos.example.com"
  app_profile = "http"
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
    # Kerberos Authentication
    app_auth = "kerberos"
    app_auth_domain = "EXAMPLE.COM"
    app_client_cert_auth = "false"
    forward_ticket_granting_ticket = "true"
    keytab = "example.keytab"
    service_principal_name = "HTTP/valid-kerberos.example.com@EXAMPLE.COM"
    kerberos_negotiate_once = "true"
    
    # Health Check Configuration
    health_check_type = "HTTP"
    health_check_http_url = "/health"
    health_check_http_version = "HTTP/1.1"
    health_check_http_host_header = "valid-kerberos.example.com"
    health_check_interval = "30"
    health_check_timeout = "10"
    health_check_rise = "3"
    health_check_fall = "3"
    
    # Server Load Balancing
    load_balancing_metric = "round-robin"
    session_sticky = "true"
    cookie_age = 3600
    
    # Enterprise Connectivity Parameters
    idle_conn_floor = "10"
    idle_conn_ceil = "100"
    idle_conn_step = "10"
    idle_close_time_seconds = "300"
    
    # Miscellaneous Parameters
    proxy_buffer_size_kb = "64"
    logging_enabled = "true"
    hidden_app = "false"
    saas_enabled = "false"
    sticky_agent = "true"
  })
}

# Valid Enterprise Application - SAML Authentication (Correct)
resource "eaa_application" "enterprise_valid_saml" {
  name        = "enterprise-valid-saml"
  description = "Valid enterprise application with SAML authentication (app_auth=none)"
  host        = "valid-saml.example.com"
  app_profile = "http"
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
  saml = "true"  # SAML enabled at resource level
  
  advanced_settings = jsonencode({
    # SAML Settings Block
    saml_settings = {
      idp = {
        self_signed = "true"
      }
    }
    
    # When SAML is enabled at resource level, app_auth must be "none"
    
    
    # Health Check Configuration
    health_check_type = "HTTP"
    health_check_http_url = "/health"
    health_check_http_version = "HTTP/1.1"
    health_check_http_host_header = "valid-saml.example.com"
    health_check_interval = "30"
    health_check_timeout = "10"
    health_check_rise = "3"
    health_check_fall = "3"
    
    # Server Load Balancing
    load_balancing_metric = "round-robin"
    session_sticky = "true"
    cookie_age = 3600
    
    # Enterprise Connectivity Parameters
    idle_conn_floor = "10"
    idle_conn_ceil = "100"
    idle_conn_step = "10"
    idle_close_time_seconds = "300"
    
    # Miscellaneous Parameters
    proxy_buffer_size_kb = "64"
    logging_enabled = "true"
    hidden_app = "false"
    saas_enabled = "false"
    sticky_agent = "true"
  })
}