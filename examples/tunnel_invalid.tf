terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# This should FAIL - tunnel app with invalid/blocked fields
resource "eaa_application" "tunnel_invalid_auth" {
  name                = "tunnel-invalid-auth"
  app_type            = "tunnel"
  app_profile         = "tcp"
  client_app_mode     = "tunnel"
  host                = "tunnel-invalid.example.com"
  auth_enabled        = true

  # These should be BLOCKED for tunnel apps
  saml                = true   
   

  domain              = "wapp"
  popregion           = "us-west-1"
  agents              = ["EAA_DC1_US1_TCP_01"]

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "8080"
    host       = "internal.example.com"
  }

  advanced_settings = jsonencode({
    # These should be BLOCKED for tunnel apps
    login_url                    = "https://tunnel.example.com/login"     
    logout_url                   = "https://tunnel.example.com/logout"    
    cors_origin_list             = "https://example.com"                  
    cors_header_list             = "Content-Type"                         # CORS
    cors_method_list             = "GET,POST"                             # CORS
    cors_support_credential      = true                                   # CORS
    cors_max_age                 = "3600"                                 # CORS
    tls_suite_name              = "TLS-Suite-v3"                         # TLS Suite
    tls_cipher_suite            = "ECDHE-RSA-AES256-GCM-SHA384"          # TLS Suite
    custom_headers               = []                                     # Miscellaneous
    hidden_app                   = false                                  # Miscellaneous
    offload_onpremise_traffic    = true                                   # Miscellaneous
    logging_enabled              = true                                   # Miscellaneous
    saas_enabled                 = false                                  # Miscellaneous
    segmentation_policy_enable   = true                                   # Miscellaneous
    rdp_audio_redirection        = true                                   # RDP configuration
    rdp_clipboard_redirection    = true                                   # RDP configuration
    rdp_disk_redirection         = true                                   
    
    # These should be ALLOWED for tunnel apps
    health_check_type            = "TCP"                                  # Health Check
    websocket_enabled            = true                                   # Basic Config
    is_ssl_verification_enabled  = "false"                               # Basic Config
    load_balancing_metric        = "round_robin"                          # Server Load Balancing
    session_sticky               = true                                   # Server Load Balancing
    acceleration                 = true                                   # Tunnel Client Parameters
    x_wapp_read_timeout          = "300"                                 # Tunnel Client Parameters
  })
}

# This should FAIL - tunnel app with wrong app_type
resource "eaa_application" "tunnel_wrong_type" {
  name                = "tunnel-wrong-type"
  app_type            = "enterprise"  # Wrong app_type for tunnel validation
  app_profile         = "tcp"
  client_app_mode     = "tunnel"
  host                = "tunnel-wrong.example.com"
  auth_enabled        = true

  domain              = "wapp"
  popregion           = "us-west-1"
  agents              = ["EAA_DC1_US1_TCP_01"]

  servers {
    origin_host     = "backend.example.com"
    origin_port     = 443
    origin_protocol = "https"
    orig_tls        = true
  }

  advanced_settings = jsonencode({
    # These should be BLOCKED for tunnel apps but allowed for enterprise
    login_url                    = "https://tunnel.example.com/login"     # Allowed for enterprise
    logout_url                   = "https://tunnel.example.com/logout"    # Allowed for enterprise
    allow_cors                   = true                                   # Allowed for enterprise
    tls_suite_name              = "TLS-Suite-v3"                         # Allowed for enterprise
    custom_headers               = []                                     # Allowed for enterprise
  })
}

# This should FAIL - tunnel app with missing required fields
resource "eaa_application" "tunnel_missing_required" {
  name                = "tunnel-missing-required"
  app_type            = "tunnel"
  app_profile         = "tcp"
  client_app_mode     = "tunnel"
  # host                = "tunnel-missing.example.com"  # Missing required field
  auth_enabled        = true

  # domain              = "wapp"                        # Missing required field
  # popregion           = "us-west-1"                  # Missing required field
  # agents              = ["EAA_DC1_US1_TCP_01"]       # Missing required field

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "8080"
    host       = "internal.example.com"
  }

  advanced_settings = jsonencode({
    health_check_type = "TCP"
    websocket_enabled = true
  })
}