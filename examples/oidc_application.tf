# OpenID Connect Authentication Application Example
# This example demonstrates how to create an EAA application with OpenID Connect authentication

terraform {
  required_providers {
    eaa = {
      source = "terraform.eaaprovider.dev/eaaprovider/eaa"
    }
  }
}

provider "eaa" {
  # Configuration options
}

# Basic OpenID Connect Application with Default Settings
resource "eaa_application" "oidc_basic" {
  name        = "oidc-basic-app"
  description = "OpenID Connect application with default settings"
  host        = "oidc-basic.example.com"
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
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "OpenID Connect 1.0"
    # No oidc_settings needed - defaults will be applied
  }

  # No app_authentication block needed for first-time creation
  # API will automatically assign default IDP and create default OIDC settings
}

# OpenID Connect Application with Alternative app_auth Value
resource "eaa_application" "oidc_alt" {
  name        = "oidc-alt-app"
  description = "OpenID Connect application using 'oidc' value"
  host        = "oidc-alt.example.com"
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
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "oidc"  # Alternative to "OpenID Connect 1.0"
  }

  # Uses same default behavior as "OpenID Connect 1.0"
}

# OpenID Connect Application with Custom Settings
# Note: OIDC settings are read-only and populated from API response
resource "eaa_application" "oidc_custom" {
  name        = "oidc-custom-app"
  description = "OpenID Connect application with custom configuration"
  host        = "oidc-custom.example.com"
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
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "OpenID Connect 1.0"
  }

  # OIDC settings are populated from API response
  # These fields are computed and will be populated after creation
  oidc_settings {
    # These fields will be populated from the API response
    # authorization_endpoint = "https://oidc-provider.example.com/auth"
    # token_endpoint = "https://oidp-provider.example.com/token"
    # userinfo_endpoint = "https://oidp-provider.example.com/userinfo"
    # jwks_uri = "https://oidp-provider.example.com/jwks"
    # discovery_url = "https://oidp-provider.example.com/.well-known/openid_configuration"
    # etc.
  }
} 