# JWT Authentication Application Example
# This example demonstrates how to create an EAA application with JWT user-facing authentication

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

# JWT Authentication Application with Default Settings
resource "eaa_application" "jwt_basic" {
  name        = "jwt-basic-app"
  description = "JWT authentication application with default settings"
  host        = "jwt-basic.example.com"
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
    wapp_auth = "jwt"
    # Default JWT settings will be applied:
    # jwt_grace_period = "60"
    # jwt_return_option = "401"
    # Other JWT fields default to empty strings
  }
}

# JWT Authentication Application with Custom Settings
resource "eaa_application" "jwt_custom" {
  name        = "jwt-custom-app"
  description = "JWT authentication application with custom settings"
  host        = "jwt-custom.example.com"
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
    wapp_auth = "jwt"
    jwt_issuers = "https://auth.example.com"
    jwt_audience = "my-app"
    jwt_grace_period = "90"
    jwt_return_option = "401"
    jwt_username = "sub"
    jwt_return_url = "https://jwt-custom.example.com/return"
  }
}

