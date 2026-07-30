# JWT User-Facing Authentication
# Enterprise app with JWT-based user-facing authentication.

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.2.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# wapp_auth="jwt" is user-facing authentication (browser-to-EAA), not app-to-origin.
# EAA validates the JWT before proxying the request to the origin server.
resource "eaa_application" "jwt_app" {
  name            = "JWT Protected App"
  description     = "Enterprise app with JWT user-facing authentication"
  host            = "jwt-app.example.com"
  app_profile     = "http"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"
  popregion       = "us-east-1"
  agents          = ["EAA_DC1_US1_Access_01"]

  servers {
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }

  auth_enabled = "true"

  app_authentication {
    app_idp = "employees-idp"

    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Engineering"
      }
    }
  }

  advanced_settings = {
    wapp_auth        = "jwt"
    jwt_issuers      = "https://auth.example.com"
    jwt_audience     = "my-app"
    jwt_grace_period = "90"
    jwt_username     = "sub"
    jwt_return_url   = "https://jwt-app.example.com/return"
    # jwt_return_option: "401" returns HTTP 401, "redirect" sends the user to jwt_return_url
    jwt_return_option = "401"
  }
}
