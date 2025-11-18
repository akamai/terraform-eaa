terraform {
  required_providers {
    eaa = {
      source = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
  contractid       = "XXXXXXX"
  edgerc           = ".edgerc"
}

# OpenID Connect Application Example
# This example demonstrates how to create an EAA application with OIDC authentication



# Basic OIDC Application with Default Settings
resource "eaa_application" "oidc_basic" {
  name        = "oidc-basic-app"
  description = "OIDC application with default settings-update"
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
  app_authentication {
       app_idp = "employees-idp"

       app_directories {
            name = "Cloud Directory"
            app_groups {
                name = "Engineering"
            }
            app_groups {
                name = "SQA"
            }
        }
    }

  advanced_settings = jsonencode({
    app_auth = "OpenID Connect 1.0"
    
    # No oidc_settings needed - defaults will be applied
  })

  # No app_authentication block needed for first-time creation
  # API will automatically assign default IDP and create default OIDC settings
}

# OIDC Application with Custom Settings

# SaaS Application with OIDC Authentication (OpenID Connect 1.0)
resource "eaa_application" "saas_oidc" {
  name        = "saas-oidc-example"
  description = "SaaS application with OIDC authentication"
  host        = "saas-oidc.example.com"
  app_profile = "http"
  app_type    = "saas"

  # Protocol determines authentication method for SaaS apps
  protocol = "OpenID Connect 1.0"
}
