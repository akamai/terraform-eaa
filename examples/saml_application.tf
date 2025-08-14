# SAML Authentication Application Example
# This example demonstrates how to create an EAA application with SAML2.0 authentication

terraform {
  required_providers {
    eaa = {
      source = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
  # Configuration options
  contractid       = "XXXXXXX"
  edgerc           = ".edgerc"
}

# Basic SAML2.0 Application with Default Settings
resource "eaa_application" "saml_basic" {
  name        = "saml-basic-app"
  description = "SAML2.0 application with default settings"
  host        = "saml-basic.example.com"
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
    app_auth = "SAML2.0"
    # No saml_settings needed - defaults will be applied
  }

  # No app_authentication block needed for first-time creation
  # API will automatically assign default IDP and create default SAML settings
}

# SAML2.0 Application with Custom Settings
resource "eaa_application" "saml_custom" {
  name        = "saml-custom-app"
  description = "SAML2.0 application with custom settings"
  host        = "saml-custom.example.com"
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
    app_auth = "SAML2.0"
  }

  saml_settings {
    sp {
      entity_id = "https://saml-custom.example.com"
      acs_url   = "https://saml-custom.example.com/saml/acs"
      slo_url   = "https://saml-custom.example.com/saml/slo"
      req_bind  = "redirect"
      force_auth = false
      req_verify = false
      sign_cert  = ""
      resp_encr  = false
      encr_cert  = ""
      encr_algo  = "aes256-cbc"
      slo_req_verify = true
      dst_url    = ""
    }
    
    idp {
      entity_id = "https://test-idp.example.com"
      metadata  = ""
      sign_cert = ""
      sign_key  = ""
      self_signed = false
      sign_algo   = "SHA256"
      resp_bind   = "post"
      slo_url     = "https://test-idp.example.com/saml/slo"
      ecp_enable  = false
      ecp_resp_signature = false
    }
    
    subject {
      fmt = "email"
      src = "user.email"
      val = ""
      rule = ""
    }
    
    attrmap {
      name = "email"
      fname = "Email"
      fmt  = "email"
      val  = ""
      src  = "user.email"
      rule = ""
    }
    
    attrmap {
      name = "firstName"
      fname = "First Name"
      fmt  = "firstName"
      val  = ""
      src  = "user.firstName"
      rule = ""
    }
    
    attrmap {
      name = "lastName"
      fname = "Last Name"
      fmt  = "lastName"
      val  = ""
      src  = "user.lastName"
      rule = ""
    }
  }
} 