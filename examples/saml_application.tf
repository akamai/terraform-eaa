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
  name        = "saml-basic-app-new"
  description = "SAML2.0 application with UPDATED description - testing JSON approach"
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

  advanced_settings = jsonencode({
    app_auth = "SAML2.0"
  })

  # No saml_settings needed - defaults will be applied
}

# SAML2.0 Application with Custom Settings using JSON approach
resource "eaa_application" "saml_custom_example_1" {
  name        = "saml-custom-json-test-v3"
  description = "SAML2.0 application with comprehensive custom settings using JSON approach"
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

  advanced_settings = jsonencode({
    app_auth = "SAML2.0"
  })

  # Comprehensive SAML settings using JSON approach with jsonencode()
  saml_settings = jsonencode([
    {
      sp = {
        entity_id = "https://saml-custom.example.com/sp"
        acs_url   = "https://saml-custom.example.com/acs"
        slo_url   = "https://saml-custom.example.com/slo"
        req_bind  = "post"
        force_auth = true
        req_verify = true
        sign_cert  = ""
        resp_encr  = true
        encr_cert  = ""
        encr_algo  = "aes256-cbc"
        slo_req_verify = true
        dst_url    = "https://saml-custom.example.com/dst"
        slo_bind   = "post"
        metadata   = "https://saml-custom.example.com/metadata"
      }
      idp = {
        entity_id = "https://custom-idp.example.com"
        metadata  = "https://custom-idp.example.com/metadata"
        self_signed = true
        sign_algo   = "SHA256"
        resp_bind   = "post"
        slo_url     = "https://custom-idp.example.com/slo"
        ecp_enable  = true
        ecp_resp_signature = true
      }
      subject = {
        fmt = "email"
        src = "user.email"
        val = ""
        rule = ""
      }
      attrmap = [
        {
          name = "email"
          fname = "Email"
          fmt  = "email"
          val  = ""
          src  = "user.email"
          rule = ""
        },
        {
          name = "firstName"
          fname = "First Name"
          fmt  = "firstName"
          val  = ""
          src  = "user.firstName"
          rule = ""
        },
        {
          name = "lastName"
          fname = "Last Name"
          fmt  = "lastName"
          val  = ""
          src  = "user.lastName"
          rule = ""
        }
      ]
    }
  ])
}