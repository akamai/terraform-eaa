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
  saml            = true
  
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
  saml            = true
  
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
    
  })

  # SAML settings using schema approach (nested blocks)
  saml_settings {
    
    
    idp {
      self_signed = false
      sign_cert   = ""
      
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