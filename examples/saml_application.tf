# SAML Authentication Application Example
# This example demonstrates how to create an EAA application with SAML2.0 authentication
terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
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
    app_auth = "SAML2.0"
    
  })
  saml_settings {
    
    # Identity Provider (IDP) Configuration
    idp {
      self_signed = true                   # Set to true if using self-signed certificates
    }
    
    
  }

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
    app_auth = "SAML2.0"
  })

  # SAML settings using schema approach (nested blocks)
  saml_settings {
    # Service Provider (SP) Configuration
    sp {
      entity_id  = "https://saml-custom.example.com/sp"
      acs_url    = "https://saml-custom.example.com/acs"
      slo_url    = "https://saml-custom.example.com/slo"
      dst_url    = "https://saml-custom.example.com/destination"
      resp_bind  = "post"                    # Valid: "post", "redirect"
      token_life = 3600                      # Token lifetime in seconds
      encr_algo  = "aes256-cbc"             # Valid: "aes128-cbc", "aes192-cbc", "aes256-cbc", "tripledes-cbc"
    }
    
    # Identity Provider (IDP) Configuration
    idp {
      entity_id   = "https://idp.example.com/metadata"
      sign_algo   = "SHA256"                
      sign_cert   = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"
      sign_key    = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"
      self_signed = true                   # Set to true if using self-signed certificates
    }
    
    # Subject Configuration
    subject {
      fmt = "email"                         # Valid: "email", "nameid", "persistent", "transient", "unspecified"
      src = "user.email"                    # Source attribute for subject
    }
    
    # Attribute Mapping Configuration
    # Custom Attribute Mapping
    attrmap {
      name = "name"
      fname = "name"
      fmt = "basic"
      src = "user.email"
    }
  }
}