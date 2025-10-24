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

# SaaS Application with SAML Authentication
resource "eaa_application" "saas_saml" {
  name        = "saas-saml-test"
  description = "SaaS application with SAML authentication"
  host        = "saas-saml.example.com"
  app_profile = "http"
  app_type    = "saas"

  # Protocol determines authentication method for SaaS apps
  protocol = "SAML2.0"

  # SAML Settings
  saml_settings {
    # Service Provider (SP) Configuration
    sp {
      entity_id  = "https://saas-saml.example.com/sp"  # Entity ID
      acs_url    = "https://saas-saml.example.com/acs"  # ACS URL
      slo_url    = "https://saas-saml.example.com/slo"  # Single logout URL
      dst_url    = "https://saas-saml.example.com/dashboard"  # Default Relay State
      resp_bind  = "post"                    # Single logout binding (Post)
      token_life = 3600                      # Token lifetime in seconds
      encr_algo  = "aes256-cbc"             # Response encryption algorithm (AES256-CBC)
    }
    
    # Identity Provider (IDP) Configuration
    idp {
      entity_id   = "https://idp.example.com/metadata"
      sign_algo   = "SHA256"                # Response signing algorithm (SHA256)
      #sign_key    = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"  # Request signing certificate
    }
    
    # Subject Configuration
    subject {
      fmt = "email"                         # NameID format (Email)
      src = "user.email"                    # NameID attribute (user.email)
    }
    
    # Attribute Mapping Configuration
    attrmap {
      name = "name"
      fname = "name"
      fmt = "basic"
      src = "user.email"
    }
  }
}

# SaaS Application with OIDC Authentication
resource "eaa_application" "saas_oidc" {
  name        = "saas-oidc-test"
  description = "SaaS application with OIDC authentication"
  host        = "saas-oidc.example.com"
  app_profile = "http"
  app_type    = "saas"

  # Protocol determines authentication method for SaaS apps
   protocol = "OpenID Connect 1.0"
}

# SaaS Application with WS-Federation Authentication
resource "eaa_application" "saas_wsfed" {
  name        = "saas-wsfed-test"
  description = "SaaS application with WS-Federation authentication"
  host        = "saas-wsfed.example.com"
  app_profile = "http"
  app_type    = "saas"

  # Protocol determines authentication method for SaaS apps
  protocol = "WS-Federation"

  # WS-Federation Settings
  wsfed_settings {
    sp {
      entity_id = "https://saas-wsfed.example.com"
      slo_url   = "https://saas-wsfed.example.com/wsfed/slo"
      dst_url   = "https://saas-wsfed.example.com/wsfed/dst"
      resp_bind = "post"
      token_life = 3600
      encr_algo  = "aes128-cbc"
    }
    
    idp {
      entity_id = "https://test-idp.example.com/wsfed/idp/sso"
      sign_algo = "SHA1"
      sign_key  = ""
      self_signed = true
    }
    
    subject {
      fmt = "email"
      custom_fmt = ""
      src = "user.email"
      val = ""
      rule = ""
    }
    
    attrmap {
      name = "email"
      fmt  = "email"
      custom_fmt = ""
      val  = ""
      src  = "user.email"
      rule = ""
    }
    
    attrmap {
      name = "firstName"
      fmt  = "firstName"
      custom_fmt = ""
      val  = ""
      src  = "user.firstName"
      rule = ""
    }
    
    attrmap {
      name = "lastName"
      fmt  = "lastName"
      custom_fmt = ""
      val  = ""
      src  = "user.lastName"
      rule = ""
    }
  }
}