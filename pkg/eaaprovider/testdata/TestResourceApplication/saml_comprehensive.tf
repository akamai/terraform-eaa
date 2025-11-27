
provider "eaa" {
  contractid = "test-contract-123"

}

# SAML Application with Self-Signed Certificate
resource "eaa_application" "saml_self_signed" {
  name        = "saml-self-signed-app"
  description = "SAML application with self-signed certificate"
  host        = "saml-self-signed.example.com"
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
  agents = ["test-agent-01"]
  auth_enabled = "true"
  app_authentication {
    app_idp = "test-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Engineering"
      }
    }
  }

  advanced_settings = jsonencode({
    app_auth = "SAML2.0"
  })

  saml_settings {
    idp {
      self_signed = true
    }
  }
}

# SAML Application with Full SP Configuration
resource "eaa_application" "saml_full_sp" {
  name        = "saml-full-sp-app"
  description = "SAML application with full SP configuration"
  host        = "saml-full-sp.example.com"
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
  agents = ["test-agent-01"]
  auth_enabled = "true"
  app_authentication {
    app_idp = "test-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Engineering"
      }
    }
  }

  advanced_settings = jsonencode({
    app_auth = "SAML2.0"
  })

  saml_settings {
    sp {
      entity_id  = "https://saml-full-sp.example.com/sp"
      acs_url    = "https://saml-full-sp.example.com/acs"
      slo_url    = "https://saml-full-sp.example.com/slo"
      dst_url    = "https://saml-full-sp.example.com/destination"
      resp_bind  = "post"
      encr_algo  = "aes256-cbc"
    }
    
    idp {
      entity_id  = "https://idp.example.com"
      sign_algo  = "SHA256"
      sign_cert  = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
      sign_key   = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
      self_signed = false
    }
    
    subject {
      fmt  = "email"
      src  = "user.email"
    }
  }
}

# SAML Application with Custom Subject Format
resource "eaa_application" "saml_custom_subject" {
  name        = "saml-custom-subject-app"
  description = "SAML application with custom subject format"
  host        = "saml-custom-subject.example.com"
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
  agents = ["test-agent-01"]
  auth_enabled = "true"
  app_authentication {
    app_idp = "test-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Engineering"
      }
    }
  }

  advanced_settings = jsonencode({
    app_auth = "SAML2.0"
  })

  saml_settings {
    idp {
      self_signed = true
    }
    
    subject {
      fmt = "email"
      src = "user.username"
    }
  }
}

