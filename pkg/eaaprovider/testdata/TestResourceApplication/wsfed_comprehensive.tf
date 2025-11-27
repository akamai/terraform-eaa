
provider "eaa" {
  contractid = "test-contract-123"

}

# WS-Federation Application with Self-Signed Certificate
resource "eaa_application" "wsfed_self_signed" {
  name        = "wsfed-self-signed-app"
  description = "WS-Federation application with self-signed certificate"
  host        = "wsfed-self-signed.example.com"
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
    app_auth = "WS-Federation"
  })

  wsfed_settings {
    idp {
      self_signed = true
    }
  }
}

# WS-Federation Application with Full SP Configuration
resource "eaa_application" "wsfed_full_sp" {
  name        = "wsfed-full-sp-app"
  description = "WS-Federation application with full SP configuration"
  host        = "wsfed-full-sp.example.com"
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
    app_auth = "WS-Federation"
  })

  wsfed_settings {
    sp {
      entity_id  = "https://wsfed-full-sp.example.com/sp"
      slo_url    = "https://wsfed-full-sp.example.com/slo"
      dst_url    = "https://wsfed-full-sp.example.com/destination"
      resp_bind  = "post"
      token_life = 3600
      encr_algo  = "aes256-cbc"
    }
    
    idp {
      entity_id   = "https://idp.example.com"
      sign_algo   = "SHA256"
      sign_cert   = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
      sign_key    = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
      self_signed = false
    }
    
    subject {
      fmt  = "email"
      src  = "user.email"
      val  = "user.email"
      rule = ""
    }
  }
}

# WS-Federation Application with Attribute Mapping
resource "eaa_application" "wsfed_attrmap" {
  name        = "wsfed-attrmap-app"
  description = "WS-Federation application with attribute mapping"
  host        = "wsfed-attrmap.example.com"
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
    app_auth = "WS-Federation"
  })

  wsfed_settings {
    idp {
      self_signed = true
    }
    
    subject {
      fmt  = "email"
      src  = "user.email"
      val  = "user.email"
      rule = ""
    }
    
    attrmap {
      name  = "Email"
      fmt   = "email"
      src   = "user.email"
      val   = "user.email"
      rule  = ""
    }
    
    attrmap {
      name  = "Groups"
      fmt   = "groups"
      src   = "user.groups"
      val   = "user.groups"
      rule  = ""
    }
  }
}


