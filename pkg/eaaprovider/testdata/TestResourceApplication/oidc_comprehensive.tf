
provider "eaa" {
  contractid = "test-contract-123"

}

# OIDC Application with Default Settings (Auto-configured)
resource "eaa_application" "oidc_default" {
  name        = "oidc-default-app"
  description = "OIDC application with default settings"
  host        = "oidc-default.example.com"
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
    app_auth = "OpenID Connect 1.0"
  })
}

# OIDC Application with Custom Client Settings
resource "eaa_application" "oidc_custom_client" {
  name        = "oidc-custom-client-app"
  description = "OIDC application with custom client settings"
  host        = "oidc-custom-client.example.com"
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
    app_auth = "OpenID Connect 1.0"
  })

  oidc_settings {
    oidc_clients {
      client_id = "custom-client-id"
      type      = "confidential"
    }
  }
}

# OIDC Application with Claims Configuration
resource "eaa_application" "oidc_with_claims" {
  name        = "oidc-with-claims-app"
  description = "OIDC application with claims configuration"
  host        = "oidc-with-claims.example.com"
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
    app_auth = "OpenID Connect 1.0"
  })

  oidc_settings {
    oidc_clients {
      client_id = "claims-client-id"
      type      = "confidential"
      claims {
        name = "email"
        val  = "user.email"
      }
      claims {
        name = "groups"
        val  = "user.groups"
      }
    }
  }
}

