
provider "eaa" {
  contractid = "test-contract-123"

}

# Initial Configuration - Minimal
resource "eaa_application" "update_from_minimal" {
  name        = "update-from-minimal-app"
  description = "Application starting with minimal config for update testing"
  host        = "update-from-minimal.example.com"
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
    app_auth = "none"
  })
}

# Update Scenario - Add Authentication
resource "eaa_application" "update_add_auth" {
  name        = "update-add-auth-app"
  description = "Application for testing adding authentication in update"
  host        = "update-add-auth.example.com"
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
      app_groups {
        name = "SQA"
      }
    }
  }

  advanced_settings = jsonencode({
    app_auth = "saml"
  })

  saml_settings {
    idp {
      self_signed = true
    }
  }
}

# Update Scenario - Change App Type
resource "eaa_application" "update_change_type" {
  name        = "update-change-type-app"
  description = "Application for testing app type changes"
  host        = "update-change-type.example.com"
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
    app_auth = "none"
  })
}

# Update Scenario - Modify Advanced Settings
resource "eaa_application" "update_modify_settings" {
  name        = "update-modify-settings-app"
  description = "Application for testing advanced settings modifications"
  host        = "update-modify-settings.example.com"
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
    app_auth = "none"
    websocket_enabled = "true"
    logging_enabled = "true"
    hidden_app = "false"
    sticky_agent = "true"
  })
}

