
provider "eaa" {
  contractid = "test-contract-123"

}

# RDP Application with Default Settings
resource "eaa_application" "rdp_basic" {
  name        = "rdp-basic-app"
  description = "RDP application with default settings"
  host        = "rdp-basic.example.com"
  app_profile = "rdp"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "rdp"
    origin_port     = 3389
    origin_host     = "192.168.2.1"
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

# RDP Application with Custom Window Settings
resource "eaa_application" "rdp_custom_window" {
  name        = "rdp-custom-window-app"
  description = "RDP application with custom window settings"
  host        = "rdp-custom-window.example.com"
  app_profile = "rdp"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "rdp"
    origin_port     = 3389
    origin_host     = "192.168.2.1"
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
    rdp_window_width = "1920"
    rdp_window_height = "1080"
    rdp_window_color_depth = "32"
    rdp_legacy_mode = "false"
    rdp_tls1 = "true"
  })
}

# RDP Application with Remote Apps
resource "eaa_application" "rdp_remote_apps" {
  name        = "rdp-remote-apps-app"
  description = "RDP application with remote apps configuration"
  host        = "rdp-remote-apps.example.com"
  app_profile = "rdp"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "rdp"
    origin_port     = 3389
    origin_host     = "192.168.2.1"
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
    rdp_initial_program = "notepad.exe"
  })
}

