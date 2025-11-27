
provider "eaa" {
  contractid = "test-contract-123"

}

# Basic Authentication Application with CORS
resource "eaa_application" "basic_auth_cors" {
  name        = "basic-auth-cors-app"
  description = "Basic authentication application with CORS settings"
  host        = "basic-auth-cors.example.com"
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
    app_auth = "basic"
    allow_cors = "true"
    cors_method_list = "GET,POST,PUT,DELETE"
    cors_origin_list = "https://app.example.com,https://api.example.com"
    cors_header_list = "Content-Type,Authorization,X-Custom-Header"
    cors_max_age = "3600"
    cors_support_credential = "on"
  })
}

# Basic Authentication with Custom Headers
resource "eaa_application" "basic_auth_headers" {
  name        = "basic-auth-headers-app"
  description = "Basic authentication application with custom headers"
  host        = "basic-auth-headers.example.com"
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
    app_auth = "basic"
    custom_headers = [
      {
        attribute_type = "custom"
        header = "X-Custom-Header"
        attribute = "custom-value"
      },
      {
        attribute_type = "user"
        header = "X-User-Email"
        attribute = "user.email"
      },
      {
        attribute_type = "user"
        header = "X-User-Name"
        attribute = "user.name"
      }
    ]
  })
}


