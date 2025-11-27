
provider "eaa" {
  contractid = "test-contract-123"

}

# Import Scenario - Enterprise Application
# This represents an existing application that will be imported
# terraform import eaa_application.import_enterprise <app-uuid>
resource "eaa_application" "import_enterprise" {
  name        = "import-enterprise-app"
  description = "Enterprise application for import testing"
  host        = "import-enterprise.example.com"
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

# Import Scenario - Tunnel Application
# terraform import eaa_application.import_tunnel <app-uuid>
resource "eaa_application" "import_tunnel" {
  name        = "import-tunnel-app"
  description = "Tunnel application for import testing"
  host        = "import-tunnel"
  app_profile = "tcp"
  app_type    = "tunnel"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "tcp"
    origin_port     = 3306
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
    is_ssl_verification_enabled = "false"
    health_check_type = "TCP"
  })
}

# Import Scenario - Bookmark Application
# terraform import eaa_application.import_bookmark <app-uuid>
resource "eaa_application" "import_bookmark" {
  name        = "import-bookmark-app"
  description = "Bookmark application for import testing"
  host        = "import-bookmark.example.com"
  app_profile = "http"
  app_type    = "bookmark"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  bookmark_url = "https://example.com"
  
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
}

# Import Scenario - SaaS Application
# terraform import eaa_application.import_saas <app-uuid>
resource "eaa_application" "import_saas" {
  name        = "import-saas-app"
  description = "SaaS application for import testing"
  host        = "import-saas.example.com"
  app_profile = "http"
  app_type    = "saas"
  protocol    = "OpenID Connect 1.0"
}

