# Enterprise HTTP Applications
# Akamai domain, custom domain (self-signed and uploaded cert), CORS, ACL rules.

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.1.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

# --- Akamai-domain app with advanced settings and ACL rules ---
resource "eaa_application" "jira_app" {
  name            = "JIRA Application"
  description     = "Web-based JIRA app behind EAA"
  host            = "jira-app"
  app_profile     = "http"
  app_type        = "enterprise"
  domain          = "wapp"
  client_app_mode = "tcp"
  app_category    = "Development"
  popregion       = "us-east-1"
  agents          = ["EAA_DC1_US1_Access_01"]

  servers {
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "jira-app.example.com"
  }

  advanced_settings = {
    app_auth        = "basic"
    wapp_auth       = "form"
    app_auth_domain = "example.com"

    # CORS: required when the front-end SPA is on a different origin than the EAA hostname
    allow_cors              = "true"
    cors_origin_list        = "https://spa.example.com,https://admin.example.com"
    cors_method_list        = "GET,POST,PUT,DELETE"
    cors_header_list        = "Content-Type,Authorization,X-Request-ID"
    cors_max_age            = "3600"
    cors_support_credential = "on"

    # Health check
    health_check_type             = "HTTP"
    health_check_http_url         = "/"
    health_check_http_version     = "1.1"
    health_check_http_host_header = "jira-app.example.com"
    health_check_interval         = "30000"
    health_check_timeout          = "50000"
    health_check_rise             = "2"
    health_check_fall             = "3"

    # Load balancing and session stickiness
    load_balancing_metric        = "round-robin"
    session_sticky               = "true"
    session_sticky_cookie_maxage = "3600"
    session_sticky_server_cookie = "session_cookie"

    # Connection pool tuning
    idle_conn_floor         = "50"
    idle_conn_ceil          = "75"
    idle_conn_step          = "10"
    idle_close_time_seconds = "1200"
    app_server_read_timeout = "60"

    # Security and misc
    hsts_age          = "15552000"
    http_only_cookie  = "true"
    websocket_enabled = "false"
    logging_enabled   = "true"
    hidden_app        = "false"
    saas_enabled      = "false"
    sticky_agent      = "false"

    # custom_headers must be a jsonencode'd list; each entry needs attribute_type + header + attribute
    custom_headers = jsonencode([
      {
        attribute_type = "custom"
        header         = "X-Upstream-Token"
        attribute      = "secret-value"
      },
      {
        attribute_type = "user"
        header         = "X-Authenticated-User"
        attribute      = ""
      }
    ])
  }

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

  # ACL service rules: each access_rule is an OR group; rules within are ANDed
  service {
    service_type = "access"
    status       = "on"
    access_rule {
      name   = "eng-access"
      status = "on"
      rule {
        operator = "=="
        type     = "group"
        value    = "Engineering"
      }
      rule {
        operator = "=="
        type     = "user"
        value    = "admin@example.com"
      }
    }
    access_rule {
      name   = "url-gate"
      status = "on"
      rule {
        operator = "=="
        type     = "url"
        value    = "/api/*"
      }
    }
  }
}

# --- Custom domain with self-signed certificate ---
# cert_type options: "self_signed" (auto-generated), "uploaded" (bring your own)
resource "eaa_application" "custom_domain_self_signed" {
  name            = "Internal Portal (Self-Signed)"
  description     = "Enterprise app on a custom domain with auto-generated cert"
  host            = "portal.internal.example.com"
  app_profile     = "http"
  app_type        = "enterprise"
  client_app_mode = "tcp"
  popregion       = "us-east-1"
  agents          = ["EAA_DC1_US1_Access_01"]

  domain    = "custom"
  cert_type = "self_signed"

  servers {
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "origin.internal.example.com"
  }

  advanced_settings = {
    is_ssl_verification_enabled = "false"
    ignore_cname_resolution     = "true"
    g2o_enabled                 = "true"
    edge_authentication_enabled = "true"
  }

  auth_enabled = "true"

  app_authentication {
    app_idp = "employees-idp"

    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Portal-Users"
      }
    }
  }
}

# --- Custom domain with uploaded certificate ---
resource "eaa_application" "custom_domain_uploaded_cert" {
  name            = "Partner Portal (Uploaded Cert)"
  description     = "Enterprise app on a custom domain with pre-provisioned certificate"
  host            = "partners.example.com"
  app_profile     = "http"
  app_type        = "enterprise"
  client_app_mode = "tcp"
  popregion       = "us-east-1"
  agents          = ["EAA_DC1_US1_Access_01"]

  domain    = "custom"
  cert_type = "uploaded"
  cert_name = "wildcard-example-com-2026"

  servers {
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "origin.partners.example.com"
  }

  advanced_settings = {
    is_ssl_verification_enabled = "false"
    ignore_cname_resolution     = "true"
    g2o_enabled                 = "true"
    edge_authentication_enabled = "true"
  }

  auth_enabled = "true"

  app_authentication {
    app_idp = "employees-idp"

    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "Partner-Admins"
      }
    }
  }
}
