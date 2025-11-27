# This test file is based on examples/kerberos_application.tf
# Differences: Uses test values (test-agent-01, test-idp) instead of real values
# Purpose: Unit test fixture for Kerberos authentication scenarios


provider "eaa" {
  contractid = "test-contract-123"

}

# Basic Kerberos Authentication Application
resource "eaa_application" "kerberos_basic" {
  name        = "kerberos-basic-app"
  description = "Kerberos authentication application"
  host        = "kerberos-basic.example.com"
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
  # Note: Kerberos apps don't use app_authentication blocks
  # Kerberos authentication is configured via advanced_settings.app_auth

  advanced_settings = jsonencode({
    app_auth = "kerberos"
    app_auth_domain = "EXAMPLE.COM"
    app_client_cert_auth = "false"
    forward_ticket_granting_ticket = "false"
    keytab = ""
    service_principle_name = "HTTP/kerberos-basic.example.com"
  })
}

# Kerberos Authentication Application with Client Certificate Auth
resource "eaa_application" "kerberos_client_cert" {
  name        = "kerberos-client-cert-app"
  description = "Kerberos authentication application with client certificate auth"
  host        = "kerberos-client-cert.example.com"
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
  # Note: Kerberos apps don't use app_authentication blocks
  # Kerberos authentication is configured via advanced_settings.app_auth

  advanced_settings = jsonencode({
    app_auth = "kerberos"
    app_auth_domain = "EXAMPLE.COM"
    app_client_cert_auth = "true"
    forward_ticket_granting_ticket = "true"
    keytab = ""
    service_principle_name = "HTTP/kerberos-client-cert.example.com"
  })
}

