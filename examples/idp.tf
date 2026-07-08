# EAA Identity Provider (IDP) Examples
# Demonstrates basic IDP creation, MFA, SAML, and directory association.

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

# --- Basic IDP with Directory Association ---
resource "eaa_idp" "corp_idp" {
  name        = "Corp IDP"
  description = "Corporate identity provider"
  idp_type    = 2
  login_host  = "corp-login"
  pop         = "us-east-pop"

  cookie_expiry = 120
  trust_expiry  = 365

  directories = ["Cloud Directory"]

  settings = {
    force_login       = "true"
    force_login_after = "7200"
    captive_portal    = "true"
  }
}

# --- IDP with MFA and Login Lockout ---
resource "eaa_idp" "secure_idp" {
  name        = "Secure IDP"
  description = "IDP with MFA and lockout policies"
  idp_type    = 2
  login_host  = "secure-login"
  pop         = "us-west-pop"

  login_lockout      = "true"
  max_login_failures = 5
  lockout_interval   = 30
  cookie_expiry      = 60
  trust_expiry       = 180

  enable_mfa = true

  mfa_settings = {
    duo_enabled   = "true"
    totp_enabled  = "true"
    email_enabled = "true"
  }

  directories = ["Corporate LDAP", "Cloud Directory"]
}

# --- IDP with Custom Certificates ---
resource "eaa_idp" "custom_cert_idp" {
  name       = "Custom Cert IDP"
  idp_type   = 2
  login_host = "custom-login"
  pop        = "eu-west-pop"

  cert        = "valid-cert-name"
  client_cert = "client-auth-cert"

  cookie_expiry = 90
  trust_expiry  = 365
}

# --- IDP with SAML Configuration ---
resource "eaa_idp" "saml_idp" {
  name        = "SAML IDP"
  description = "IDP with SAML authentication"
  idp_type    = 2
  login_host  = "saml-login"
  pop         = "us-east-pop"

  saml_url                  = "https://saml.example.com/sso"
  logout_url                = "https://saml.example.com/logout"
  saml_cert_type            = 2
  saml_idp_custom_sign_cert = "saml-signing-cert"
  auth_request_signed       = true
  auth_response_encrypt     = true

  cookie_expiry = 120
  trust_expiry  = 365

  attribute_map = {
    email      = "urn:oid:0.9.2342.19200300.100.1.3"
    first_name = "urn:oid:2.5.4.42"
    last_name  = "urn:oid:2.5.4.4"
  }

  directories = ["Cloud Directory"]
}

# --- Discover Available Directories ---
data "eaa_data_source_directories" "all" {}

output "directory_names" {
  value = [for d in data.eaa_data_source_directories.all.directories : d.name]
}

output "cloud_directories" {
  value = [
    for d in data.eaa_data_source_directories.all.directories :
    d.name if d.service == 6
  ]
}

# --- IDP with Dynamically Discovered Directories ---
resource "eaa_idp" "dynamic_idp" {
  name       = "Dynamic IDP"
  idp_type   = 2
  login_host = "dynamic-login"
  pop        = "us-east-pop"

  cookie_expiry = 120
  trust_expiry  = 365

  # Associate all Cloud Directories
  directories = [
    for d in data.eaa_data_source_directories.all.directories :
    d.name if d.service == 6
  ]
}

# --- IDP with Custom Post-Auth/Logout Redirects ---
resource "eaa_idp" "custom_redirect_idp" {
  name       = "Custom Redirect IDP"
  idp_type   = 2
  login_host = "redirect-login"
  pop        = "us-east-pop"

  cookie_expiry = 120
  trust_expiry  = 365

  post_auth_failure_redirect_type       = "custom"
  post_auth_failure_redirect_custom_url = "https://support.example.com/auth-failed"

  post_logout_redirect_type       = "custom"
  post_logout_redirect_custom_url = "https://www.example.com"

  helpdesk_email = "support@example.com"
}

# --- Outputs ---
output "corp_idp_uuid" {
  value = eaa_idp.corp_idp.uuid_url
}

output "corp_idp_login_url" {
  value = eaa_idp.corp_idp.login_cname
}

output "secure_idp_directory_count" {
  value = eaa_idp.secure_idp.directory_count
}
