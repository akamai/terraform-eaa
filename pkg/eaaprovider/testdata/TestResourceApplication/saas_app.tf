
provider "eaa" {
  contractid = "test-contract-123"

}

# SaaS Application with OIDC Protocol
resource "eaa_application" "saas_oidc" {
  name        = "saas-oidc-example"
  description = "SaaS application with OIDC authentication"
  host        = "saas-oidc.example.com"
  app_profile = "http"
  app_type    = "saas"
  protocol    = "OpenID Connect 1.0"
}

# SaaS Application with SAML Protocol
resource "eaa_application" "saas_saml" {
  name        = "saas-saml-example"
  description = "SaaS application with SAML authentication"
  host        = "saas-saml.example.com"
  app_profile = "http"
  app_type    = "saas"
  protocol    = "SAML2.0"
}

# SaaS Application with WS-Federation Protocol
resource "eaa_application" "saas_wsfed" {
  name        = "saas-wsfed-example"
  description = "SaaS application with WS-Federation authentication"
  host        = "saas-wsfed.example.com"
  app_profile = "http"
  app_type    = "saas"
  protocol    = "WS-Federation"
}
