provider "eaa" {
  contractid = "test-contract"
}

resource "eaa_application" "test" {
  name        = "test-application"
  description = "Test application"
  app_profile = "http"
  app_type    = "bookmark"
  host        = "example.com"
}
