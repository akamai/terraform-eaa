provider "eaa" {
  contractid = "test-contract"
}

resource "eaa_application" "test" {
  name        = "test-application-updated"
  description = "Updated test application"
  app_profile = "http"
  app_type    = "bookmark"
  host        = "updated.example.com"
}
