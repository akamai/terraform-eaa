provider "eaa" {
  contractid = "test-contract"
}

# This will be used for import testing
# Note: The mock returns "test-application" as name, so we match that
resource "eaa_application" "import_test" {
  name        = "test-application"
  description = "Application imported from existing infrastructure"
  app_profile = "http"
  app_type    = "enterprise"
  host        = "test.example.com"
}
