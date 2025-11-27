provider "eaa" {
  contractid = "test-contract"
}

# Test basic application - using a resource since there's no eaa_data_source_apps
# This demonstrates how to test data sources
resource "eaa_application" "test" {
  name        = "test-application"
  app_profile = "http"
  app_type    = "bookmark"
  host        = "example.com"
}
