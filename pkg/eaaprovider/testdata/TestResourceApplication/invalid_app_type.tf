provider "eaa" {
  contractid = "test-contract"
}

# Test error scenario - invalid app_type
resource "eaa_application" "test" {
  name        = "test-app"
  app_type    = "invalid_type"  # Invalid app type
  app_profile = "http"
  host        = "test.example.com"
}

