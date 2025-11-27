provider "eaa" {
  contractid = "test-contract"
}

# Test error scenario - invalid app_profile for app_type
resource "eaa_application" "test" {
  name        = "test-app"
  app_type    = "enterprise"
  app_profile = "invalid_profile"  # Invalid profile
  host        = "test.example.com"
}

