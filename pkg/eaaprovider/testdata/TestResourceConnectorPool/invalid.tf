provider "eaa" {
  contractid = "test-contract"
}

# Test error scenario - invalid package_type
resource "eaa_connector_pool" "test" {
  name         = "test-pool"
  package_type = "invalid_package"  # Invalid package type
}

