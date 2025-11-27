provider "eaa" {
  contractid = "test-contract"
}

# Test error scenario - invalid configuration
resource "eaa_application" "test" {
  name = "" # Empty name should cause validation error
}
