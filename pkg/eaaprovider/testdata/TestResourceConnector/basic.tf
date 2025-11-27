# This test file is based on examples/connectors.tf
# Differences: Uses test values (test-contract-123) instead of real values
# Purpose: Unit test fixture for connector resource scenarios

provider "eaa" {
  contractid = "test-contract-123"
}

resource "eaa_connector" "test" {
  name        = "test-connector"
  description = "Test EAA connector created by unit tests"
  debug_channel_permitted = true
  package = "aws_classic"
  
  advanced_settings {
    network_info = ["192.168.1.0/24"]
  }
}
