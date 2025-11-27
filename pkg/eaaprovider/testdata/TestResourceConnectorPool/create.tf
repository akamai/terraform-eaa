# This test file is based on examples/connector_pool.tf
# Differences: Uses test values (test-contract-123, test-app-01) instead of real values
# Purpose: Unit test fixture for connector pool creation scenarios

provider "eaa" {
  contractid = "test-contract-123"
}

# Connector Pool - Basic Configuration
resource "eaa_connector_pool" "test" {
  name         = "test-connector-pool"
  package_type = "vmware"
  description  = "Test connector pool created by unit tests"
  
  # Connectors in the pool
  connectors = [
    "test-connector-01"
  ]
  
  # Apps assigned to this connector pool
  apps = [
    "test-app-01"
  ]
  
  # Registration tokens for the pool
  registration_tokens {
    name                  = "token-1"
    max_use               = 5
    expires_in_days       = 1
    generate_embedded_img = false
  }
  registration_tokens {
    name                  = "token-2"
    max_use               = 5
    expires_in_days       = 2
    generate_embedded_img = false
  }
}

