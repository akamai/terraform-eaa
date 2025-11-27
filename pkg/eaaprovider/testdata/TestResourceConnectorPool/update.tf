provider "eaa" {
  contractid = "test-contract-123"
}

# Connector Pool - Updated Configuration
resource "eaa_connector_pool" "test" {
  name         = "updated-connector-pool"
  package_type = "aws"
  description  = "Updated test connector pool"
  
  # Updated connectors in the pool
  connectors = [
    "test-connector-01",
    "test-connector-02"
  ]
  
  # Updated apps assigned to this connector pool
  apps = [
    "test-app-01",
    "test-app-02"
  ]
  
  # Updated registration tokens
  registration_tokens {
    name                  = "token-1"
    max_use               = 10
    expires_in_days       = 2
    generate_embedded_img = true
  }
  
  registration_tokens {
    name                  = "token-2"
    max_use               = 3
    expires_in_days       = 5
    generate_embedded_img = false
  }
}

