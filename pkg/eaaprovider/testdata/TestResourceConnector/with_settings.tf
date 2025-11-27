provider "eaa" {
  contractid = "test-contract-123"
}

resource "eaa_connector" "test" {
  name        = "test-connector-with-settings"
  description = "Test EAA connector with advanced settings"
  package     = "vmware"
  
  # Add more complex configuration for testing updates
  # host = "192.168.1.100"
  # port = 2222
  # status = "active"
  # advanced_settings {
  #   timeout = 30
  #   retries = 3
  # }
}
