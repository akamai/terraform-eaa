provider "eaa" {
  contractid = "test-contract"
}

# This will be used for import testing
resource "eaa_connector_pool" "import_test" {
  name         = "imported-connector-pool"
  description  = "Connector pool imported from existing infrastructure"
  package_type = "vmware"
}

