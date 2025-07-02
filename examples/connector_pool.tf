terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "1.0.0"
    }
  }
}

provider "eaa" {
    contractid       = "XXXXXXX"
    edgerc           = ".edgerc"
}

resource "eaa_connector_pool" "new_pool" {
  name          = "june24_conn94_20241202_1300"
  package_type  = 1
  description   = "test"
}

# Outputs for reading from tfstate
output "connector_pool_uuid" {
  description = "UUID of the created connector pool"
  value       = eaa_connector_pool.new_pool.id
}

