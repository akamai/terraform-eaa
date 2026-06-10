# EAA Connector
# Creates a connector VM that bridges EAA cloud to your data center network.

terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.0.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
}

resource "eaa_connector" "dc1_connector" {
  name                    = "dc1-connector-01"
  description             = "Primary connector in DC1"
  debug_channel_permitted = true
  package                 = "aws"

  advanced_settings {
    # Network ranges the connector can reach. Use CIDR notation (e.g., "10.0.0.0/16").
    # Defaults to "0.0.0.0/0" (all networks) if omitted.
    network_info = ["10.0.0.0/16"]
  }
}
