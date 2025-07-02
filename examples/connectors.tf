terraform {
    required_providers {
        eaa = {
            source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
            version = "1.0.0"
        }
    }
}

provider "eaa" {
    contractid       = "XX"
    edgerc           = ".edgerc"
}

resource "eaa_connector" "sample_connector" {
  provider = eaa

  name        = "sample_connector"
  description = "created using terraform"
  debug_channel_permitted = true
  package = "aws_classic"
  advanced_settings {
  network_info = ["0.0.0.0"]
  }
}
