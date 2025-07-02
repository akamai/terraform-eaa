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

resource "eaa_registration_token" "example" {
  name                  = "test_new_11_different_1_unique_20240702_19300"
  max_use               = 10
  expires_at            = "2025-12-31T23:59:59.000Z"
  connector_pool        = eaa_connector_pool.new_pool.id
  generate_embedded_img = true
}

# Registration token resource that references the connector pool directly
resource "eaa_registration_token" "example_from_state" {
  name                  = "test_from_tfstate_unique_2_unique_20240702_19300"
  max_use               = 5
  expires_at            = "2025-12-31T23:59:59.000Z"
  connector_pool        = eaa_connector_pool.new_pool.id
  generate_embedded_img = true
}

