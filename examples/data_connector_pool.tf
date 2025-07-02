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


# Step 1: Use data source to get connector pool details (GID-free)
data "eaa_connector_pool" "pool_details" {
  uuid = eaa_connector_pool.new_pool.id
}

# Step 2: Use data source to get app access groups (GID-free)
data "eaa_app_access_groups" "app_groups" {
  connector_pool_uuid_url = eaa_connector_pool.new_pool.id
}

