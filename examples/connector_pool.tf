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


# Consolidated connector pool resource that handles everything
resource "eaa_connector_pool" "example" {
  name         = "connec-pool"
  package_type = "vmware"
  description  = "created using terraform"
  
  # Connectors in the pool
  connectors = [
    "sample_connector"
  ]
  
  # Apps assigned to this connector pool (commented out as no apps are available)
  apps = [
      "jira",
  #    "JIRA Application"
  ]
  
  # Registration tokens for the pool
  
  registration_tokens {
    name                  = "token-1"
    max_use               = 5
    expires_in_days       = 1
    generate_embedded_img = false
  }
  registration_tokens {
    name                  = "token-3"
    max_use               = 5
    expires_in_days       = 2
    generate_embedded_img = false
  }
}




# Example: Get all connector pools
#data "eaa_connector_pools" "all" {
  # Optional filters can be added here
#}

# Example: Get agents (connectors)
#data "eaa_data_source_agents" "all" {
  # Optional filters can be added here
#}

#Example: Get all apps (you can use this to see available app names)
#data "eaa_data_source_apps" "all" {
   # This will return all apps in your tenant
#}




