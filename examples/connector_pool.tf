terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.1.0"
    }
  }
}

provider "eaa" {
  contractid = "XXXXXXX"
  edgerc     = ".edgerc"
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

  # Apps assigned to this connector pool
  apps = [
    "jira",
  ]

  # Registration tokens for the pool

  registration_tokens {
    name                  = "token-1"
    max_use               = 5
    expires_at            = "2030-01-01T00:00:01Z"
    generate_embedded_img = false
  }
  registration_tokens {
    name                  = "token-3"
    max_use               = 5
    expires_at            = "2030-02-01T00:00:01Z"
    generate_embedded_img = false
  }
}



# Example: CPAG connector pool
# When using infra_type = "cpag", operating_mode must be "cpag_public" or "cpag_private".
# Incompatible combinations will be rejected by the EAA API.
resource "eaa_connector_pool" "cpag_example" {
  name           = "cpag-pool"
  package_type   = "vmware"
  description    = "CPAG connector pool created using terraform"
  infra_type     = "cpag"
  operating_mode = "cpag_public"

  connectors = [
    "sample_connector"
  ]

  registration_tokens {
    name                  = "cpag-token-1"
    max_use               = 5
    expires_at            = "2030-01-01T00:00:01Z"
    generate_embedded_img = false
  }
}

# Example: Get all connector pools and output their names
data "eaa_connector_pools" "all" {}

output "connector_pool_names" {
  value = [for pool in data.eaa_connector_pools.all.connector_pools : pool.name]
}

output "connector_pool_details" {
  value = [for pool in data.eaa_connector_pools.all.connector_pools : {
    name           = pool.name
    uuid_url       = pool.uuid_url
    infra_type     = pool.infra_type
    operating_mode = pool.operating_mode
    connectors     = [for c in pool.connectors : c.name]
  }]
}

# Example: Get all agents (connectors) and output their details
data "eaa_data_source_agents" "all" {}

output "agent_names" {
  value = [for agent in data.eaa_data_source_agents.all.agents : agent.name]
}

output "agent_details" {
  value = [for agent in data.eaa_data_source_agents.all.agents : {
    name                = agent.name
    uuid_url            = agent.uuid_url
    connector_pool_name = agent.connector_pool_name
    reach               = agent.reach # 1=reachable, 0=unreachable
    state               = agent.state # 0=not_created, 1=created, 2=not_installed, 3=not_verified, 4=verified, 5=unenrolled, 6=enrolled, 7=not_configured, 8=configured
    public_ip           = agent.public_ip
    private_ip          = agent.private_ip
  }]
}

# Example: Get all apps and output their names
data "eaa_data_source_apps" "all" {}

output "app_names" {
  value = [for app in data.eaa_data_source_apps.all.apps : app.name]
}

output "app_details" {
  value = [for app in data.eaa_data_source_apps.all.apps : {
    name     = app.name
    uuid_url = app.uuid_url
  }]
}
