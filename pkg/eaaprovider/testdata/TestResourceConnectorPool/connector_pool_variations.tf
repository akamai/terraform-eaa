provider "eaa" {
  contractid = "test-contract-123"
}

# Connector Pool with Minimal Configuration
resource "eaa_connector_pool" "minimal" {
  name         = "test-pool-minimal"
  package_type = "vmware"
  infra_type   = "eaa"
  operating_mode = "connector"
}

# Connector Pool with All Fields
resource "eaa_connector_pool" "comprehensive" {
  name         = "test-pool-comprehensive"
  description  = "Comprehensive connector pool with all fields"
  package_type = "vmware"
  infra_type   = "eaa"
  operating_mode = "connector"
  
  registration_tokens {
    name                  = "token-1"
    max_use               = 5
    expires_in_days       = 1
    generate_embedded_img = false
  }
  
  registration_tokens {
    name                  = "token-2"
    max_use               = 10
    expires_in_days       = 2
    generate_embedded_img = true
  }
}

# Connector Pool Update Scenario - Add Tokens
resource "eaa_connector_pool" "update_add_tokens" {
  name         = "test-pool-update-tokens"
  package_type = "vmware"
  infra_type   = "eaa"
  operating_mode = "connector"
  
  registration_tokens {
    name = "initial-token"
  }
}

# Connector Pool Update Scenario - Change Description
resource "eaa_connector_pool" "update_description" {
  name         = "test-pool-update-desc"
  description  = "Initial description"
  package_type = "vmware"
  infra_type   = "eaa"
  operating_mode = "connector"
}

# Connector Pool with Different Package Types
resource "eaa_connector_pool" "docker_package" {
  name         = "test-pool-docker"
  package_type = "docker"
  infra_type   = "eaa"
  operating_mode = "connector"
}

resource "eaa_connector_pool" "azure_package" {
  name         = "test-pool-azure"
  package_type = "azure"
  infra_type   = "eaa"
  operating_mode = "connector"
}

# Connector Pool with Different Operating Modes
resource "eaa_connector_pool" "peb_mode" {
  name         = "test-pool-peb"
  package_type = "vmware"
  infra_type   = "eaa"
  operating_mode = "peb"
}

resource "eaa_connector_pool" "combined_mode" {
  name         = "test-pool-combined"
  package_type = "vmware"
  infra_type   = "eaa"
  operating_mode = "combined"
}

