# EAA Connector Pool Management

A connector pool in EAA (Enterprise Application Access) is a logical grouping of connectors that can be used to manage access to applications. This document describes how to use the `eaa_connector_pool` resource to create and manage connector pools using Terraform.

## Resource: eaa_connector_pool

Manages the lifecycle of an EAA connector pool, including connectors, registration tokens, and application assignments.

### Argument Reference

This resource supports the following arguments:

#### Basic Configuration

* ```name``` - (Required) Name of the connector pool
* ```description``` - (Optional) Description of the connector pool. Defaults to empty string
* ```package_type``` - (Required) Package type for the connector pool. Valid values:
  * `vmware` - VMware package type
  * `vbox` - VirtualBox package type
  * `aws` - AWS package type
  * `kvm` - KVM package type
  * `hyperv` - Hyper-V package type
  * `docker` - Docker package type
  * `aws_classic` - AWS Classic package type
  * `azure` - Azure package type
  * `google` - Google Cloud package type
  * `softlayer` - SoftLayer package type
  * `fujitsu_k5` - Fujitsu K5 package type

#### Advanced Configuration

* ```infra_type``` - (Optional) Infrastructure type for the connector pool. Valid values:
  * `eaa` - EAA infrastructure
  * `unified` - Unified infrastructure
  * `broker` - Broker infrastructure
  * `cpag` - CPAG infrastructure

* ```operating_mode``` - (Optional) Operating mode for the connector pool. Valid values:
  * `connector` - Connector mode
  * `peb` - PEB mode
  * `combined` - Combined mode
  * `cpag_public` - CPAG public mode
  * `cpag_private` - CPAG private mode
  * `connector_with_china_acceleration` - Connector with China acceleration

#### Connector Management

* ```connectors``` - (Optional) List of connector names that should be in the pool
  * Type: List of strings
  * Example: `["connector1", "connector2"]`

#### Application Assignment

* ```apps``` - (Optional) List of app names that should be assigned to this connector pool
  * Type: List of strings
  * Example: `["app1", "app2"]`

#### Registration Tokens

* ```registration_tokens``` - (Optional) List of registration tokens for the connector pool
  * Type: List of objects with the following attributes:
    * ```name``` - (Required) Name of the registration token
    * ```max_use``` - (Optional) Maximum number of times the token can be used. Defaults to 1, range 1-1000
    * ```expires_in_days``` - (Optional) Number of days from now until the token expires. Defaults to 1, range 1-700
    * ```generate_embedded_img``` - (Optional) Whether to generate an embedded image for the token. Defaults to false

#### Computed Attributes

* ```uuid_url``` - (Computed) UUID URL of the connector pool
* ```cidrs``` - (Computed) CIDRs from API response
* ```registration_tokens``` - (Computed) Additional computed fields for registration tokens:
  * ```uuid_url``` - UUID URL of the registration token
  * ```connector_pool``` - Connector pool UUID
  * ```agents``` - List of agents associated with the token
  * ```expires_at``` - Expiration date in RFC3339 format
  * ```image_url``` - Image URL for the token
  * ```token``` - Token value
  * ```used_count``` - Number of times the token has been used
  * ```token_suffix``` - Token suffix
  * ```modified_at``` - Last modification timestamp

### Example Usage

#### Basic Connector Pool

```hcl
resource "eaa_connector_pool" "example" {
  name         = "my-connector-pool"
  package_type = "vmware"
  description  = "A connector pool for VMware connectors"
  
  connectors = [
    "connector1",
    "connector2"
  ]
}
```

#### Connector Pool with Registration Tokens

```hcl
resource "eaa_connector_pool" "example" {
  name         = "my-connector-pool"
  package_type = "vmware"
  description  = "A connector pool with registration tokens"
  
  connectors = [
    "connector1",
    "connector2"
  ]
  
  registration_tokens {
    name                  = "token-1"
    max_use               = 5
    expires_in_days       = 30
    generate_embedded_img = false
  }
  
  registration_tokens {
    name                  = "token-2"
    max_use               = 10
    expires_in_days       = 60
    generate_embedded_img = true
  }
}
```

#### Connector Pool with App Assignment

```hcl
resource "eaa_connector_pool" "example" {
  name         = "my-connector-pool"
  package_type = "vmware"
  description  = "A connector pool assigned to applications"
  
  connectors = [
    "connector1",
    "connector2"
  ]
  
  apps = [
    "my-app-1",
    "my-app-2"
  ]
  
  registration_tokens {
    name                  = "token-1"
    max_use               = 5
    expires_in_days       = 30
    generate_embedded_img = false
  }
}
```

#### Advanced Configuration

```hcl
resource "eaa_connector_pool" "example" {
  name           = "advanced-connector-pool"
  package_type   = "aws"
  description    = "Advanced connector pool with custom settings"
  infra_type     = "unified"
  operating_mode = "combined"
  
  connectors = [
    "aws-connector-1",
    "aws-connector-2"
  ]
  
  apps = [
    "production-app"
  ]
  
  registration_tokens {
    name                  = "prod-token"
    max_use               = 20
    expires_in_days       = 90
    generate_embedded_img = true
  }
}
```

### Data Source: eaa_connector_pools

You can also retrieve information about existing connector pools using the data source:

```hcl
# Get all connector pools
data "eaa_connector_pools" "all" {
  # Optional filters can be added here
}

# Output the connector pools
output "connector_pools" {
  value = data.eaa_connector_pools.all.connector_pools
}
```

### Workflow Examples

#### Creating a Connector Pool Step by Step

1. **Create basic pool**:
```hcl
resource "eaa_connector_pool" "basic" {
  name         = "basic-pool"
  package_type = "vmware"
  description  = "Basic connector pool"
}
```

2. **Add connectors**:
```hcl
resource "eaa_connector_pool" "with_connectors" {
  name         = "basic-pool"
  package_type = "vmware"
  description  = "Basic connector pool"
  
  connectors = [
    "connector1",
    "connector2"
  ]
}
```

3. **Add registration tokens**:
```hcl
resource "eaa_connector_pool" "with_tokens" {
  name         = "basic-pool"
  package_type = "vmware"
  description  = "Basic connector pool"
  
  connectors = [
    "connector1",
    "connector2"
  ]
  
  registration_tokens {
    name                  = "token-1"
    max_use               = 5
    expires_in_days       = 30
    generate_embedded_img = false
  }
}
```

4. **Assign applications**:
```hcl
resource "eaa_connector_pool" "complete" {
  name         = "basic-pool"
  package_type = "vmware"
  description  = "Complete connector pool"
  
  connectors = [
    "connector1",
    "connector2"
  ]
  
  apps = [
    "app1",
    "app2"
  ]
  
  registration_tokens {
    name                  = "token-1"
    max_use               = 5
    expires_in_days       = 30
    generate_embedded_img = false
  }
}
```

