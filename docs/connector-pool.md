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

For comprehensive examples of connector pool configurations, see the [examples/](../examples/) directory in the repository.

### Examples

Refer to repository examples for working configurations:

- Basic connector pool: [examples/connector_pool.tf](../examples/connector_pool.tf)
- Pool with registration tokens: [examples/connector_pool.tf](../examples/connector_pool.tf)
- Pool with application assignment: [examples/connector_pool.tf](../examples/connector_pool.tf)
- Advanced configuration (infra_type, operating_mode): [examples/connector_pool.tf](../examples/connector_pool.tf)

### Data Source

See [examples/connector_pool.tf](../examples/connector_pool.tf) for data source usage patterns.
