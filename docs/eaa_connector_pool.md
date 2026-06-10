# eaa_connector_pool

Manages the lifecycle of an EAA connector pool, including connectors, registration tokens, and application assignments.

## Argument Reference

* `name` - (Required) Pool name.
* `description` - (Optional) Pool description.
* `package_type` - (Required) Package type: `vmware`, `vbox`, `aws`, `kvm`, `hyperv`, `docker`, `azure`, `google`, `softlayer`, `fujitsu_k5`.
* `infra_type` - (Optional) Infrastructure type: `eaa`, `unified`, `broker`, `cpag`.
* `operating_mode` - (Optional) Operating mode: `connector`, `peb`, `combined`, `cpag_public`, `cpag_private`, `connector_with_china_acceleration`.
* `connectors` - (Optional) List of connector names in the pool.
* `apps` - (Optional) List of app names assigned to this pool.
* `registration_tokens` - (Optional) List of registration tokens:
  * `name` - (Required) Token name.
  * `max_use` - (Optional) Max uses (1-1000). Default `1`.
  * `expires_at` - (Required) Expiration in RFC3339 format (e.g. `2030-01-01T00:00:01Z`). Zero-second values (`:00`) are bumped to `:01`.
  * `generate_embedded_img` - (Optional) Generate embedded image. Default `false`.

`infra_type = "cpag"` requires `operating_mode` to be `cpag_public` or `cpag_private`, and vice versa. Incompatible combinations are rejected at apply time.

## Computed Attributes

* `uuid_url` - Pool UUID.
* `cidrs` - CIDRs from API.
* Registration token computed fields: `uuid_url`, `connector_pool`, `agents`, `expires_at`, `image_url`, `token`, `used_count`, `token_suffix`, `modified_at`.

## Example

```hcl
resource "eaa_connector_pool" "main" {
  name         = "main-pool"
  package_type = "vmware"
  description  = "Primary connector pool"

  connectors = ["dc1-connector", "dc2-connector"]
  apps       = ["web-app", "sap-tunnel"]

  registration_tokens {
    name       = "onboard-token"
    max_use    = 5
    expires_at = "2030-01-01T00:00:01Z"
  }
}
```

### CPAG Pool

```hcl
resource "eaa_connector_pool" "cpag" {
  name           = "cpag-pool"
  package_type   = "vmware"
  infra_type     = "cpag"
  operating_mode = "cpag_public"

  registration_tokens {
    name       = "cpag-token"
    max_use    = 5
    expires_at = "2030-01-01T00:00:01Z"
  }
}
```

See [examples/connector_pool.tf](../examples/connector_pool.tf) for pools with connectors, tokens, app assignments, and data source usage.
