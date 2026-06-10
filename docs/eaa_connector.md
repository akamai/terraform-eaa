# eaa_connector

Manages the lifecycle of an EAA connector.

## Argument Reference

* `name` - (Required) Connector name.
* `description` - (Optional) Description.
* `debug_channel_permitted` - (Optional) Enable debug channel for support.
* `package` - (Required) Installer package. Values: `vmware`, `vbox`, `aws`, `kvm`, `hyperv`, `docker`, `azure`, `google`, `softlayer`, `fujitsu_k5`. Note: `aws_classic` is no longer supported; use `aws`.
* `advanced_settings` - (Optional) Advanced configuration:
  * `network_info` - (Required) List of CIDRs/IPs for install/registration.

## Computed Attributes

* `uuid_url` - Connector UUID.
* `reach` - Reachability status.
* `state` - Connector state.
* `os_version` - OS version.
* `public_ip` - Public IP.
* `private_ip` - Private IP.
* `type` - Connector type.
* `region` - Region.
* `download_url` - Installer download URL.

## Example

```hcl
resource "eaa_connector" "dc1" {
  name                    = "dc1-connector"
  description             = "Data center 1 connector"
  debug_channel_permitted = true
  package                 = "aws"

  advanced_settings {
    network_info = ["10.0.0.0/8"]
  }
}
```

See [examples/connector.tf](../examples/connector.tf) for a complete working example.
