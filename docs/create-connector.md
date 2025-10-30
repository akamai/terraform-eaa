# Create a Connector

This guide shows how to create an EAA Connector using Terraform.

## Prerequisites
- Terraform provider configured (`provider "eaa" { ... }`).
- Appropriate credentials in your `.edgerc` and `contractid`.

## Minimal Example
See `examples/connectors.tf` for a complete working example.

## Key Arguments
- `name` (Required): Connector name.
- `description` (Optional): Free-text description.
- `debug_channel_permitted` (Optional): Enable debug channel for support.
- `package` (Required): Installer package flavor, e.g. `aws_classic`, `vmware`, etc.
- `advanced_settings.network_info` (Optional): List of CIDRs/IPs used during install/registration.


## See Also
- Connector Pool reference and advanced usage: `docs/connector-pool.md`
- Examples: `examples/connectors.tf`, `examples/connector_pool.tf`
