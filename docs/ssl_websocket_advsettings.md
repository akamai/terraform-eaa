# SSL and WebSocket Configuration Parameters

SSL verification, WebSocket protocol, and connection timeout settings for advanced settings.

* `is_ssl_verification_enabled` - (Optional) Enable SSL certificate verification. Default "true"
* `websocket_enabled` - (Required for tunnel apps) Enable WebSocket support. Allowed values: "true", "false". Default "false"
* `x_wapp_read_timeout` - (Required for tunnel apps) Read timeout in seconds. Default 300
* `ignore_cname_resolution` - (Optional) Ignore CNAME resolution for CDN access. Allowed values: "true", "false"
* `g2o_enabled` - (Optional) Enable G2O configuration for Akamai Edge Enforcement
* `internal_hostname` - (Optional) Internal hostname
* `internal_host_port` - (Optional) Internal host port

## Examples

See the following example files for usage:

* [examples/tunnel_app.tf](../examples/tunnel_app.tf) - Tunnel application demonstrating `websocket_enabled`, `x_wapp_read_timeout`, `is_ssl_verification_enabled`, `internal_hostname`, and `internal_host_port`
* [examples/custom_http_app_domain.tf](../examples/custom_http_app_domain.tf) - Custom HTTP application with domain configuration showing `ignore_cname_resolution` and other core settings
