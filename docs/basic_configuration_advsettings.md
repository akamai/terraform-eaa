# Basic Configuration Parameters

Core application configuration options.

* `is_ssl_verification_enabled` - (Optional) Enable SSL certificate verification. Default "true"
* `websocket_enabled` - (Required for tunnel apps) Enable WebSocket support. Allowed values: "true", "false". Default "false"
* `x_wapp_read_timeout` - (Required for tunnel apps) Read timeout in seconds. Default 300
* `ignore_cname_resolution` - (Optional) Ignore CNAME resolution for CDN access. Allowed values: "true", "false"
* `g2o_enabled` - (Optional) Enable G2O configuration for Akamai Edge Enforcement
* `internal_hostname` - (Optional) Internal hostname
* `internal_host_port` - (Optional) Internal host port

## Example
```json
{
  "is_ssl_verification_enabled": "true",
  "websocket_enabled": "false",
  "x_wapp_read_timeout": 300,
  "ignore_cname_resolution": "false",
  "g2o_enabled": "false",
  "internal_hostname": "app.internal.example.com",
  "internal_host_port": 8080
}
```

Example files: [examples/custom_http_app_domain.tf](../examples/custom_http_app_domain.tf), [examples/tunnel_app.tf](../examples/tunnel_app.tf)
