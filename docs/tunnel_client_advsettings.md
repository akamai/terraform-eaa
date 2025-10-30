# Tunnel Client Parameters

Configure behavior specific to tunnel applications.

* `acceleration` - (Optional) Enable acceleration for tunnel apps. Allowed values: "true", "false"
* `force_ip_route` - (Optional) Force IP routing for tunnel apps. Allowed values: "true", "false"
* `x_wapp_pool_enabled` - (Optional) Enable connection pooling. Allowed values: "true", "false", "inherit"
* `x_wapp_pool_size` - (Optional) Connection pool size (1-50). Default 10
* `x_wapp_pool_timeout` - (Optional) Connection pool timeout in seconds (60-3600). Default 300
* `domain_exception_list` - (Optional) List of domains to exclude from wildcard matching

## Example (Tunnel app)
```json
{
  "acceleration": "true",
  "force_ip_route": "false",
  "x_wapp_pool_enabled": "inherit",
  "x_wapp_pool_size": 10,
  "x_wapp_pool_timeout": 300,
  "domain_exception_list": ["internal.example.com", "corp.local"]
}
```

Example file: [examples/tunnel_app.tf](../examples/tunnel_app.tf)
