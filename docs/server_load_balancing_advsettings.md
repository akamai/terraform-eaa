# Server Load Balancing Parameters

Configure how traffic is distributed across multiple application servers.

* `load_balancing_metric` - (Optional) Load balancing algorithm. Allowed values: "round-robin", "ip-hash", "least-conn", "weighted-rr"
* `session_sticky` - (Optional) Enable session stickiness. Allowed values: "true", "false". Default "false"
* `cookie_age` - (Optional) Cookie age in seconds when session_sticky is enabled. Not supported for tunnel apps
* `tcp_optimization` - (Optional) Enable TCP optimization. Only available for tunnel apps

## Example
```json
{
  "load_balancing_metric": "round-robin",
  "session_sticky": "false",
  "cookie_age": 3600
}
```

Example file: [examples/custom_http_app.tf](../examples/custom_http_app.tf)
