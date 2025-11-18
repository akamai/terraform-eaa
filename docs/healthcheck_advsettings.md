# Health Check Parameters

Health checks monitor the availability and responsiveness of your application servers.

## Required Fields
* `health_check_type` - (Required for tunnel apps) Type of health check. Allowed values: "Default", "HTTP", "HTTPS", "TLS", "SSLv3", "TCP", "None"

## Optional Fields
* `health_check_enabled` - (Optional) Enable health check. Allowed values: "true", "false". Default "true"
* `health_check_interval` - (Optional) Health check interval in seconds (1-300). Default 30
* `health_check_http_url` - (Required for HTTP/HTTPS) Health check URL
* `health_check_http_version` - (Required for HTTP/HTTPS) HTTP version. Allowed values: "1.0", "1.1", "2.0"
* `health_check_http_host_header` - (Required for HTTP/HTTPS) Host header for health check
* `health_check_http_method` - (Optional) HTTP method for health check. Default "GET"
* `health_check_http_expected_response` - (Optional) Expected HTTP response code. Default 200

## Examples

See the following example files for health check configuration across different application types:

* [examples/enterprise_valid.tf](../examples/enterprise_valid.tf) - Enterprise applications with HTTP health checks, including comprehensive configuration with `health_check_type`, `health_check_http_url`, `health_check_http_version`, `health_check_http_host_header`, `health_check_interval`, `health_check_timeout`, `health_check_rise`, and `health_check_fall`
* [examples/custom_http_app.tf](../examples/custom_http_app.tf) - Custom HTTP application demonstrating HTTP health check configuration with all HTTP-specific parameters
* [examples/tunnel_app.tf](../examples/tunnel_app.tf) - Tunnel application with TCP health check configuration (`health_check_type = "TCP"`)
* [examples/tcp_app.tf](../examples/tcp_app.tf) - TCP tunnel application demonstrating TCP health check for tunnel app types
* [examples/tunnel_valid.tf](../examples/tunnel_valid.tf) - Valid tunnel application example with TCP health check configuration
