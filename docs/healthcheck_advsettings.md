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

## Example
```json
{
  "health_check_type": "HTTP",
  "health_check_enabled": "true",
  "health_check_interval": 30,
  "health_check_http_url": "/status",
  "health_check_http_version": "1.1",
  "health_check_http_host_header": "app.internal.example.com",
  "health_check_http_method": "GET",
  "health_check_http_expected_response": 200
}
```

Example file: [examples/custom_http_app.tf](../examples/custom_http_app.tf)
