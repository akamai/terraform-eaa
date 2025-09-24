# Advanced Settings Reference

This document provides comprehensive information about the `advanced_settings` parameter for EAA applications. Advanced settings allow you to configure detailed application behavior beyond the basic resource parameters.

## Overview

The `advanced_settings` parameter accepts a JSON-encoded string containing various configuration options. These settings are organized into several categories:

- Health Check Parameters
- Server Load Balancing Parameters  
- Enterprise Connectivity Parameters
- Tunnel Client Parameters
- Basic Configuration Parameters
- Authentication Parameters
- CORS Parameters
- TLS Suite Parameters
- Miscellaneous Parameters
- RDP Configuration Parameters

## Health Check Parameters

Health checks monitor the availability and responsiveness of your application servers.

### Required Fields
* `health_check_type` - (Required for tunnel apps) Type of health check. Allowed values: "Default", "HTTP", "HTTPS", "TLS", "SSLv3", "TCP", "None"

### Optional Fields
* `health_check_enabled` - (Optional) Enable health check. Default true
* `health_check_interval` - (Optional) Health check interval in seconds (1-300). Default 30
* `health_check_http_url` - (Required for HTTP/HTTPS) Health check URL
* `health_check_http_version` - (Required for HTTP/HTTPS) HTTP version. Allowed values: "1.0", "1.1", "2.0"
* `health_check_http_host_header` - (Required for HTTP/HTTPS) Host header for health check
* `health_check_http_method` - (Optional) HTTP method for health check. Default "GET"
* `health_check_http_expected_response` - (Optional) Expected HTTP response code. Default 200

## Server Load Balancing Parameters

Configure how traffic is distributed across multiple application servers.

* `load_balancing_metric` - (Optional) Load balancing algorithm. Allowed values: "round-robin", "ip-hash", "least-conn", "weighted-rr"
* `session_sticky` - (Optional) Enable session stickiness. Default false
* `cookie_age` - (Optional) Cookie age in seconds when session_sticky is enabled. Not supported for tunnel apps
* `tcp_optimization` - (Optional) Enable TCP optimization. Only available for tunnel apps

## Enterprise Connectivity Parameters

Configure connection behavior between EAA and your enterprise servers.

* `app_server_read_timeout` - (Optional) Application server read timeout in seconds (minimum 60). Default 300
* `idle_close_time_seconds` - (Optional) Idle connection close time in seconds (maximum 1800). Default 300
* `proxy_buffer_size_kb` - (Optional) Proxy buffer size in KB (4-256, multiple of 4). Default 4

## Tunnel Client Parameters

Configure behavior specific to tunnel applications.

* `acceleration` - (Optional) Enable acceleration for tunnel apps. Allowed values: "true", "false"
* `force_ip_route` - (Optional) Force IP routing for tunnel apps. Allowed values: "true", "false"
* `x_wapp_pool_enabled` - (Optional) Enable connection pooling. Allowed values: "true", "false", "inherit"
* `x_wapp_pool_size` - (Optional) Connection pool size (1-50). Default 10
* `x_wapp_pool_timeout` - (Optional) Connection pool timeout in seconds (60-3600). Default 300
* `domain_exception_list` - (Optional) List of domains to exclude from wildcard matching

## Basic Configuration Parameters

Core application configuration options.

* `is_ssl_verification_enabled` - (Optional) Enable SSL certificate verification. Default "true"
* `websocket_enabled` - (Required for tunnel apps) Enable WebSocket support. Default false
* `x_wapp_read_timeout` - (Required for tunnel apps) Read timeout in seconds. Default 300
* `ignore_cname_resolution` - (Optional) Ignore CNAME resolution for CDN access
* `g2o_enabled` - (Optional) Enable G2O configuration for Akamai Edge Enforcement
* `internal_hostname` - (Optional) Internal hostname
* `internal_host_port` - (Optional) Internal host port

## Authentication Parameters

Configure application-level authentication mechanisms.

### User-Facing Authentication (`wapp_auth`)
* `wapp_auth` - (Optional) User-facing authentication type. Allowed values: "form", "basic", "basic_cookie", "jwt", "certonly"
* `login_url` - (Optional) Login URL for authentication
* `logout_url` - (Optional) Logout URL for authentication
* `intercept_url` - (Optional) URL to intercept for authentication
* `form_post_url` - (Optional) Form post URL for authentication
* `form_post_attributes` - (Optional) Form post attributes
* `app_client_cert_auth` - (Optional) Enable client certificate authentication
* `app_cookie_domain` - (Optional) Cookie domain for SSO
* `sentry_redirect_401` - (Optional) Redirect 401 responses for session validation

### Application Authentication (`app_auth`)
* `app_auth` - (Optional) Application authentication type. Allowed values: "none", "kerberos", "basic", "NTLMv1", "NTLMv2", "SAML2.0", "wsfed", "oidc", "OpenID Connect 1.0"

### Kerberos Authentication Settings
* `app_auth_domain` - (Optional) Kerberos domain name. Default ""
* `forward_ticket_granting_ticket` - (Optional) Forward ticket granting ticket. Allowed values: "true", "false". Default "false"
* `keytab` - (Optional) Kerberos keytab file content. Default ""
* `service_principal_name` - (Optional) Service principal name. Default ""
* `kerberos_negotiate_once` - (Optional) Kerberos negotiate once setting

### JWT Authentication Settings (when `wapp_auth = "jwt"`)
* `jwt_issuers` - (Optional) JWT issuers. Default ""
* `jwt_audience` - (Optional) JWT audience. Default ""
* `jwt_grace_period` - (Optional) JWT grace period in seconds. Default "60"
* `jwt_return_option` - (Optional) JWT return option. Default "401"
* `jwt_username` - (Optional) JWT username field. Default ""
* `jwt_return_url` - (Optional) JWT return URL. Default ""

## CORS Parameters

Configure Cross-Origin Resource Sharing (CORS) behavior.

* `allow_cors` - (Optional) Enable CORS support
* `cors_origin_list` - (Optional) Space-delimited list of allowed origins
* `cors_method_list` - (Optional) Space-delimited list of allowed HTTP methods
* `cors_header_list` - (Optional) Space-delimited list of allowed headers
* `cors_support_credential` - (Optional) Support credentials in CORS requests
* `cors_max_age` - (Optional) CORS preflight cache duration in seconds

## TLS Suite Parameters

Configure TLS/SSL cipher suites and protocols.

* `tls_suite_name` - (Optional) TLS suite name for custom configuration
* `tls_cipher_suite` - (Optional) TLS cipher suite for custom configuration

## Miscellaneous Parameters

Various application behavior settings.

* `custom_headers` - (Optional) Custom headers to insert and forward
* `hidden_app` - (Optional) Hide application from user interface
* `offload_onpremise_traffic` - (Optional) Offload on-premise traffic
* `logging_enabled` - (Optional) Enable application logging
* `saas_enabled` - (Optional) Enable SaaS mode
* `segmentation_policy_enable` - (Optional) Enable segmentation policy
* `sticky_agent` - (Optional) Route requests to same connector

## RDP Configuration Parameters

Configure Remote Desktop Protocol settings for RDP applications.

* `rdp_audio_redirection` - (Optional) Enable RDP audio redirection
* `rdp_clipboard_redirection` - (Optional) Enable RDP clipboard redirection
* `rdp_disk_redirection` - (Optional) Enable RDP disk redirection
* `rdp_printer_redirection` - (Optional) Enable RDP printer redirection
* `rdp_initial_program` - (Optional) RDP initial program
* `rdp_tls1` - (Optional) Enable RDP TLS 1.0
* `remote_spark_recording` - (Optional) Enable remote Spark recording
* `remote_spark_printer` - (Optional) Enable remote Spark printer
* `remote_spark_disk` - (Optional) Enable remote Spark disk
* `rdp_keyboard_lang` - (Optional) RDP keyboard language
* `rdp_remote_apps` - (Optional) RDP remote applications

## Validation Rules

### Authentication Method Conflicts
* When `saml = true`, `oidc = true`, or `wsfed = true` at the resource level, `app_auth` in `advanced_settings` must be set to "none"
* These authentication methods are mutually exclusive with `app_auth` values other than "none"

### Kerberos Settings Validation
* Kerberos settings are only applicable when `app_auth = "kerberos"`
* `app_client_cert_auth` and `forward_ticket_granting_ticket` must be either "true" or "false"

### JWT Settings Validation
* JWT settings are only applicable when `wapp_auth = "jwt"`
* `jwt_grace_period` and `jwt_return_option` are numeric values sent as strings
* All JWT fields are optional with default values

### Certificate Only Constraints
* When `wapp_auth = "certonly"`, `app_auth` can only be "none", "kerberos", or "oidc"

## Example Usage

### Basic Advanced Settings
```hcl
advanced_settings = jsonencode({
  # Health Check
  health_check_type = "HTTP"
  health_check_enabled = true
  health_check_interval = 30
  health_check_http_url = "https://example.com/health"
  health_check_http_version = "1.1"
  health_check_http_host_header = "example.com"
  
  # Server Load Balancing
  load_balancing_metric = "round-robin"
  session_sticky = true
  cookie_age = 3600
  
  # Enterprise Connectivity
  app_server_read_timeout = "300"
  idle_close_time_seconds = "600"
  proxy_buffer_size_kb = "8"
  
  # Basic Configuration
  is_ssl_verification_enabled = "true"
  ignore_cname_resolution = "false"
  g2o_enabled = "true"
})
```

### Authentication Settings
```hcl
advanced_settings = jsonencode({
  # User-facing authentication
  wapp_auth = "basic"
  login_url = "https://example.com/login"
  logout_url = "https://example.com/logout"
  
  # Application authentication
  app_auth = "kerberos"
  app_auth_domain = "EXAMPLE.COM"
  service_principal_name = "HTTP/app.example.com"
  keytab = ""
  forward_ticket_granting_ticket = "false"
})
```

### JWT Authentication
```hcl
advanced_settings = jsonencode({
  wapp_auth = "jwt"
  jwt_issuers = "https://auth.example.com"
  jwt_audience = "my-app"
  jwt_grace_period = "90"
  jwt_return_option = "401"
  jwt_username = "sub"
  jwt_return_url = "https://app.example.com/return"
})
```

### CORS Configuration
```hcl
advanced_settings = jsonencode({
  allow_cors = true
  cors_origin_list = "https://app1.example.com https://app2.example.com"
  cors_method_list = "GET POST PUT DELETE"
  cors_header_list = "Content-Type Authorization"
  cors_support_credential = true
  cors_max_age = 3600
})
```

### RDP Configuration
```hcl
advanced_settings = jsonencode({
  rdp_audio_redirection = true
  rdp_clipboard_redirection = true
  rdp_disk_redirection = false
  rdp_printer_redirection = true
  rdp_initial_program = "notepad.exe"
  rdp_tls1 = false
})
```

## Error Messages

### Health Check Validation Errors
* `ErrHealthCheckTypeUnsupported`: "health_check_type must be one of: Default, HTTP, HTTPS, TLS, SSLv3, TCP, None"
* `ErrHealthCheckHTTPURLRequired`: "health_check_http_url is required when health_check_type is HTTP/HTTPS"
* `ErrHealthCheckHTTPVersionRequired`: "health_check_http_version is required when health_check_type is HTTP/HTTPS"
* `ErrHealthCheckHTTPHostHeaderRequired`: "health_check_http_host_header is required when health_check_type is HTTP/HTTPS"

### Server Load Balancing Validation Errors
* `ErrLoadBalancingMetricUnsupported`: "load_balancing_metric must be one of: round-robin, ip-hash, least-conn, weighted-rr"
* `ErrSessionStickyInvalid`: "session_sticky must be a boolean"
* `ErrCookieAgeRequired`: "cookie_age must be a number when session_sticky is enabled"
* `ErrCookieAgeNotSupportedTunnel`: "cookie_age is not supported for tunnel apps"

### Tunnel Client Parameters Validation Errors
* `ErrAccelerationInvalidValue`: "acceleration must be 'true' or 'false'"
* `ErrForceIPRouteInvalidValue`: "force_ip_route must be 'true' or 'false'"
* `ErrXWappPoolEnabledInvalidValue`: "x_wapp_pool_enabled must be one of: 'true', 'false', 'inherit'"
* `ErrXWappPoolSizeOutOfRange`: "x_wapp_pool_size must be between 1 and 50"
* `ErrXWappPoolTimeoutOutOfRange`: "x_wapp_pool_timeout must be between 60 and 3600 seconds"

### Enterprise Connectivity Validation Errors
* `ErrAppServerReadTimeoutTooLow`: "app_server_read_timeout must be at least 60 seconds"
* `ErrIdleCloseTimeTooHigh`: "idle_close_time_seconds cannot exceed 1800 seconds (30 minutes)"
* `ErrProxyBufferSizeOutOfRange`: "proxy_buffer_size_kb must be between 4 and 256 KB"
* `ErrProxyBufferSizeNotMultipleOf4`: "proxy_buffer_size_kb must be a multiple of 4"

### Miscellaneous Parameters Validation Errors
* `ErrAllowCorsNotAvailableForTunnel`: "allow_cors is not available for tunnel applications"
* `ErrHiddenAppNotAvailableForTunnel`: "hidden_app is not available for tunnel applications"
* `ErrXWappReadTimeoutOnlyForTunnel`: "x_wapp_read_timeout is only available for tunnel applications"
* `ErrOffloadOnpremiseTrafficNotBoolean`: "offload_onpremise_traffic must be a boolean"

### RDP Configuration Validation Errors
* `ErrRDPNotSupportedForAppType`: "RDP configuration parameters are not supported for this app type. RDP configuration is only available for Enterprise Hosted applications"
* `ErrRDPNotSupportedForProfile`: "RDP configuration parameters are not supported for this app profile. RDP configuration is only available for RDP applications"
* `ErrRDPPrinterRequiresMapPrinter`: "remote_spark_printer requires remote_spark_mapPrinter to be enabled"
* `ErrRDPDiskRequiresMapDisk`: "remote_spark_disk requires remote_spark_mapDisk to be enabled"
