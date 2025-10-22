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

## Application Types and Profiles

Understanding which settings apply to your application type and profile is crucial for proper configuration:

### Enterprise Applications
Enterprise applications support the most comprehensive configuration options:

#### HTTP Profile
- **Health Check Parameters**: All types supported (HTTP, HTTPS, TCP, None)
- **Server Load Balancing Parameters**: Full support
- **Enterprise Connectivity Parameters**: Full support
- **Authentication Parameters**: All authentication methods
- **CORS Parameters**: Full CORS support
- **TLS Suite Parameters**: Custom and predefined suites
- **Miscellaneous Parameters**: All options available
- **Custom Headers**: Full support

#### RDP Profile
- **RDP Configuration Parameters**: Audio, clipboard, disk, printer redirection
- **Health Check Parameters**: TCP and None types recommended
- **Server Load Balancing Parameters**: Full support
- **Enterprise Connectivity Parameters**: Full support
- **Authentication Parameters**: Kerberos recommended
- **TLS Suite Parameters**: Custom and predefined suites
- **Miscellaneous Parameters**: Most options available

#### SSH Profile
- **Health Check Parameters**: TCP and None types recommended
- **Server Load Balancing Parameters**: Full support
- **Enterprise Connectivity Parameters**: Full support
- **Authentication Parameters**: Limited (no app_auth in advanced_settings)
- **TLS Suite Parameters**: Custom and predefined suites
- **Miscellaneous Parameters**: Most options available

#### VNC Profile
- **Health Check Parameters**: TCP and None types recommended
- **Server Load Balancing Parameters**: Full support
- **Enterprise Connectivity Parameters**: Full support
- **Authentication Parameters**: Limited (no app_auth in advanced_settings)
- **TLS Suite Parameters**: Custom and predefined suites
- **Miscellaneous Parameters**: Most options available

#### SMB Profile
- **Health Check Parameters**: TCP and None types recommended
- **Server Load Balancing Parameters**: Full support
- **Enterprise Connectivity Parameters**: Full support
- **Authentication Parameters**: Kerberos recommended
- **TLS Suite Parameters**: Custom and predefined suites
- **Miscellaneous Parameters**: Most options available

### Tunnel Applications
Tunnel applications have limited configuration options:

#### TCP Profile
- **Tunnel Client Parameters**: Required (acceleration, force_ip_route, x_wapp_pool_*)
- **Health Check Parameters**: TCP type required
- **Basic Configuration Parameters**: websocket_enabled required
- **Server Load Balancing Parameters**: Limited support
- **Enterprise Connectivity Parameters**: Limited support
- **Authentication Parameters**: Not supported in advanced_settings
- **CORS Parameters**: Not supported
- **TLS Suite Parameters**: Not supported
- **Miscellaneous Parameters**: Limited support

### Bookmark Applications
Bookmark applications have minimal configuration:

- **Advanced Settings**: Not supported at all
- **Configuration**: Resource-level parameters only

### SaaS Applications
SaaS applications have limited advanced settings:

- **Advanced Settings**: Not supported at all
- **Authentication**: Resource-level boolean flags only (saml, oidc, wsfed)

## Health Check Parameters

Health checks monitor the availability and responsiveness of your application servers.

### Required Fields
* `health_check_type` - (Required for tunnel apps) Type of health check. Allowed values: "Default", "HTTP", "HTTPS", "TLS", "SSLv3", "TCP", "None"

### Optional Fields
* `health_check_enabled` - (Optional) Enable health check. Allowed values: "true", "false". Default "true"
* `health_check_interval` - (Optional) Health check interval in seconds (1-300). Default 30
* `health_check_http_url` - (Required for HTTP/HTTPS) Health check URL
* `health_check_http_version` - (Required for HTTP/HTTPS) HTTP version. Allowed values: "1.0", "1.1", "2.0"
* `health_check_http_host_header` - (Required for HTTP/HTTPS) Host header for health check
* `health_check_http_method` - (Optional) HTTP method for health check. Default "GET"
* `health_check_http_expected_response` - (Optional) Expected HTTP response code. Default 200

## Server Load Balancing Parameters

Configure how traffic is distributed across multiple application servers.

* `load_balancing_metric` - (Optional) Load balancing algorithm. Allowed values: "round-robin", "ip-hash", "least-conn", "weighted-rr"
* `session_sticky` - (Optional) Enable session stickiness. Allowed values: "true", "false". Default "false"
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
* `websocket_enabled` - (Required for tunnel apps) Enable WebSocket support. Allowed values: "true", "false". Default "false"
* `x_wapp_read_timeout` - (Required for tunnel apps) Read timeout in seconds. Default 300
* `ignore_cname_resolution` - (Optional) Ignore CNAME resolution for CDN access. Allowed values: "true", "false"
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


