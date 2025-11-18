# Application Type Configurations

This document outlines the specific configurations and restrictions for different EAA application types. Each application type has different capabilities and limitations.

## Application Types Overview

EAA supports the following application types:
- **Enterprise**: Full-featured applications with comprehensive configuration options
- **Tunnel**: TCP tunnel applications with limited configuration options
- **Bookmark**: Simple bookmark applications with minimal configuration
- **SaaS**: Software-as-a-Service applications with specific authentication options

## Enterprise Applications

Enterprise applications provide the most comprehensive configuration options and support all advanced settings categories. They are designed for internal applications that require full control over authentication, routing, and behavior.

### HTTP Profile

**Description**: Web applications accessed via HTTP/HTTPS protocols. Supports all advanced settings categories and authentication methods.

**Allowed Advanced Settings**:
- [Health Check Parameters](./healthcheck_advsettings.md) - All types supported (HTTP, HTTPS, TCP, None)
- [Server Load Balancing Parameters](./server_load_balancing_advsettings.md) - Full support
- [Enterprise Connectivity Parameters](./enterprise_connectivity_advsettings.md) - Full support
- [Authentication Parameters](./authentication_advsettings.md) - All authentication methods
- [CORS Parameters](./cors_advsettings.md) - Full CORS support
- [TLS Suite Parameters](./tls_suite_advsettings.md) - Custom and predefined suites
- [Miscellaneous Parameters](./miscellaneous_advsettings.md) - All options available
- [SSL and WebSocket Configuration Parameters](./ssl_websocket_advsettings.md) - Full support

**Example Files**:
- [examples/custom_http_app.tf](../examples/custom_http_app.tf) - Comprehensive HTTP application with all advanced settings
- [examples/enterprise_valid.tf](../examples/enterprise_valid.tf) - Enterprise HTTP application with full configuration (see `enterprise_valid_comprehensive` resource)
- [examples/custom_http_app_domain.tf](../examples/custom_http_app_domain.tf) - Custom HTTP application with domain configuration
- [examples/saml_application.tf](../examples/saml_application.tf) - Enterprise HTTP application with SAML authentication
- [examples/oidc_application.tf](../examples/oidc_application.tf) - Enterprise HTTP application with OpenID Connect authentication
- [examples/wsfederation_application.tf](../examples/wsfederation_application.tf) - Enterprise HTTP application with WS-Federation authentication
- [examples/kerberos_application.tf](../examples/kerberos_application.tf) - Enterprise HTTP application with Kerberos authentication
- [examples/jwt_application.tf](../examples/jwt_application.tf) - Enterprise HTTP application with JWT authentication

### RDP Profile

**Description**: Remote Desktop Protocol applications for accessing Windows desktops and applications remotely.

**Allowed Advanced Settings**:
- [RDP Configuration Parameters](./rdp_advsettings.md) - Audio, clipboard, disk, printer redirection
- [Health Check Parameters](./healthcheck_advsettings.md) - TCP and None types recommended
- [Server Load Balancing Parameters](./server_load_balancing_advsettings.md) - Full support
- [Enterprise Connectivity Parameters](./enterprise_connectivity_advsettings.md) - Full support
- [Authentication Parameters](./authentication_advsettings.md) - Kerberos recommended
- [TLS Suite Parameters](./tls_suite_advsettings.md) - Custom and predefined suites
- [Miscellaneous Parameters](./miscellaneous_advsettings.md) - Most options available

**Example Files**:
- [examples/enterprise_valid.tf](../examples/enterprise_valid.tf) - Enterprise RDP application (see `enterprise_valid_rdp` resource)

### SSH Profile

**Description**: Secure Shell applications for secure command-line access to remote systems.

**Allowed Advanced Settings**:
- [Health Check Parameters](./healthcheck_advsettings.md) - TCP and None types recommended
- [Server Load Balancing Parameters](./server_load_balancing_advsettings.md) - Full support
- [Enterprise Connectivity Parameters](./enterprise_connectivity_advsettings.md) - Full support
- [Authentication Parameters](./authentication_advsettings.md) - Limited (no `app_auth` in advanced_settings)
- [TLS Suite Parameters](./tls_suite_advsettings.md) - Custom and predefined suites
- [Miscellaneous Parameters](./miscellaneous_advsettings.md) - Most options available

**Restrictions**: `app_auth` is disabled - field should not be present in `advanced_settings`

**Example Files**:
- See [examples/](../examples/) directory for SSH profile examples

### VNC Profile

**Description**: Virtual Network Computing applications for remote desktop access to Linux/Unix systems.

**Allowed Advanced Settings**:
- [Health Check Parameters](./healthcheck_advsettings.md) - TCP and None types recommended
- [Server Load Balancing Parameters](./server_load_balancing_advsettings.md) - Full support
- [Enterprise Connectivity Parameters](./enterprise_connectivity_advsettings.md) - Full support
- [Authentication Parameters](./authentication_advsettings.md) - Limited (no `app_auth` in advanced_settings)
- [TLS Suite Parameters](./tls_suite_advsettings.md) - Custom and predefined suites
- [Miscellaneous Parameters](./miscellaneous_advsettings.md) - Most options available

**Restrictions**: `app_auth` is disabled - field should not be present in `advanced_settings`

**Example Files**:
- See [examples/](../examples/) directory for VNC profile examples

### SMB Profile

**Description**: Server Message Block applications for file sharing and network file system access.

**Allowed Advanced Settings**:
- [Health Check Parameters](healthcheck_advsettings.md) - TCP and None types recommended
- [Server Load Balancing Parameters](server_load_balancing_advsettings.md) - Full support
- [Enterprise Connectivity Parameters](enterprise_connectivity_advsettings.md) - Full support
- [Authentication Parameters](authentication_advsettings.md) - Kerberos recommended
- [TLS Suite Parameters](tls_suite_advsettings.md) - Custom and predefined suites
- [Miscellaneous Parameters](miscellaneous_advsettings.md) - Most options available

**Example Files**:
- See [examples/](../examples/) directory for SMB profile examples

### TCP Profile

**Description**: Generic TCP applications for custom TCP-based protocols.

**Allowed Advanced Settings**:
- [Health Check Parameters](./healthcheck_advsettings.md) - TCP and None types recommended
- [Server Load Balancing Parameters](./server_load_balancing_advsettings.md) - Full support
- [Enterprise Connectivity Parameters](./enterprise_connectivity_advsettings.md) - Full support
- [Authentication Parameters](./authentication_advsettings.md) - Limited (no `app_auth` in advanced_settings)
- [TLS Suite Parameters](./tls_suite_advsettings.md) - Custom and predefined suites
- [Miscellaneous Parameters](./miscellaneous_advsettings.md) - Most options available

**Example Files**:
- See [examples/](../examples/) directory for TCP profile examples

### Authentication Methods

Enterprise applications support all authentication methods via `app_auth` in `advanced_settings`:
- SAML (`app_auth = "SAML2.0"` or `app_auth = "saml"`)
- OpenID Connect (`app_auth = "OpenID Connect 1.0"` or `app_auth = "oidc"`)
- WS-Federation (`app_auth = "WS-Federation"`)
- Kerberos (`app_auth = "kerberos"`)
- Basic Authentication (`app_auth = "basic"`)
- NTLMv1 (`app_auth = "NTLMv1"`)
- NTLMv2 (`app_auth = "NTLMv2"`)
- None (`app_auth = "none"`)

See [Authentication Parameters](./authentication_advsettings.md) for detailed documentation.

## Tunnel Applications

Tunnel applications provide TCP tunneling capabilities with limited configuration options. They are designed for forwarding TCP traffic through secure tunnels.

### TCP Profile

**Description**: TCP tunnel applications that forward TCP traffic through secure tunnels. Limited advanced settings support.

**Allowed Advanced Settings**:
- [Tunnel Client Parameters](./tunnel_client_advsettings.md) - Required (acceleration, force_ip_route, x_wapp_pool_*)
- [Health Check Parameters](./healthcheck_advsettings.md) - TCP type required
- [SSL and WebSocket Configuration Parameters](./ssl_websocket_advsettings.md) - websocket_enabled required
- [Server Load Balancing Parameters](./server_load_balancing_advsettings.md) - Limited support
- [Enterprise Connectivity Parameters](./enterprise_connectivity_advsettings.md) - Limited support
- [Miscellaneous Parameters](./miscellaneous_advsettings.md) - Limited support

**Blocked Advanced Settings**:
- Authentication parameters (`login_url`, `logout_url`, `wapp_auth`, `app_auth`, etc.)
- CORS parameters (`allow_cors`, `cors_*`)
- TLS Suite parameters (`tls_suite_name`, `tls_cipher_suite`)
- RDP configuration parameters (`rdp_*`)

**Required Fields**:
- `websocket_enabled = true`
- `auth_enabled = true`
- `health_check_type = "TCP"`

**Example Files**:
- [examples/tunnel_app.tf](../examples/tunnel_app.tf) - Tunnel application with TCP profile and required settings
- [examples/tunnel_valid.tf](../examples/tunnel_valid.tf) - Valid tunnel application configuration
- [examples/tcp_app.tf](../examples/tcp_app.tf) - TCP tunnel application

**Authentication Methods**:
- Basic authentication only (handled at resource level)
- None authentication (`app_auth = "none"` is allowed in advanced_settings)
- SAML, OIDC, WS-Federation - NOT allowed

## Bookmark Applications

Bookmark applications are simple applications with minimal configuration requirements. They provide quick access to external URLs without advanced configuration.

### HTTP Profile

**Description**: Web bookmark applications that provide access to external URLs. No advanced settings support.

**Allowed Advanced Settings**:
- None - `advanced_settings` is NOT allowed at all

**Example Files**:
- See [examples/](../examples/) directory for bookmark application examples

**Authentication Methods**:
- Basic authentication only (handled at resource level)
- No `advanced_settings` block allowed (so no `app_auth` configuration)

## SaaS Applications

SaaS (Software-as-a-Service) applications are designed for third-party cloud services. They support modern authentication protocols but have no advanced settings support.

### HTTP Profile

**Description**: Web SaaS applications for accessing third-party cloud services. Authentication via resource-level `protocol` field only.

**Allowed Advanced Settings**:
- None - `advanced_settings` is NOT allowed at all

**Example Files**:
- See [examples/](../examples/) directory for SaaS application examples

**Authentication Methods**:
- SAML (`protocol = "SAML"` or `protocol = "SAML2.0"`)
- OpenID Connect (`protocol = "OpenID Connect 1.0"` or `protocol = "OIDC"`)
- WS-Federation (`protocol = "WSFed"` or `protocol = "WS-Federation"`) - Note: Both "WSFed" and "WS-Federation" are valid (case-sensitive, lowercase "wsfed" is NOT supported)
- Authentication is specified using the `protocol` field (not `saml`, `oidc`, `wsfed` boolean flags)

## Summary

For a complete reference of all advanced settings parameters, see [Advanced Settings Reference](./advanced-settings.md).
