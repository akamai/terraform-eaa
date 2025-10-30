# Advanced Settings Reference

This document provides comprehensive information about the `advanced_settings` parameter for EAA applications. Advanced settings allow you to configure detailed application behavior beyond the basic resource parameters.

## Overview

The `advanced_settings` parameter accepts a JSON-encoded string containing various configuration options. See per-category references:

- [Health Check Parameters](./healthcheck_advsettings.md)
- [Server Load Balancing Parameters](./server_load_balancing_advsettings.md)
- [Enterprise Connectivity Parameters](./enterprise_connectivity_advsettings.md)
- [Tunnel Client Parameters](./tunnel_client_advsettings.md)
- [Basic Configuration Parameters](./basic_configuration_advsettings.md)
- [Authentication Parameters](./authentication_advsettings.md)
- [CORS Parameters](./cors_advsettings.md)
- [TLS Suite Parameters](./tls_suite_advsettings.md)
- [Miscellaneous Parameters](./miscellaneous_advsettings.md)
- [RDP Configuration Parameters](./rdp_advsettings.md)

## Application-Specific Advanced Settings

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

Example: [Custom HTTP Application](../examples/custom_http_app.tf)

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

Example: [Tunnel Application](../examples/tunnel_app.tf)

### Bookmark Applications
Bookmark applications have minimal configuration:

- **Advanced Settings**: Not supported at all
- **Configuration**: Resource-level parameters only

Example: (Not applicable)

### SaaS Applications
SaaS applications have limited advanced settings:

- **Advanced Settings**: Not supported at all
- **Authentication**: Resource-level `protocol` field only (not boolean flags)

Example: [SaaS Application](../examples/saas.tf)

 

## Authentication Parameters

Configure application-level authentication mechanisms.

### User-Facing Authentication (`wapp_auth`)
* `wapp_auth` - (Optional) Defines how users authenticate at the access page; select one of the methods below. Allowed values: "form", "basic", "basic_cookie", "jwt", "certonly"

* `form` - (Optional) Username/password form at the EAA access page
* `basic` - (Optional) HTTP Basic challenge at the EAA access page
* `basic_cookie` - (Optional) Basic auth with session cookie for subsequent requests
* `jwt` - (Optional) Validates a JSON Web Token presented by the client
* `certonly` - (Optional) Requires client TLS certificate for user access
* `login_url` - (Optional) Login URL for authentication
* `logout_url` - (Optional) Logout URL for authentication
* `intercept_url` - (Optional) URL to intercept for authentication
* `form_post_url` - (Optional) Form post URL for authentication
* `form_post_attributes` - (Optional) Form post attributes
* `app_client_cert_auth` - (Optional) Enable client certificate authentication
* `app_cookie_domain` - (Optional) Cookie domain for SSO
* `sentry_redirect_401` - (Optional) Redirect 401 responses for session validation

### Application Authentication (`app_auth`)
* `app_auth` - (Optional) Defines how the application authenticates to the origin; select one of the methods below.

* `none` - (Optional) No application-level authentication performed to the origin
* `kerberos` - (Optional) Authenticates to the origin using Kerberos 
* `basic` - (Optional) Uses HTTP Basic authentication to the origin
* `NTLMv1` - (Optional) Authenticates to the origin using NTLMv1 
* `NTLMv2` - (Optional) Authenticates to the origin using NTLMv2
* `SAML2.0` - (Optional) Federated SSO using SAML 2.0
* `WS-Federation` - (Optional)  using the WS-Federation 
* `OpenID Connect 1.0` - (Optional)  using OpenID Connect 1.0

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

### Examples

Example (user-facing authentication):

```json
{
  "wapp_auth": "basic",
  "login_url": "/login",
  "logout_url": "/logout",
  "app_cookie_domain": ".example.com"
}
```

Example files:

- [examples/jwt_application.tf](../examples/jwt_application.tf)
- [examples/kerberos_application.tf](../examples/kerberos_application.tf)
- [examples/saml_application.tf](../examples/saml_application.tf)
- [examples/oidc_application.tf](../examples/oidc_application.tf)
- [examples/wsfederation_application.tf](../examples/wsfederation_application.tf)

Example (application authentication - Kerberos):

```json
{
  "app_auth": "kerberos",
  "app_auth_domain": "EXAMPLE.COM",
  "service_principal_name": "HTTP/app.internal.example.com@EXAMPLE.COM",
  "kerberos_negotiate_once": "true"
}
```

Example (JWT):

```json
{
  "wapp_auth": "jwt",
  "jwt_issuers": "https://issuer.example.com/",
  "jwt_audience": "my-app",
  "jwt_grace_period": "60",
  "jwt_return_option": "401"
}
```

 


