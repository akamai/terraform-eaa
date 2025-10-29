# Application Type Configurations

This document outlines the specific configurations and restrictions for different EAA application types. Each application type has different capabilities and limitations.

## Application Types Overview

EAA supports the following application types:
- **Enterprise**: Full-featured applications with comprehensive configuration options
- **Tunnel**: TCP tunnel applications with limited configuration options
- **Bookmark**: Simple bookmark applications with minimal configuration
- **SaaS**: Software-as-a-Service applications with specific authentication options

## Enterprise Applications

Enterprise applications provide the most comprehensive configuration options and support all advanced settings categories.

### Supported Profiles
- **HTTP**: Web applications
- **RDP**: Remote Desktop Protocol applications
- **VNC**: Virtual Network Computing applications
- **SSH**: Secure Shell applications
- **SMB**: Server Message Block applications
- **TCP**: Generic TCP applications

### Allowed Advanced Settings Categories

#### HTTP Profile
- [Health Check Parameters](advanced-settings.md#health-check-parameters)
- [Server Load Balancing Parameters](advanced-settings.md#server-load-balancing-parameters)
- [Enterprise Connectivity Parameters](advanced-settings.md#enterprise-connectivity-parameters)
- [Authentication Parameters](advanced-settings.md#authentication-parameters)
- [CORS Parameters](advanced-settings.md#cors-parameters)
- [TLS Suite Parameters](advanced-settings.md#tls-suite-parameters)
- [Miscellaneous Parameters](advanced-settings.md#miscellaneous-parameters)

#### RDP Profile
- [RDP Configuration Parameters](advanced-settings.md#rdp-configuration-parameters)
- [Health Check Parameters](advanced-settings.md#health-check-parameters)
- [Server Load Balancing Parameters](advanced-settings.md#server-load-balancing-parameters)
- [Enterprise Connectivity Parameters](advanced-settings.md#enterprise-connectivity-parameters)
- [Authentication Parameters](advanced-settings.md#authentication-parameters)
- [TLS Suite Parameters](advanced-settings.md#tls-suite-parameters)
- [Miscellaneous Parameters](advanced-settings.md#miscellaneous-parameters)

#### VNC Profile
- [Health Check Parameters](advanced-settings.md#health-check-parameters)
- [Server Load Balancing Parameters](advanced-settings.md#server-load-balancing-parameters)
- [Enterprise Connectivity Parameters](advanced-settings.md#enterprise-connectivity-parameters)
- [Authentication Parameters](advanced-settings.md#authentication-parameters)
- [TLS Suite Parameters](advanced-settings.md#tls-suite-parameters)
- [Miscellaneous Parameters](advanced-settings.md#miscellaneous-parameters)

#### SSH Profile
- [Health Check Parameters](advanced-settings.md#health-check-parameters)
- [Server Load Balancing Parameters](advanced-settings.md#server-load-balancing-parameters)
- [Enterprise Connectivity Parameters](advanced-settings.md#enterprise-connectivity-parameters)
- [Authentication Parameters](advanced-settings.md#authentication-parameters)
- [TLS Suite Parameters](advanced-settings.md#tls-suite-parameters)
- [Miscellaneous Parameters](advanced-settings.md#miscellaneous-parameters)

#### SMB Profile
- [Health Check Parameters](advanced-settings.md#health-check-parameters)
- [Server Load Balancing Parameters](advanced-settings.md#server-load-balancing-parameters)
- [Enterprise Connectivity Parameters](advanced-settings.md#enterprise-connectivity-parameters)
- [Authentication Parameters](advanced-settings.md#authentication-parameters)
- [TLS Suite Parameters](advanced-settings.md#tls-suite-parameters)
- [Miscellaneous Parameters](advanced-settings.md#miscellaneous-parameters)

### Authentication Methods
Enterprise applications support all authentication methods via `app_auth` in `advanced_settings`:
- SAML (`app_auth = "SAML2.0"` or `app_auth = "saml"` in advanced_settings)
- OpenID Connect (`app_auth = "OpenID Connect 1.0"` or `app_auth = "oidc"` in advanced_settings)
- WS-Federation (`app_auth = "WS-Federation"` in advanced_settings)
- Kerberos (`app_auth = "kerberos"`)
- Basic Authentication (`app_auth = "basic"`)
- NTLMv1 (`app_auth = "NTLMv1"`)
- NTLMv2 (`app_auth = "NTLMv2"`)
- None (`app_auth = "none"`)

### Special Restrictions
- **SSH Profile**: `app_auth` is disabled - field should not be present in `advanced_settings`
- **VNC Profile**: `app_auth` is disabled - field should not be present in `advanced_settings`

#### Invalid Enterprise Configuration Examples

**DO NOT USE - Enterprise SSH app with app_auth:**
```hcl
resource "eaa_application" "enterprise_ssh_invalid" {
  name        = "enterprise-ssh-invalid"
  app_type    = "enterprise"
  app_profile = "ssh"  # SSH profile
  
  advanced_settings = jsonencode({
    # This will cause validation error
    app_auth = "kerberos"  # NOT allowed for SSH profile
  })
}
```

**DO NOT USE - SSH audit for non-SSH profile:**
```hcl
resource "eaa_application" "enterprise_invalid_ssh_audit" {
  name        = "enterprise-invalid-ssh-audit"
  app_type    = "enterprise"
  app_profile = "http"  # Not SSH profile
  
  advanced_settings = jsonencode({
    # This will cause validation error
    ssh_audit_enabled = true  # Only allowed for SSH profile
  })
}
```

**DO NOT USE - RDP configuration for non-RDP profile:**
```hcl
resource "eaa_application" "enterprise_invalid_rdp" {
  name        = "enterprise-invalid-rdp"
  app_type    = "enterprise"
  app_profile = "http"  # Not RDP profile
  
  advanced_settings = jsonencode({
    # These will cause validation errors
    rdp_audio_redirection = true    # Only allowed for RDP profile
    rdp_clipboard_redirection = true # Only allowed for RDP profile
    rdp_disk_redirection = true     # Only allowed for RDP profile
  })
}
```

## Tunnel Applications

Tunnel applications provide TCP tunneling capabilities with limited configuration options.

### Supported Profiles
- **TCP**: TCP tunnel applications only

### Allowed Advanced Settings Categories
- Server Load Balancing (`load_balancing_metric`, `session_sticky`, `tcp_optimization`)
- Enterprise Connectivity (`app_server_read_timeout`, `idle_close_time_seconds`, `proxy_buffer_size_kb`)
- Tunnel Client Parameters (`acceleration`, `force_ip_route`, `x_wapp_pool_*`, `domain_exception_list`)
- Health Check (`health_check_type`, `health_check_*`)
- Basic Configuration (`websocket_enabled`, `is_ssl_verification_enabled`, `x_wapp_read_timeout`)

### Blocked Advanced Settings Categories
- Authentication parameters (`login_url`, `logout_url`, `wapp_auth`, `app_auth`, etc.)
- CORS parameters (`allow_cors`, `cors_*`)
- TLS Suite parameters (`tls_suite_name`, `tls_cipher_suite`)
- Miscellaneous parameters (`custom_headers`, `hidden_app`, `logging_enabled`, etc.)
- RDP configuration parameters (`rdp_*`)

### Authentication Methods
Tunnel applications have limited authentication options:
- SAML - NOT allowed (cannot use `app_auth = "saml"` or `app_auth = "SAML2.0"` in advanced_settings)
- OpenID Connect - NOT allowed (cannot use `app_auth = "oidc"` or `app_auth = "OpenID Connect 1.0"` in advanced_settings)
- WS-Federation - NOT allowed (cannot use `app_auth = "WS-Federation"` in advanced_settings)
- Basic authentication only (handled at resource level)
- None authentication (`app_auth = "none"` is allowed in advanced_settings)

### Required Fields
- `websocket_enabled = true`
- `auth_enabled = true`
- `health_check_type = "TCP"`

### Special Notes
- `cookie_age` is not supported for tunnel apps
- `x_wapp_read_timeout` is only available for tunnel applications
- `app_auth` should not be present in `advanced_settings` - it's set at resource level as "tcp"

## Bookmark Applications

Bookmark applications are simple applications with minimal configuration requirements.

### Supported Profiles
- **HTTP**: Web bookmark applications

### Advanced Settings Restrictions
- `advanced_settings` - NOT allowed at all
- All advanced settings categories are blocked

### Authentication Methods
Bookmark applications have limited authentication options:
- SAML - NOT allowed
- OpenID Connect - NOT allowed
- WS-Federation - NOT allowed
- Basic authentication only (handled at resource level)
- No `advanced_settings` block allowed (so no `app_auth` configuration)

### Configuration Notes
- Bookmark apps use resource-level configuration only
- No `advanced_settings` block should be provided
- Authentication is handled at the resource level using basic authentication

## SaaS Applications

SaaS (Software-as-a-Service) applications are designed for third-party cloud services.

### Supported Profiles
- **HTTP**: Web SaaS applications

### Advanced Settings Restrictions
- `advanced_settings` - NOT allowed at all
- All advanced settings categories are blocked

### Authentication Methods
SaaS applications support modern authentication methods via the `protocol` field:
- SAML (`protocol = "SAML"` or `protocol = "SAML2.0"`)
- OpenID Connect (`protocol = "OpenID Connect 1.0"` or `protocol = "OIDC"`)
- WS-Federation (`protocol = "WSFed"` or `protocol = "WS-Federation"`) - Note: Both "WSFed" and "WS-Federation" are valid (case-sensitive, lowercase "wsfed" is NOT supported)
- Kerberos - NOT allowed
- Basic Authentication - NOT allowed
- NTLMv1/NTLMv2 - NOT allowed

### Configuration Notes
- SaaS apps use resource-level configuration only
- No `advanced_settings` block should be provided
- Authentication is specified using the `protocol` field (not `saml`, `oidc`, `wsfed` boolean flags)

## Configuration Examples

### Enterprise HTTP Application
```hcl
resource "eaa_application" "enterprise_http" {
  name        = "Enterprise HTTP App"
  app_type    = "enterprise"
  app_profile = "http"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  # Supports all advanced settings
  advanced_settings = jsonencode({
    # Authentication
    wapp_auth = "basic"
    app_auth = "kerberos"
    
    # Server Load Balancing
    load_balancing_metric = "round-robin"
    session_sticky = true
    
    # Health Check
    health_check_type = "HTTP"
    health_check_enabled = true
    
    # Enterprise Connectivity
    app_server_read_timeout = "300"
    
    # CORS
    allow_cors = true
    cors_origin_list = "https://example.com"
    
    # Miscellaneous
    logging_enabled = true
    custom_headers = []
  })
  
  # Authentication methods are set via app_auth in advanced_settings (not boolean flags)
  # The advanced_settings above already includes app_auth = "kerberos" as an example
  # For SAML, OIDC, or WSFed, set app_auth to:
  #   app_auth = "SAML2.0" or "saml" for SAML
  #   app_auth = "OpenID Connect 1.0" or "oidc" for OIDC  
  #   app_auth = "WS-Federation" for WS-Federation
  # Other valid values: "kerberos", "basic", "NTLMv1", "NTLMv2", "none"
  
  # Note: DO NOT use top-level boolean flags (saml = true, oidc = true, wsfed = true)
  # These are deprecated and should not be used
}
```

### Tunnel Application
```hcl
resource "eaa_application" "tunnel_app" {
  name        = "Tunnel App"
  app_type    = "tunnel"
  app_profile = "tcp"
  domain      = "wapp"
  client_app_mode = "tunnel"
  
  # Limited advanced settings
  advanced_settings = jsonencode({
    # Health Check (Required)
    health_check_type = "TCP"
    
    # Basic Configuration (Required)
    websocket_enabled = true
    
    # Server Load Balancing (Allowed)
    load_balancing_metric = "round-robin"
    session_sticky = true
    
    # Tunnel Client Parameters (Allowed)
    acceleration = true
    x_wapp_read_timeout = "300"
    
    # Enterprise Connectivity (Allowed)
    app_server_read_timeout = "300"
    
    # Authentication - only "none" is allowed for tunnel apps
    # app_auth = "none"  # Optional - "none" is allowed
    # Cannot use: app_auth = "saml", "oidc", "WS-Federation", "kerberos" - NOT allowed
  })
  
  # No advanced authentication methods at resource level
  # Cannot use saml, oidc, or wsfed boolean flags
  # Only basic authentication at resource level is supported
}
```

### Bookmark Application
```hcl
resource "eaa_application" "bookmark_app" {
  name        = "Bookmark App"
  app_type    = "bookmark"
  app_profile = "http"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  # No advanced_settings allowed
  # advanced_settings = jsonencode({...})  # NOT allowed
  
  # No advanced authentication methods
  # Cannot use saml, oidc, or wsfed boolean flags (no longer exist)
  # Cannot use protocol field (only for SaaS apps)
  # Only basic authentication at resource level is supported
}
```

### SaaS Application
```hcl
resource "eaa_application" "saas_app" {
  name        = "SaaS App"
  app_type    = "saas"
  app_profile = "http"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  # No advanced_settings allowed
  # advanced_settings = jsonencode({...})  # NOT allowed
  
  # Supports modern authentication methods via protocol field
  protocol = "SAML"  # or "SAML2.0", "OpenID Connect 1.0", "OIDC", "WSFed", "WS-Federation"
}
```


## Summary Matrix

### Enterprise Applications
- **Advanced Settings**: Full Support - All categories supported
- **SAML Authentication**: Supported via `app_auth = "SAML2.0"` or `app_auth = "saml"` in advanced_settings
- **OIDC Authentication**: Supported via `app_auth = "OpenID Connect 1.0"` or `app_auth = "oidc"` in advanced_settings
- **WS-Federation**: Supported via `app_auth = "WS-Federation"` in advanced_settings
- **Kerberos Authentication**: Supported via `app_auth = "kerberos"` in advanced_settings
- **Basic Authentication**: Supported via `app_auth = "basic"` in advanced_settings
- **CORS Support**: Supported
- **TLS Suite Configuration**: Supported
- **RDP Configuration**: Supported (RDP profile only)
- **Health Check**: Supported
- **Load Balancing**: Supported

### Tunnel Applications
- **Advanced Settings**: Limited - Only specific categories allowed
- **SAML Authentication**: Not Allowed (cannot use `app_auth = "saml"` or `app_auth = "SAML2.0"` in advanced_settings)
- **OIDC Authentication**: Not Allowed (cannot use `app_auth = "oidc"` or `app_auth = "OpenID Connect 1.0"` in advanced_settings)
- **WS-Federation**: Not Allowed (cannot use `app_auth = "WS-Federation"` in advanced_settings)
- **Kerberos Authentication**: Not Allowed (cannot use `app_auth = "kerberos"` in advanced_settings)
- **Basic Authentication**: Supported at resource level
- **None Authentication**: Supported via `app_auth = "none"` in advanced_settings
- **CORS Support**: Not Allowed
- **TLS Suite Configuration**: Not Allowed
- **RDP Configuration**: Not Allowed
- **Health Check**: Supported (TCP only)
- **Load Balancing**: Supported

#### Invalid Tunnel Configuration Examples

**DO NOT USE - Tunnel app with SAML authentication:**
```hcl
resource "eaa_application" "tunnel_invalid" {
  name            = "tunnel-invalid"
  app_type        = "tunnel"
  app_profile     = "tcp"
  client_app_mode = "tunnel"
  
  advanced_settings = jsonencode({
    # These will cause validation errors
    app_auth = "SAML2.0"  # NOT allowed for tunnel apps (or "saml", "oidc", "WS-Federation")
    login_url = "https://example.com/login"     # Authentication - NOT allowed
    logout_url = "https://example.com/logout"   # Authentication - NOT allowed
    allow_cors = true                           # CORS - NOT allowed
    cors_origin_list = "https://example.com"    # CORS - NOT allowed
    tls_suite_name = "TLS-Suite-v3"            # TLS Suite - NOT allowed
    custom_headers = []                         # Miscellaneous - NOT allowed
    hidden_app = false                          # Miscellaneous - NOT allowed
    logging_enabled = true                      # Miscellaneous - NOT allowed
    rdp_audio_redirection = true                # RDP - NOT allowed
  })
}
```

### Bookmark Applications
- **Advanced Settings**: Not Allowed
- **SAML Authentication**: Not Allowed
- **OIDC Authentication**: Not Allowed
- **WS-Federation**: Not Allowed
- **Kerberos Authentication**: Not Allowed
- **Basic Authentication**: Supported
- **CORS Support**: Not Allowed
- **TLS Suite Configuration**: Not Allowed
- **RDP Configuration**: Not Allowed
- **Health Check**: Not Allowed
- **Load Balancing**: Not Allowed

### SaaS Applications
- **Advanced Settings**: Not Allowed
- **SAML Authentication**: Supported via `protocol = "SAML"` or `protocol = "SAML2.0"`
- **OIDC Authentication**: Supported via `protocol = "OpenID Connect 1.0"` or `protocol = "OIDC"`
- **WS-Federation**: Supported via `protocol = "WSFed"` or `protocol = "WS-Federation"`
- **Kerberos Authentication**: Not Allowed
- **Basic Authentication**: Not Allowed
- **CORS Support**: Not Allowed
- **TLS Suite Configuration**: Not Allowed
- **RDP Configuration**: Not Allowed
- **Health Check**: Not Allowed
- **Load Balancing**: Not Allowed
