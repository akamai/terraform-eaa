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
- Related Applications
- Authentication
- Server Load Balancing
- Configure TLS Cipher Suite
- Health Check Configuration
- Custom HTTP Headers
- Enterprise Connectivity Parameters
- Miscellaneous
- DLP Controls

#### RDP Profile
- Remote Desktop Configuration
- Remote Desktop User Preferences
- Authentication
- Configure TLS Cipher Suite
- Health Check Configuration
- Custom HTTP Headers
- Enterprise Connectivity Parameters
- Miscellaneous
- DLP Controls

#### VNC Profile
- Authentication
- Configure TLS Cipher Suite
- Health Check Configuration
- Custom HTTP Headers
- Enterprise Connectivity Parameters
- Miscellaneous
- DLP Controls

#### SSH Profile
- Authentication
- Configure TLS Cipher Suite
- Health Check Configuration
- Custom HTTP Headers
- Enterprise Connectivity Parameters
- Miscellaneous
- DLP Controls

#### SMB Profile
- Authentication
- Configure TLS Cipher Suite
- Health Check Configuration
- Custom HTTP Headers
- Enterprise Connectivity Parameters
- Miscellaneous
- DLP Controls

### Authentication Methods
Enterprise applications support all authentication methods:
- SAML (`saml = true`)
- OpenID Connect (`oidc = true`)
- WS-Federation (`wsfed = true`)
- Kerberos (`app_auth = "kerberos"`)
- Basic Authentication (`app_auth = "basic"`)
- NTLMv1 (`app_auth = "NTLMv1"`)
- NTLMv2 (`app_auth = "NTLMv2"`)

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
- SAML (`saml = true`) - NOT allowed
- OpenID Connect (`oidc = true`) - NOT allowed
- WS-Federation (`wsfed = true`) - NOT allowed
- Basic authentication only (handled at resource level)

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
- SAML (`saml = true`) - NOT allowed
- OpenID Connect (`oidc = true`) - NOT allowed
- WS-Federation (`wsfed = true`) - NOT allowed
- Basic authentication only (handled at resource level)

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
SaaS applications support modern authentication methods:
- SAML (`saml = true`)
- OpenID Connect (`oidc = true`)
- WS-Federation (`wsfed = true`)
- Kerberos (`app_auth = "kerberos"`) - NOT allowed in `advanced_settings`
- Basic Authentication (`app_auth = "basic"`) - NOT allowed in `advanced_settings`
- NTLMv1/NTLMv2 - NOT allowed in `advanced_settings`

### Configuration Notes
- SaaS apps use resource-level configuration only
- No `advanced_settings` block should be provided
- Authentication is handled at the resource level using boolean flags (`saml`, `oidc`, `wsfed`)

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
  
  # Supports all authentication methods
  saml = true
  # or oidc = true
  # or wsfed = true
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
  })
  
  # No advanced authentication methods
  # saml = true  # NOT allowed
  # oidc = true  # NOT allowed
  # wsfed = true # NOT allowed
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
  # saml = true  # NOT allowed
  # oidc = true  # NOT allowed
  # wsfed = true # NOT allowed
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
  
  # Supports modern authentication methods
  saml = true
  # or oidc = true
  # or wsfed = true
}
```


## Summary Matrix

### Enterprise Applications
- **Advanced Settings**: Full Support - All categories supported
- **SAML Authentication**: Supported
- **OIDC Authentication**: Supported  
- **WS-Federation**: Supported
- **Kerberos Authentication**: Supported
- **Basic Authentication**: Supported
- **CORS Support**: Supported
- **TLS Suite Configuration**: Supported
- **RDP Configuration**: Supported (RDP profile only)
- **Health Check**: Supported
- **Load Balancing**: Supported

### Tunnel Applications
- **Advanced Settings**: Limited - Only specific categories allowed
- **SAML Authentication**: Not Allowed
- **OIDC Authentication**: Not Allowed
- **WS-Federation**: Not Allowed
- **Kerberos Authentication**: Not Allowed
- **Basic Authentication**: Supported
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
  
  # This will cause validation error
  saml = true  # NOT allowed for tunnel apps
  
  advanced_settings = jsonencode({
    # These will cause validation errors
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
- **SAML Authentication**: Supported
- **OIDC Authentication**: Supported
- **WS-Federation**: Supported
- **Kerberos Authentication**: Not Allowed
- **Basic Authentication**: Not Allowed
- **CORS Support**: Not Allowed
- **TLS Suite Configuration**: Not Allowed
- **RDP Configuration**: Not Allowed
- **Health Check**: Not Allowed
- **Load Balancing**: Not Allowed
