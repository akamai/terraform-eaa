# eaa_application

Manages the lifecycle of an EAA application.

## Argument Reference

* `name` - (Required) Application name.
* `description` - (Optional) Application description.
* `app_profile` - (Optional) Access profile. Values: `http`, `tcp`, `rdp`, `ssh`, `vnc`, `smb`, `sharepoint`, `jira`, `jenkins`, `confluence`. Default `http`.
* `app_type` - (Optional) Application type. Values: `enterprise`, `tunnel`, `bookmark`, `saas`. Default `enterprise`.
* `client_app_mode` - (Optional) Client app mode. Values: `tcp`, `tunnel`. Default `tcp`.
* `domain` - (Optional) Domain type. Values: `custom`, `wapp`. Default `wapp`.
* `host` - (Optional) External hostname for the application.
* `bookmark_url` - (Optional) URL for bookmark applications.
* `pop` - (Computed) PoP identifier.
* `popname` - (Computed) PoP name.
* `popregion` - (Optional/Computed) Target region for deployment.
* `app_category` - (Optional) Application category name.
* `agents` - (Optional) List of connector names to assign.
* `auth_enabled` - (Optional) Enable application authentication. Default `"false"` (string; use `"true"`/`"false"`).
* `protocol` - (Optional, SaaS only) Auth protocol. Values: `SAML`, `SAML2.0`, `OIDC`, `OpenID Connect 1.0`, `WSFed`, `WS-Federation`. Note: lowercase `wsfed` is NOT valid.
* `app_bundle` - (Optional) Application bundle name for grouping related apps.
* `tls_suite_name` - (Optional/Computed) TLS cipher suite name. See [TLS Suite](#tls-suite) for details.

### Servers

* `servers` - (Optional) List of origin servers:
  * `origin_host` - Origin server IP or FQDN.
  * `origin_port` - Origin server port.
  * `origin_protocol` - Protocol: `http`, `https`, `tcp`, `rdp`.
  * `orig_tls` - (Deprecated) Computed by the API based on `origin_protocol`. Do not set directly.

### Tunnel Internal Hosts

* `tunnel_internal_hosts` - (Optional) For tunnel apps:
  * `host` - IP or FQDN.
  * `port_range` - Port range (e.g. `3200-6000`).
  * `proto_type` - `1` (TCP), `2` (UDP), or `3` (ALL).

### Certificates

* `cert_type` - (Optional) Certificate type for custom domain. Valid values: `self_signed` (default), `uploaded`.
  * **`self_signed`** — The provider checks if a self-signed certificate already exists for the application's `host`. If one exists, it is reused. Otherwise, a new self-signed certificate is automatically generated. No additional fields are required.
  * **`uploaded`** — The provider looks up a previously uploaded certificate by the name specified in `cert_name`. The certificate must already exist in EAA; if it is not found, the operation fails.
* `cert_name` - (Optional) Name of a previously uploaded certificate to use. Required when `cert_type` is `uploaded`. Ignored when `cert_type` is `self_signed`.
* `cert` - (Computed) The resolved certificate UUID assigned to the application. This is set automatically by the provider based on `cert_type` and `cert_name`.
* `cert_body` - (Computed, Sensitive) The certificate body content. Set automatically by the provider.

### Authentication

* `app_authentication` - (Optional) Authentication configuration:
  * `app_idp` - IDP name.
  * `app_directories` - List of directories:
    * `name` - Directory name.
    * `enable_mfa` - (Optional) Enable MFA.
    * `app_groups` - List of groups:
      * `name` - Group name. Must exist; unmatched names fail validation.
      * `enable_mfa` - (Optional) Enable MFA.

### SAML/OIDC/WS-Fed Settings

* `saml_settings` - (Optional) SAML configuration.
* `oidc_settings` - (Optional) OpenID Connect configuration.
* `wsfed_settings` - (Optional) WS-Federation configuration.

### Access Control (Service)

* `service` - (Optional) Access service configuration:
  * `service_type` - (Required) Service type.
  * `status` - (Required) Service status.
  * `access_rule` - (Optional) List of access rules:
    * `name` - (Required) Rule name.
    * `status` - (Required) Rule status.
    * `rule` - (Optional) Rule conditions:
      * `operator` - (Required) Operator.
      * `type` - (Required) Condition type.
      * `value` - (Required) Condition value.

### TLS Suite

* `tls_suite_name` - (Optional/Computed, top-level) TLS cipher suite name for the application. When omitted, the API assigns the partner default suite. Use the `eaa_data_source_tls_cipher_suites` data source to discover valid suite names for an application.

  **Behavior notes:**
  - The API does not validate the suite name — an incorrect name will be saved without error.
  - Setting `tls_suite_name = ""` (empty string) has no effect — the API does not support clearing the suite name. The provider silently ignores the empty value and the previously assigned suite remains active.
  - Once set, removing `tls_suite_name` from the config will not reset it to the default. The previously computed value remains in Terraform state. To change the suite, set it to a different valid name explicitly.

## Computed Attributes

* `app_operational` - App operational status.
* `app_status` - App status code.
* `app_deployed` - Whether the app is deployed.
* `cname` - App CNAME.
* `uuid_url` - App UUID.
* `domain_suffix` - Domain suffix.

## Advanced Settings

Flat map of key/value string pairs passed via `advanced_settings`. Organized by category below.

The `advanced_settings` map also accepts keys not listed here — any key the EAA API supports can be passed through. The list below covers the most commonly used fields.

### Health Check

* `health_check_type` - Type. Values: `Default`, `HTTP`, `HTTPS`, `TLS`, `SSLv3`, `TCP`, `None`.
* `health_check_interval` - Interval in milliseconds. Default `30000`.
* `health_check_http_url` - (Required for HTTP/HTTPS) Health check URL.
* `health_check_http_version` - (Required for HTTP/HTTPS) HTTP version: `1.0`, `1.1`.
* `health_check_http_host_header` - (Required for HTTP/HTTPS) Host header.
* `health_check_fall` - Failures before marking unhealthy. Default `3`.
* `health_check_rise` - Successes before marking healthy. Default `2`.
* `health_check_timeout` - Timeout in milliseconds. Default `50000`.

### Server Load Balancing

* `load_balancing_metric` - Algorithm: `round-robin`, `ip-hash`, `least-conn`, `weighted-rr`.
* `session_sticky` - Enable session stickiness. Default `false`.
* `session_sticky_cookie_maxage` - Sticky session cookie max age in seconds (not for tunnel apps). Default `0`.
* `session_sticky_server_cookie` - Server cookie name for sticky sessions.

### Enterprise Connectivity

* `app_server_read_timeout` - Server read timeout in seconds (min 60). Default `60`.
* `idle_close_time_seconds` - Idle close time in seconds (max 1800). Default `1200`.
* `idle_conn_floor` - Minimum idle connections. Default `50`.
* `idle_conn_ceil` - Maximum idle connections. Default `75`.
* `idle_conn_step` - Idle connection step size. Default `10`.
* `proxy_buffer_size_kb` - Buffer size in KB (4-256, multiple of 4). Default `4`.

### Authentication

**User-facing (`wapp_auth`):**
* `wapp_auth` - Auth method at the access page: `form`, `basic`, `basic_cookie`, `jwt`, `certonly`.
* `login_url` - Login URL.
* `logout_url` - Logout URL.
* `intercept_url` - Intercept URL.
* `form_post_url` - Form post URL.
* `form_post_attributes` - Form post attributes (JSON-encoded list of strings).
* `app_client_cert_auth` - Enable client cert auth.
* `app_cookie_domain` - Cookie domain for SSO.
* `sentry_redirect_401` - Redirect 401 for session validation.

**App-to-origin (`app_auth`):**
* `app_auth` - Auth to origin: `none`, `kerberos`, `basic`, `NTLMv1`, `NTLMv2`, `SAML2.0` (or `saml`), `WS-Federation` (or `wsfed`), `OpenID Connect 1.0` (or `oidc`), `auto`, `service account`.

**Kerberos fields:**
* `app_auth_domain` - Kerberos domain.
* `forward_ticket_granting_ticket` - Forward TGT. Default `false`.
* `keytab` - Keytab file content.
* `service_principle_name` - SPN. Note: the API uses this spelling.
* `kerberos_negotiate_once` - Negotiate once.

**JWT fields (when `wapp_auth = "jwt"`):**
* `jwt_issuers` - Issuers.
* `jwt_audience` - Audience.
* `jwt_grace_period` - Grace period in seconds. Default `60`.
* `jwt_return_option` - Return option. Default `401`.
* `jwt_username` - Username field.
* `jwt_return_url` - Return URL.

### CORS

* `allow_cors` - Enable CORS.
* `cors_origin_list` - Comma-delimited allowed origins.
* `cors_method_list` - Comma-delimited allowed methods.
* `cors_header_list` - Comma-delimited allowed headers.
* `cors_support_credential` - Support credentials.
* `cors_max_age` - Preflight cache duration in seconds.

### SSL & WebSocket

* `is_ssl_verification_enabled` - SSL cert verification. Default `true`.
* `websocket_enabled` - WebSocket support. Default `false`.
* `x_wapp_read_timeout` - Read timeout in seconds. Default `900`.
* `ignore_cname_resolution` - Ignore CNAME resolution for CDN access.
* `g2o_enabled` - Enable G2O for Akamai Edge Enforcement.
* `internal_hostname` - Internal hostname.
* `internal_host_port` - Internal host port.

### Tunnel Client

* `acceleration` - Enable acceleration. Values: `true`, `false`.
* `force_ip_route` - Force IP routing. Values: `true`, `false`.
* `x_wapp_pool_enabled` - Connection pooling. Values: `true`, `false`, `inherit`.
* `x_wapp_pool_size` - Pool size. Default `20`.
* `x_wapp_pool_timeout` - Pool timeout in seconds. Default `120`.
* `domain_exception_list` - Domains to exclude from wildcard matching.

### Security

* `edge_authentication_enabled` - Enable edge authentication. Default `true`.
* `ip_access_allow` - Enable IP-based access control.
* `hsts_age` - HSTS max-age in seconds. Default `15552000`.
* `http_only_cookie` - Set cookies as HTTP-only. Default `true`.

### RDP

* `rdp_initial_program` - Initial program.
* `rdp_tls1` - TLS 1.0.
* `rdp_keyboard_lang` - Keyboard language.
* `rdp_legacy_mode` - Enable RDP legacy mode.
* `rdp_window_color_depth` - Window color depth.
* `rdp_window_height` - Window height.
* `rdp_window_width` - Window width.
* `rdp_remote_apps` - Remote applications (JSON-encoded list).
* `remote_spark_audio` - Audio redirection.
* `remote_spark_recording` - Spark recording.
* `remote_spark_printer` - Spark printer.
* `remote_spark_disk` - Spark disk.
* `remote_spark_map_clipboard` - Clipboard mapping.
* `remote_spark_map_disk` - Disk mapping.
* `remote_spark_map_printer` - Printer mapping.

### Miscellaneous

* `custom_headers` - Custom headers to forward (JSON-encoded list).
* `hidden_app` - Hide from UI.
* `offload_onpremise_traffic` - Offload on-premise traffic.
* `logging_enabled` - Enable logging.
* `saas_enabled` - Enable SaaS mode.
* `segmentation_policy_enable` - Enable segmentation policy.
* `sticky_agent` - Route to same connector.

## App Type Compatibility

Which advanced settings categories are allowed per app type:

| Category | Enterprise HTTP | Enterprise RDP | Enterprise SSH/VNC/SMB/TCP | Tunnel | Bookmark | SaaS |
|---|---|---|---|---|---|---|
| Health Check | ✓ | ✓ | ✓ | ✓ (TCP only) | - | - |
| Load Balancing | ✓ | ✓ | ✓ | limited | - | - |
| Enterprise Connectivity | ✓ | ✓ | ✓ | limited | - | - |
| Authentication | ✓ (all methods) | ✓ (all methods) | ✓ (no `app_auth`) | blocked | - | - |
| CORS | ✓ | - | - | blocked | - | - |
| SSL & WebSocket | ✓ | ✓ | ✓ | ✓ (required) | - | - |
| Tunnel Client | - | - | - | ✓ (required) | - | - |
| Security | ✓ | ✓ | ✓ | ✓ | - | - |
| RDP | - | ✓ | - | - | - | - |
| Miscellaneous | ✓ | ✓ | ✓ | limited | - | - |


**Bookmark and SaaS apps do not support `advanced_settings` at all.**

### Auth Methods by App Type

| Method | Enterprise | Tunnel | Bookmark | SaaS |
|---|---|---|---|---|
| `app_auth` in advanced_settings | ✓ (HTTP/RDP only) | `none` only | - | - |
| `protocol` field | - | - | - | ✓ (SAML, OIDC, WSFed) |
| Basic (resource-level) | ✓ | ✓ | ✓ | - |

## Examples

### Enterprise HTTP Application

```hcl
resource "eaa_application" "web_app" {
  name        = "Web App"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  host        = "web-app"
  popregion   = "us-east-1"
  agents      = ["my-connector"]

  servers {
    origin_host     = "app.internal.example.com"
    origin_port     = 443
    origin_protocol = "https"
  }

  advanced_settings = {
    health_check_type             = "HTTP"
    health_check_http_url         = "/health"
    health_check_http_version     = "1.1"
    health_check_http_host_header = "app.internal.example.com"
    load_balancing_metric         = "round-robin"
    app_auth                      = "basic"
  }

  auth_enabled = "true"

  app_authentication {
    app_idp = "corp-idp"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "WebApp-Users"
      }
    }
  }
}
```

### Tunnel Application

```hcl
resource "eaa_application" "tunnel_app" {
  name            = "SAP Tunnel"
  app_profile     = "tcp"
  app_type        = "tunnel"
  client_app_mode = "tunnel"
  domain          = "wapp"
  host            = "sap-tunnel"
  popregion       = "us-west-1"
  agents          = ["dc1-connector"]

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "3200-6000"
    host       = "192.168.2.1"
  }

  advanced_settings = {
    is_ssl_verification_enabled = "false"
    health_check_type           = "TCP"
    websocket_enabled           = "true"
    x_wapp_read_timeout         = "300"
  }

  auth_enabled = "true"
}
```

### Custom Domain Application

```hcl
resource "eaa_application" "custom_domain_app" {
  name        = "Custom App"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "custom"
  host        = "app.example.com"
  popregion   = "us-east-1"
  agents      = ["my-connector"]

  servers {
    origin_host     = "internal-app.corp.example.com"
    origin_port     = 8443
    origin_protocol = "https"
  }

  auth_enabled = "true"
}
```

### More Examples

- [Enterprise HTTP](../examples/enterprise_http.tf) — Akamai domain, custom domain, CORS, ACL rules, custom headers
- [Enterprise RDP](../examples/enterprise_rdp.tf) — RDP with remote app publishing
- [Tunnel apps](../examples/tunnel.tf) — TCP tunnel with internal hosts
- [SAML auth](../examples/auth_saml.tf) — Enterprise and SaaS SAML
- [OIDC auth](../examples/auth_oidc.tf) — Enterprise and SaaS OpenID Connect
- [WS-Federation auth](../examples/auth_wsfed.tf) — Enterprise and SaaS WS-Fed
- [Kerberos auth](../examples/auth_kerberos.tf) — Kerberos with and without client cert
- [JWT auth](../examples/auth_jwt.tf) — JWT user-facing authentication
