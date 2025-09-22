# Create a new EAA Application

A Terraform configuration is a complete document written in HCL (Hashicorp Configuration language) that tells Terraform how to manage a given collection of infrastructure.
Configuration files tell Terraform what plugins to install, what infrastructure to create, and what data to fetch.
The main purpose of the Terraform language is declaring resources, which represent infrastructure objects. The following sections describe how to define the resource eaa_application in terraform configuration file.

### Resource: eaa_application

Manages the lifecycle of the EAA application.  

#### Argument Reference

This resource supports the following arguments:

* ```name``` - (Required) Name of the application
* ```description``` - (Optional) Description of the application
* ```app_profile``` - (Required) The access application profile. "http", "tcp". Default "http"
* ```app_type``` - (Required) The type of application configuration. "enterprise", "tunnel". Default "enterprise"	
* ```client_app_mode``` - (Required) The mode of client app. "tcp", "tunnel". Default "tcp"
* ```app_category``` - (Optional) Name of the application category
* ```domain``` - (Required) The type of access domain. "custom", "wapp". Default "custom"
* ```host``` - (Required) The external default hostname for the application.
* ```servers``` - (Optional) EAA application server details. list of dictionaries with following settings
  * origin_host - The IP address or FQDN of the origin server.
  * orig_tls - Enables TLS on the origin server.
  * origin_port - The port number of the origin server.
  * origin_protocol - The protocol of the origin server connection. Either ssh or http.
* ```tunnel_internal_hosts``` - (Optional)
  * host       - The IP address or FQDN of the hsot
  * port_range - the port range of the host
  * proto_type - The protocol of the host. Either "tcp" or "udp"
* ```agents``` - (Optional) EAA application connector details. list of agent names	
* ```popregion``` - (Optional) The target region to deploy the application	
* ```popname``` - (Computed)	 The name for the target pop to deploy the application
* ```auth_enabled``` - (Required) - Is the application authentication enabled
* ```app_authentication``` - (Optional) dictionary with the application authentication data
  * app_idp - Name of the application IDP
    * app_directories - List of application directories
      * name - Name of the dictionary
      * app_groups - list of subset of directory's groups that are assigned to the application.
* ```advanced_settings```	- (Optional) dictionary of advanced settings	

  **Health Check Parameters:**
  * health_check_type - (Required for tunnel apps) Type of health check. Allowed values: "Default", "HTTP", "HTTPS", "TLS", "SSLv3", "TCP", "None"
  * health_check_enabled - (Optional) Enable health check. Default true
  * health_check_interval - (Optional) Health check interval in seconds (1-300). Default 30
  * health_check_http_url - (Required for HTTP/HTTPS) Health check URL
  * health_check_http_version - (Required for HTTP/HTTPS) HTTP version. Allowed values: "1.0", "1.1", "2.0"
  * health_check_http_host_header - (Required for HTTP/HTTPS) Host header for health check
  * health_check_http_method - (Optional) HTTP method for health check. Default "GET"
  * health_check_http_expected_response - (Optional) Expected HTTP response code. Default 200

  **Server Load Balancing Parameters:**
  * load_balancing_metric - (Optional) Load balancing algorithm. Allowed values: "round-robin", "ip-hash", "least-conn", "weighted-rr"
  * session_sticky - (Optional) Enable session stickiness. Default false
  * cookie_age - (Optional) Cookie age in seconds when session_sticky is enabled. Not supported for tunnel apps
  * tcp_optimization - (Optional) Enable TCP optimization. Only available for tunnel apps

  **Enterprise Connectivity Parameters:**
  * app_server_read_timeout - (Optional) Application server read timeout in seconds (minimum 60). Default 300
  * idle_close_time_seconds - (Optional) Idle connection close time in seconds (maximum 1800). Default 300
  * proxy_buffer_size_kb - (Optional) Proxy buffer size in KB (4-256, multiple of 4). Default 4

  **Tunnel Client Parameters:**
  * acceleration - (Optional) Enable acceleration for tunnel apps. Allowed values: "true", "false"
  * force_ip_route - (Optional) Force IP routing for tunnel apps. Allowed values: "true", "false"
  * x_wapp_pool_enabled - (Optional) Enable connection pooling. Allowed values: "true", "false", "inherit"
  * x_wapp_pool_size - (Optional) Connection pool size (1-50). Default 10
  * x_wapp_pool_timeout - (Optional) Connection pool timeout in seconds (60-3600). Default 300
  * domain_exception_list - (Optional) List of domains to exclude from wildcard matching

  **Basic Configuration Parameters:**
  * is_ssl_verification_enabled - (Optional) Enable SSL certificate verification. Default "true"
  * websocket_enabled - (Required for tunnel apps) Enable WebSocket support. Default false
  * x_wapp_read_timeout - (Required for tunnel apps) Read timeout in seconds. Default 300
  * ignore_cname_resolution - (Optional) Ignore CNAME resolution for CDN access
  * g2o_enabled - (Optional) Enable G2O configuration for Akamai Edge Enforcement
  * internal_hostname - (Optional) Internal hostname
  * internal_host_port - (Optional) Internal host port

  **Authentication Parameters (NOT allowed for tunnel apps):**
  * login_url - (Optional) Login URL for authentication
  * logout_url - (Optional) Logout URL for authentication
  * wapp_auth - (Optional) User-facing authentication type. Allowed values: "form", "basic", "basic_cookie", "jwt"
  * app_auth - (Optional) Application authentication type. Allowed values: "none", "kerberos", "basic", "NTLMv1", "NTLMv2", "SAML2.0", "wsfed", "oidc", "OpenID Connect 1.0"
  * intercept_url - (Optional) URL to intercept for authentication
  * form_post_url - (Optional) Form post URL for authentication
  * form_post_attributes - (Optional) Form post attributes
  * app_client_cert_auth - (Optional) Enable client certificate authentication
  * app_cookie_domain - (Optional) Cookie domain for SSO
  * sentry_redirect_401 - (Optional) Redirect 401 responses for session validation

  **CORS Parameters (NOT allowed for tunnel apps):**
  * allow_cors - (Optional) Enable CORS support
  * cors_origin_list - (Optional) Space-delimited list of allowed origins
  * cors_method_list - (Optional) Space-delimited list of allowed HTTP methods
  * cors_header_list - (Optional) Space-delimited list of allowed headers
  * cors_support_credential - (Optional) Support credentials in CORS requests
  * cors_max_age - (Optional) CORS preflight cache duration in seconds

  **TLS Suite Parameters (NOT allowed for tunnel apps):**
  * tls_suite_name - (Optional) TLS suite name for custom configuration
  * tls_cipher_suite - (Optional) TLS cipher suite for custom configuration

  **Miscellaneous Parameters (NOT allowed for tunnel apps):**
  * custom_headers - (Optional) Custom headers to insert and forward
  * hidden_app - (Optional) Hide application from user interface
  * offload_onpremise_traffic - (Optional) Offload on-premise traffic
  * logging_enabled - (Optional) Enable application logging
  * saas_enabled - (Optional) Enable SaaS mode
  * segmentation_policy_enable - (Optional) Enable segmentation policy
  * sticky_agent - (Optional) Route requests to same connector

  **RDP Configuration Parameters (NOT allowed for tunnel apps):**
  * rdp_audio_redirection - (Optional) Enable RDP audio redirection
  * rdp_clipboard_redirection - (Optional) Enable RDP clipboard redirection
  * rdp_disk_redirection - (Optional) Enable RDP disk redirection
  * rdp_printer_redirection - (Optional) Enable RDP printer redirection
  * rdp_initial_program - (Optional) RDP initial program
  * rdp_tls1 - (Optional) Enable RDP TLS 1.0
  * remote_spark_recording - (Optional) Enable remote Spark recording
  * remote_spark_printer - (Optional) Enable remote Spark printer
  * remote_spark_disk - (Optional) Enable remote Spark disk

  **Application Authentication Type (`app_auth`)**
  * ```app_auth``` - (Optional) The type of application authentication. Default "none"
    * **Allowed Values**: "none", "kerberos", "basic", "NTLMv1", "NTLMv2", "SAML2.0", "wsfed", "oidc", "OpenID Connect 1.0"
    * **Special Behavior**: When set to "SAML2.0", "wsfed", "oidc", or "OpenID Connect 1.0", the corresponding boolean flags (`saml`, `wsfed`, `oidc`) are automatically set to `true`
    * **API Payload**: 
      * When `app_auth` is "SAML2.0" in Terraform config, the `app_auth` field in the API payload is sent as "none"
      * When `app_auth` is "wsfed" or "WS-Federation" in Terraform config, the `app_auth` field in the API payload is sent as "wsfed"
      * When `app_auth` is "oidc" or "OpenID Connect 1.0" in Terraform config, the `app_auth` field in the API payload is sent as "oidc"

  **User-Facing Authentication Type (`wapp_auth`)**
  * ```wapp_auth``` - (Optional) The type of user-facing authentication. Default "form"
    * **Allowed Values**: "form", "basic", "basic_cookie", "jwt"
    * **Description**: Controls how users authenticate to the application interface
    * **Default Value**: "form" (form-based authentication)
    JWT Authentication Settings** (Only applicable when `wapp_auth = "jwt"`)
  * ```jwt_issuers``` - (Optional) JWT issuers. Default ""
  * ```jwt_audience``` - (Optional) JWT audience. Default ""
  * ```jwt_grace_period``` - (Optional) JWT grace period in seconds. Default "60"
  * ```jwt_return_option``` - (Optional) JWT return option. Default "401"
  * ```jwt_username``` - (Optional) JWT username field. Default ""
  * ```jwt_return_url``` - (Optional) JWT return URL. Default "

  **Kerberos Authentication Settings** (Only applicable when `app_auth = "kerberos"`)
  * ```app_auth_domain``` - (Optional) Kerberos domain name. Default ""
  * ```app_client_cert_auth``` - (Optional) Enable client certificate authentication. Allowed values: "true", "false". Default "false"
  * ```forward_ticket_granting_ticket``` - (Optional) Forward ticket granting ticket. Allowed values: "true", "false". Default "false"
  * ```keytab``` - (Optional) Kerberos keytab file content. Default ""
  * ```service_principal_name``` - (Optional) Service principal name. Default ""

* ```saml``` - (Computed) Boolean flag indicating if SAML authentication is enabled
* ```wsfed``` - (Computed) Boolean flag indicating if WS-Federation authentication is enabled
* ```saml_settings``` - (Optional) SAML configuration settings. Array of SAML configuration objects (minimum 1 item)
  * ```sp``` - (Required) Service Provider configuration block
    * ```entity_id``` - (Optional) Entity ID for the service provider. Default ""
    * ```acs_url``` - (Optional) Assertion Consumer Service URL. Default ""
    * ```slo_url``` - (Optional) Single Logout URL. Default ""
    * ```req_bind``` - (Optional) Request binding method. Allowed values: "redirect", "post". Default "redirect"
    * ```metadata``` - (Optional) SP metadata. Default ""
    * ```default_relay_state``` - (Optional) Default relay state. Can be null. Default null
    * ```force_auth``` - (Optional) Force authentication. Default false
    * ```req_verify``` - (Optional) Request verification. Default false
    * ```sign_cert``` - (Optional) Signing certificate. Default ""
    * ```resp_encr``` - (Optional) Response encryption. Default false
    * ```encr_cert``` - (Optional) Encryption certificate. Default ""
    * ```encr_algo``` - (Optional) Encryption algorithm. Default "aes256-cbc"
    * ```slo_req_verify``` - (Optional) SLO request verification. Default true
    * ```dst_url``` - (Optional) Destination URL. Default ""
    * ```slo_bind``` - (Optional) SLO binding method. Default "post"

  * ```idp``` - (Required) Identity Provider configuration block
    * ```entity_id``` - (Optional) Entity ID for the identity provider. Default ""
    * ```metadata``` - (Optional) IDP metadata. Default ""
    * ```sign_cert``` - (Optional) Signing certificate. Default ""
    * ```sign_key``` - (Optional) Signing private key. Default ""
    * ```self_signed``` - (Optional) Self-signed certificate flag. Default true
    * ```sign_algo``` - (Optional) Signing algorithm. Allowed values: "SHA256", "SHA384", "SHA512". Default "SHA256"
    * ```resp_bind``` - (Optional) Response binding method. Allowed values: "post", "redirect". Default "post"
    * ```slo_url``` - (Optional) Single Logout URL. Default ""
    * ```ecp_enable``` - (Optional) Enable ECP. Default false
    * ```ecp_resp_signature``` - (Optional) ECP response signature. Default false

  * ```subject``` - (Required) Subject configuration block
    * ```fmt``` - (Optional) Subject format. Allowed values: "email", "persistent", "transient", "unspecified". Default "email"
    * ```src``` - (Optional) Subject source. Allowed values: "user.email", "user.persistentId", "user.samAccountName", "user.userPrincipleName". Default "user.email"
    * ```val``` - (Optional) Subject value. Default ""
    * ```rule``` - (Optional) Subject rule. Default ""

  * ```attrmap``` - (Required) Attribute mapping configuration block
    * ```name``` - (Required) Attribute name
    * ```fname``` - (Optional) Friendly name. Default ""
    * ```fmt``` - (Required) Attribute format. Allowed values: "email", "phone", "country", "firstName", "lastName", "groups", "netbios", "persistentId", "samAccountName", "userPrincipleName"
    * ```val``` - (Optional) Attribute value. Default ""
    * ```src``` - (Required) Attribute source. Allowed values: "user.email", "user.phoneNumber", "user.countryCode", "user.firstName", "user.lastName", "user.groups", "user.netbios", "user.persistentId", "user.samAccountName", "user.userPrincipleName"
    * ```rule``` - (Optional) Attribute rule. Default ""

* ```wsfed_settings``` - (Optional) WS-Federation configuration settings. Array of WS-Federation configuration objects (minimum 1 item)
  * ```sp``` - (Required) Service Provider configuration block
    * ```entity_id``` - (Optional) Entity ID for the service provider. Default ""
    * ```slo_url``` - (Optional) Single Logout URL. Default ""
    * ```dst_url``` - (Optional) Destination URL. Default ""
    * ```resp_bind``` - (Optional) Response binding method. Allowed values: "post". Default "post"
    * ```token_life``` - (Optional) Token lifetime in seconds. Default 3600
    * ```encr_algo``` - (Optional) Encryption algorithm. Allowed values: "aes256-cbc", "aes128-cbc". Default "aes256-cbc"

  * ```idp``` - (Optional) Identity Provider configuration block
    * ```entity_id``` - (Optional) Entity ID for the identity provider. Default ""
    * ```sign_algo``` - (Optional) Signing algorithm. Allowed values: "SHA256", "SHA1". Default "SHA256"
    * ```sign_cert``` - (Optional) Signing certificate in PEM format. Default ""
    * ```sign_key``` - (Optional) Signing private key in PEM format. Default ""
    * ```self_signed``` - (Optional) Self-signed certificate flag. Default true

  * ```subject``` - (Required) Subject configuration block
    * ```fmt``` - (Required) Subject format. Allowed values: "email", "persistent", "transient", "unspecified"
    * ```custom_fmt``` - (Optional) Custom format. Default ""
    * ```src``` - (Optional) Subject source. Allowed values: "user.email", "user.persistentId", "user.samAccountName", "user.userPrincipleName"
    * ```val``` - (Optional) Subject value. Default ""
    * ```rule``` - (Optional) Subject rule. Default ""

  * ```attrmap``` - (Optional) Attribute mapping configuration block
    * ```name``` - (Optional) Attribute name. Default ""
    * ```fmt``` - (Required) Attribute format. Allowed values: "email", "phone", "country", "firstName", "lastName", "groups", "netbios", "persistentId", "samAccountName", "userPrincipleName"
    * ```custom_fmt``` - (Optional) Custom format. Default ""
    * ```val``` - (Optional) Attribute value. Default ""
    * ```src``` - (Optional) Attribute source. Allowed values: "user.email", "user.phoneNumber", "user.countryCode", "user.firstName", "user.lastName", "user.groups", "user.netbios", "user.persistentId", "user.samAccountName", "user.userPrincipleName"
    * ```rule``` - (Optional) Attribute rule. Default ""

* ```oidc``` - (Computed) Boolean flag indicating if OpenID Connect authentication is enabled
* ```oidc_settings``` - (Optional) OpenID Connect configuration settings. Array of OIDC configuration objects (minimum 1 item)
  * ```authorization_endpoint``` - (Optional) Authorization endpoint URL. Default ""
  * ```certs_uri``` - (Optional) Certificates URI. Default ""
  * ```check_session_iframe``` - (Optional) Check session iframe URL. Default ""
  * ```discovery_url``` - (Optional) Discovery URL. Default ""
  * ```end_session_endpoint``` - (Optional) End session endpoint URL. Default ""
  * ```jwks_uri``` - (Optional) JWKS URI. Default ""
  * ```openid_metadata``` - (Optional) OpenID metadata. Default ""
  * ```token_endpoint``` - (Optional) Token endpoint URL. Default ""
  * ```userinfo_endpoint``` - (Optional) User info endpoint URL. Default ""

#### Validation Rules

**Tunnel Application Validation:**
* **Authentication Methods**: Tunnel apps do NOT support advanced authentication methods:
  * `saml = true` is NOT allowed for tunnel apps
  * `oidc = true` is NOT allowed for tunnel apps  
  * `wsfed = true` is NOT allowed for tunnel apps
  * Tunnel apps use basic authentication only
* **Advanced Settings Restrictions**: Tunnel apps only support specific parameter categories:
  * **Allowed Categories**:
    * Server Load Balancing (`load_balancing_metric`, `session_sticky`, `cookie_age`, `tcp_optimization`)
    * Enterprise Connectivity (`app_server_read_timeout`, `idle_close_time_seconds`, `proxy_buffer_size_kb`)
    * Tunnel Client Parameters (`acceleration`, `force_ip_route`, `x_wapp_pool_*`, `domain_exception_list`)
    * Health Check (`health_check_type`, `health_check_*`)
    * Basic Configuration (`websocket_enabled`, `is_ssl_verification_enabled`, `x_wapp_read_timeout`)
  * **Blocked Categories**:
    * Authentication parameters (`login_url`, `logout_url`, `wapp_auth`, `app_auth`, etc.)
    * CORS parameters (`allow_cors`, `cors_*`)
    * TLS Suite parameters (`tls_suite_name`, `tls_cipher_suite`)
    * Miscellaneous parameters (`custom_headers`, `hidden_app`, `logging_enabled`, etc.)
    * RDP configuration parameters (`rdp_*`)
* **Health Check**: Health checks are now supported for tunnel apps with `health_check_type = "TCP"` (required)
* **Required Fields**: Tunnel apps require:
  * `websocket_enabled = true`
  * `auth_enabled = true`
  * `health_check_type = "TCP"`

**SAML Settings Validation:**
* When `app_auth = "SAML2.0"`, `saml_settings` must be provided with at least one configuration block
* `saml_settings` is an array with minimum 1 item
* All mandatory fields in SP, IDP, Subject, and Attrmap blocks must be present (even if empty strings)

**Subject and Attrmap Validation:**
* `fmt` field validation:
  * **For subject**: "email", "persistent", "transient", "unspecified"
  * **For attrmap**: "email", "phone", "country", "firstName", "lastName", "groups", "netbios", "persistentId", "samAccountName", "userPrincipleName"
* `src` field validation:
  * **For subject**: "user.email", "user.persistentId", "user.samAccountName", "user.userPrincipleName"
  * **For attrmap**: "user.email", "user.phoneNumber", "user.countryCode", "user.firstName", "user.lastName", "user.groups", "user.netbios", "user.persistentId", "user.samAccountName", "user.userPrincipleName"
* **Conditional validation**: If `fmt` is "email", then `src` must be "user.email"

**Kerberos Settings Validation:**
* Kerberos settings are only applicable when `app_auth = "kerberos"`
* `app_client_cert_auth` and `forward_ticket_granting_ticket` must be either "true" or "false"

**WS-Federation Settings Validation:**
* When `app_auth = "wsfed"` or `app_auth = "WS-Federation"`, `wsfed_settings` must be provided with at least one configuration block
* `wsfed_settings` is an array with minimum 1 item
* All mandatory fields in SP, IDP, Subject, and Attrmap blocks must be present (even if empty strings)
* `resp_bind` field validation: Only "post" is allowed
* `encr_algo` field validation: "aes256-cbc", "aes128-cbc"
* `sign_algo` field validation: "SHA256", "SHA1"
* Subject and Attrmap validation follows the same rules as SAML settings

**OpenID Connect Settings Validation:**
* When `app_auth = "oidc"` or `app_auth = "OpenID Connect 1.0"`, `oidc_settings` must be provided with at least one configuration block
* `oidc_settings` is an array with minimum 1 item
* All endpoint fields are optional and will be populated from the API response

**JWT Settings Validation:**
* JWT settings are only applicable when `wapp_auth = "jwt"`
* `jwt_grace_period` and `jwt_return_option` are numeric values sent as strings
* All JWT fields are optional with default values

**Authentication Method Conflicts:**
* When `saml = true`, `oidc = true`, or `wsfed = true` at the resource level, `app_auth` in `advanced_settings` must be set to "none"
* These authentication methods are mutually exclusive with `app_auth` values other than "none"

#### Error Messages and Validation Constants

**Tunnel Application Error Messages:**
* `ErrTunnelAppSAMLNotAllowed`: "saml=true is not allowed for tunnel apps. Tunnel apps use basic authentication"
* `ErrTunnelAppOIDCNotAllowed`: "oidc=true is not allowed for tunnel apps. Tunnel apps use basic authentication"
* `ErrTunnelAppWSFEDNotAllowed`: "wsfed=true is not allowed for tunnel apps. Tunnel apps use basic authentication"

**Advanced Settings Validation Errors:**
* `ErrAppAuthNotAllowedForTunnel`: "app_auth should not be present in advanced_settings for tunnel apps"
* `ErrAppAuthNotAllowedForSaaS`: "app_auth should not be present in advanced_settings for SaaS apps"
* `ErrAppAuthNotAllowedForBookmark`: "app_auth should not be present in advanced_settings for bookmark apps"
* `ErrAppAuthDisabledForEnterpriseSSH`: "app_auth is disabled for enterprise SSH apps"
* `ErrAppAuthDisabledForEnterpriseVNC`: "app_auth is disabled for enterprise VNC apps"

**Health Check Validation Errors:**
* `ErrHealthCheckTypeUnsupported`: "health_check_type must be one of: Default, HTTP, HTTPS, TLS, SSLv3, TCP, None"
* `ErrHealthCheckHTTPURLRequired`: "health_check_http_url is required when health_check_type is HTTP/HTTPS"
* `ErrHealthCheckHTTPVersionRequired`: "health_check_http_version is required when health_check_type is HTTP/HTTPS"
* `ErrHealthCheckHTTPHostHeaderRequired`: "health_check_http_host_header is required when health_check_type is HTTP/HTTPS"

**Server Load Balancing Validation Errors:**
* `ErrLoadBalancingMetricUnsupported`: "load_balancing_metric must be one of: round-robin, ip-hash, least-conn, weighted-rr"
* `ErrSessionStickyInvalid`: "session_sticky must be a boolean"
* `ErrCookieAgeRequired`: "cookie_age must be a number when session_sticky is enabled"
* `ErrCookieAgeNotSupportedTunnel`: "cookie_age is not supported for tunnel apps"

**Tunnel Client Parameters Validation Errors:**
* `ErrAccelerationInvalidValue`: "acceleration must be 'true' or 'false'"
* `ErrForceIPRouteInvalidValue`: "force_ip_route must be 'true' or 'false'"
* `ErrXWappPoolEnabledInvalidValue`: "x_wapp_pool_enabled must be one of: 'true', 'false', 'inherit'"
* `ErrXWappPoolSizeOutOfRange`: "x_wapp_pool_size must be between 1 and 50"
* `ErrXWappPoolTimeoutOutOfRange`: "x_wapp_pool_timeout must be between 60 and 3600 seconds"

**Enterprise Connectivity Validation Errors:**
* `ErrAppServerReadTimeoutTooLow`: "app_server_read_timeout must be at least 60 seconds"
* `ErrIdleCloseTimeTooHigh`: "idle_close_time_seconds cannot exceed 1800 seconds (30 minutes)"
* `ErrProxyBufferSizeOutOfRange`: "proxy_buffer_size_kb must be between 4 and 256 KB"
* `ErrProxyBufferSizeNotMultipleOf4`: "proxy_buffer_size_kb must be a multiple of 4"

**Miscellaneous Parameters Validation Errors:**
* `ErrAllowCorsNotAvailableForTunnel`: "allow_cors is not available for tunnel applications"
* `ErrHiddenAppNotAvailableForTunnel`: "hidden_app is not available for tunnel applications"
* `ErrXWappReadTimeoutOnlyForTunnel`: "x_wapp_read_timeout is only available for tunnel applications"
* `ErrOffloadOnpremiseTrafficNotBoolean`: "offload_onpremise_traffic must be a boolean"

**RDP Configuration Validation Errors:**
* `ErrRDPNotSupportedForAppType`: "RDP configuration parameters are not supported for this app type. RDP configuration is only available for Enterprise Hosted applications"
* `ErrRDPNotSupportedForProfile`: "RDP configuration parameters are not supported for this app profile. RDP configuration is only available for RDP applications"
* `ErrRDPPrinterRequiresMapPrinter`: "remote_spark_printer requires remote_spark_mapPrinter to be enabled"
* `ErrRDPDiskRequiresMapDisk`: "remote_spark_disk requires remote_spark_mapDisk to be enabled"

#### Special Behaviors

**First-time App Creation with SAML2.0:**
* When creating a new app with `app_auth = "SAML2.0"` for the first time:
  * **No `app_authentication` block needed initially**
  * API automatically assigns a default IDP
  * API creates default SAML settings with `self_signed = true`
  * API provides default certificates and metadata
* `app_authentication` can be added later via updates

**Default SAML Settings:**
* If `app_auth = "SAML2.0"` but no `saml_settings` block is provided:
  * Provider automatically creates default SAML settings structure
  * All mandatory fields are included with default values
  * Empty arrays are sent instead of null values

**API Payload Behavior:**
* When `app_auth = "SAML2.0"` in Terraform config, the API payload sends `app_auth = "none"`
* This is the expected behavior for SAML2.0 applications

**WS-Federation Special Behaviors:**

**First-time App Creation with WS-Federation:**
* When creating a new app with `app_auth = "wsfed"` or `app_auth = "WS-Federation"` for the first time:
  * **No `app_authentication` block needed initially**
  * API automatically assigns a default IDP
  * API creates default WS-Federation settings with `self_signed = true`
  * API provides default certificates and metadata

**Default WS-Federation Settings:**
* If `app_auth = "wsfed"` or `app_auth = "WS-Federation"` but no `wsfed_settings` block is provided:
  * Provider automatically creates default WS-Federation settings structure
  * All mandatory fields are included with default values
  * Empty arrays are sent instead of null values

**API Payload Behavior for WS-Federation:**
* When `app_auth = "wsfed"` or `app_auth = "WS-Federation"` in Terraform config, the API payload sends `app_auth = "wsfed"`
* This is the expected behavior for WS-Federation applications

**OpenID Connect Special Behaviors:**

**First-time App Creation with OpenID Connect:**
* When creating a new app with `app_auth = "oidc"` or `app_auth = "OpenID Connect 1.0"` for the first time:
  * **No `app_authentication` block needed initially**
  * API automatically assigns a default IDP
  * API creates default OIDC settings structure

**Default OIDC Settings:**
* If `app_auth = "oidc"` or `app_auth = "OpenID Connect 1.0"` but no `oidc_settings` block is provided:
  * Provider automatically creates default OIDC settings structure
  * Empty object `{}` is sent in the API payload
  * API response contains endpoint URLs that are read back into the state

**API Payload Behavior for OpenID Connect:**
* When `app_auth = "oidc"` or `app_auth = "OpenID Connect 1.0"` in Terraform config, the API payload sends `app_auth = "oidc"`
* This is the expected behavior for OpenID Connect applications

**JWT Authentication Special Behaviors:**

**Default JWT Settings:**
* When `wapp_auth = "jwt"` but no JWT-specific fields are provided:
  * Default values are automatically applied:
    * `jwt_grace_period = "60"`
    * `jwt_return_option = "401"`
    * Other JWT fields default to empty strings
* JWT settings are only sent in the API payload when `wapp_auth = "jwt"`

#### Example Usage

**Basic SAML2.0 Application:**
```hcl
resource "eaa_application" "saml_app" {
  provider = eaa

  name        = "SAML Application"
  description = "SAML-enabled application"
  host        = "saml-app.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "SAML2.0"
    # Other advanced settings...
  }

  # No app_authentication block needed for first-time creation
  # No saml_settings block needed - defaults will be applied
}
```

**SAML2.0 Application with Custom Settings:**
```hcl
resource "eaa_application" "custom_saml_app" {
  provider = eaa

  name        = "Custom SAML App"
  description = "SAML application with custom settings"
  host        = "custom-saml.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "SAML2.0"
    # Other advanced settings...
  }

  saml_settings {
    sp {
      entity_id = "https://custom-saml.example.com"
      acs_url   = "https://custom-saml.example.com/saml/acs"
      slo_url   = "https://custom-saml.example.com/saml/slo"
      req_bind  = "redirect"
      force_auth = false
      req_verify = false
      sign_cert  = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
      resp_encr  = false
      encr_cert  = ""
      encr_algo  = "aes256-cbc"
      slo_req_verify = true
      dst_url    = ""
    }
    
    idp {
      entity_id = "https://test-idp.example.com"
      metadata  = ""
      sign_cert = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
      sign_key  = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
      self_signed = false
      sign_algo   = "SHA256"
      resp_bind   = "post"
      slo_url     = "https://test-idp.example.com/saml/slo"
      ecp_enable  = false
      ecp_resp_signature = false
    }
    
    subject {
      fmt = "email"
      src = "user.email"
      val = ""
      rule = ""
    }
    
    attrmap {
      name = "email"
      fname = "Email"
      fmt  = "email"
      val  = ""
      src  = "user.email"
      rule = ""
    }
  }
}
```

**Kerberos Application:**
```hcl
resource "eaa_application" "kerberos_app" {
  provider = eaa

  name        = "Kerberos Application"
  description = "Kerberos-enabled application"
  host        = "kerberos-app.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "kerberos"
    app_auth_domain = "EXAMPLE.COM"
    app_client_cert_auth = "false"
    forward_ticket_granting_ticket = "false"
    keytab = ""
    service_principal_name = "HTTP/kerberos-app.example.com"
  }
}
```

**WS-Federation Application with Default Settings:**
```hcl
resource "eaa_application" "wsfed_app" {
  provider = eaa

  name        = "WS-Federation Application"
  description = "WS-Federation-enabled application"
  host        = "wsfed-app.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "WS-Federation"
    # Other advanced settings...
  }

  # No app_authentication block needed for first-time creation
  # No wsfed_settings block needed - defaults will be applied
}
```

**WS-Federation Application with Custom Settings:**
```hcl
resource "eaa_application" "custom_wsfed_app" {
  provider = eaa

  name        = "Custom WS-Federation App"
  description = "WS-Federation application with custom settings"
  host        = "custom-wsfed.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "WS-Federation"
    # Other advanced settings...
  }

  wsfed_settings {
    sp {
      entity_id = "https://custom-wsfed.example.com"
      slo_url   = "https://custom-wsfed.example.com/wsfed/slo"
      dst_url   = "https://custom-wsfed.example.com/wsfed/dst"
      resp_bind = "post"
      token_life = 7200
      encr_algo  = "aes128-cbc"
    }
    
    idp {
      entity_id = "https://test-idp.example.com/wsfed/idp/sso"
      sign_algo = "SHA1"
      sign_cert = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
      sign_key  = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
      self_signed = false
    }
    
    subject {
      fmt = "persistent"
      custom_fmt = ""
      src = "user.persistentId"
      val = ""
      rule = ""
    }
    
    attrmap {
      name = "email"
      fmt  = "email"
      custom_fmt = ""
      val  = ""
      src  = "user.email"
      rule = ""
    }
    
    attrmap {
      name = "firstName"
      fmt  = "firstName"
      custom_fmt = ""
      val  = ""
      src  = "user.firstName"
      rule = ""
    }
  }
}
```
**OpenID Connect Application with Default Settings:**
```hcl
resource "eaa_application" "oidc_app" {
  provider = eaa

  name        = "OpenID Connect Application"
  description = "OIDC-enabled application"
  host        = "oidc-app.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    app_auth = "OpenID Connect 1.0"
    # Other advanced settings...
  }

  # No app_authentication block needed for first-time creation
  # No oidc_settings block needed - defaults will be applied
}
```

**JWT Authentication Application:**
```hcl
resource "eaa_application" "jwt_app" {
  provider = eaa

  name        = "JWT Authentication Application"
  description = "JWT-enabled application"
  host        = "jwt-app.example.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "backend.example.com"
  }
  
  popregion = "us-east-1"
  agents = ["EAA_DC1_US1_Access_01"]
  auth_enabled = "true"

  advanced_settings {
    wapp_auth = "jwt"
    jwt_issuers = "https://auth.example.com"
    jwt_audience = "my-app"
    jwt_grace_period = "90"
    jwt_return_option = "401"
    jwt_username = "sub"
    jwt_return_url = "https://jwt-app.example.com/return"
  }
}
```

**Tunnel Application (Valid Configuration):**
```hcl
resource "eaa_application" "tunnel_app" {
  provider = eaa

  name        = "Tunnel Application"
  description = "TCP tunnel application"
  host        = "tunnel.example.com"
  app_profile = "tcp"
  app_type    = "tunnel"
  domain      = "wapp"
  client_app_mode = "tunnel"
  
  popregion = "us-west-1"
  agents = ["EAA_DC1_US1_TCP_01"]
  auth_enabled = true

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "3200-6000"
    host       = "192.168.2.1"
  }

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "40199"
    host       = "192.168.2.2"
  }

  advanced_settings = jsonencode({
    # Health Check (Required for tunnel apps)
    health_check_type = "TCP"
    
    # Basic Configuration (Required for tunnel apps)
    websocket_enabled = true
    is_ssl_verification_enabled = "false"
    
    # Server Load Balancing (Allowed for tunnel apps)
    load_balancing_metric = "round_robin"
    session_sticky = true
    
    # Tunnel Client Parameters (Allowed for tunnel apps)
    acceleration = true
    x_wapp_read_timeout = "300"
    
    # Enterprise Connectivity (Allowed for tunnel apps)
    app_server_read_timeout = "300"
    idle_close_time_seconds = "300"
  })

  app_authentication {
    app_idp = "SQA-SC-5"
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "SAP-Admins"
      }
    }
  }
}
```

**Tunnel Application (Invalid Configuration - Will Fail):**
```hcl
resource "eaa_application" "invalid_tunnel_app" {
  provider = eaa

  name        = "Invalid Tunnel App"
  description = "This configuration will fail validation"
  host        = "invalid-tunnel.example.com"
  app_profile = "tcp"
  app_type    = "tunnel"
  domain      = "wapp"
  client_app_mode = "tunnel"
  
  # These will cause validation errors:
  saml = true  # NOT allowed for tunnel apps
  oidc = true  # NOT allowed for tunnel apps
  wsfed = true # NOT allowed for tunnel apps
  
  popregion = "us-west-1"
  agents = ["EAA_DC1_US1_TCP_01"]
  auth_enabled = true

  tunnel_internal_hosts {
    proto_type = 1
    port_range = "8080"
    host       = "internal.example.com"
  }

  advanced_settings = jsonencode({
    # These will cause validation errors:
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
* ```app_operational``` - (Computed) if the app is operational	
* ```app_status```  - (Computed) status of the app
* ```app_deployed``` - (Computed) is the app deployed	
* ```cname``` - (Computed) cname of the app
* ```uuid_url``` - (Computed) uuid of the app


#### Example Usage

The application resource is eaa_application. In order to create a new application through terraform, the following block could be used.

```sh
resource "eaa_application" "tfappname" {
  provider = eaa /* eaa provider */

  name        = "confluence" /* Application Name */
  description = "app created using terraform" /* Application Description */
  host        = "confluence.acmewapp.com" /* The external hostname for the application */
  app_profile = "http" /* The access application profile */
  app_type    = "enterprise" /* application type */
  domain = "wapp"
  client_app_mode = "tcp"  /* mode of client applications */
  
  servers { /* EAA application server details. */
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "10.2.0.201"
  }
  
  popregion = "us-east-1" /* The target region to deploy the app */

  agents = ["agent1", "agent2"] /* List of connectors assigned to application */

  auth_enabled = "true" /* is app authentication enabled */
  
  app_authentication {
    app_idp = "enterprise-idp" /* name of IDP assigned to app */
    
    app_directories { /* List of directories assigned to the application */
      name = "Cloud Directory"
      app_groups { /* List of groups under the directory that are assigned to the applicaion */
        name = "group-1"
      }
      app_groups {
        name = "group-2"
      }
    }
  }
}

advanced_settings {
      is_ssl_verification_enabled = "false" /* is the connector verifying the origin server certificate */
      ignore_cname_resolution = "true" /* if the end user is accessing the application through Akamai CDN, which connects to the EAA cloud */
      g2o_enabled = "true" /* Is G2O enabled */
}


```  
example application configurations could be found under the examples directory.
