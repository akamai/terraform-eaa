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
  * is_ssl_verification_enabled - (Optional) controls if the EAA connector performs origin server certificate validation
  * ignore_cname_resolution - if the end user is accessing the application through Akamai CDN, which connects to the EAA cloud.   
  * g2o_enabled - Enables a G2O configuration for an application. Used only if you've enabled Akamai Edge Enforcement.
  * x_wapp_read_timeout - (Required for Tunnel apps)
  * internal_hostname - internal host name
  * internal_host_port - internal host port
  * allow_cors - (Optional) allows HTTP applications to make cross-origin resource sharing calls to other applications.
  * cors_origin_list - (Optional) space delimited list of hosts that can access this application if allow_cors is enabled.
  * cors_method_list - (Optional) space delimited list of HTTP methods that can be sent to this application if allow_cors is enabled.
  * cors_header_list - (Optional) space delimited list of HTTP headers that can be sent to this application if allow_cors is enabled.
  * cors_support_credential - (Optional) allows requests that are made with credentials if allow_cors is enabled.
  * cors_max_age - (Optional) - duration (in seconds) for which an allowed host's pre-flight request is cached and trust is maintained by the application, if allow_cors is enabled.
  * websocket_enabled - (Optional) - controls if the HTTP application uses websockets for HTTP transport.
  * sticky_agent - (Optional) - controls if the requests always get routed to the same connector.
  * app_cookie_domain - (Optional) - allows to configure common SSO domain.
  * logout_url - (Optional) - URL that is triggered when the user is logged out of this application.
  * sentry_redirect_401 - (Optional) - select this if the application is unable to handle HTTP 302 redirect to validate the logged-in user's session.
  * custom_headers - (Optional) - headers to insert and forward to the origin application.

  **NEW: Application Authentication Type (`app_auth`)**
  * ```app_auth``` - (Optional) The type of application authentication. Default "none"
    * **Allowed Values**: "none", "kerberos", "basic", "NTLMv1", "NTLMv2", "SAML2.0", "wsfed", "oidc", "OpenID Connect 1.0"
    * **Special Behavior**: When set to "SAML2.0", "wsfed", "oidc", or "OpenID Connect 1.0", the corresponding boolean flags (`saml`, `wsfed`, `oidc`) are automatically set to `true`
    * **API Payload**: 
      * When `app_auth` is "SAML2.0" in Terraform config, the `app_auth` field in the API payload is sent as "none"
      * When `app_auth` is "wsfed" or "WS-Federation" in Terraform config, the `app_auth` field in the API payload is sent as "wsfed"
      * When `app_auth` is "oidc" or "OpenID Connect 1.0" in Terraform config, the `app_auth` field in the API payload is sent as "oidc"

  **NEW: User-Facing Authentication Type (`wapp_auth`)**
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

  **NEW: Kerberos Authentication Settings** (Only applicable when `app_auth = "kerberos"`)
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
