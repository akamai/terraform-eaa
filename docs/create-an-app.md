# Create a new EAA Application

A Terraform configuration is a complete document written in HCL (Hashicorp Configuration language) that tells Terraform how to manage a given collection of infrastructure.
Configuration files tell Terraform what plugins to install, what infrastructure to create, and what data to fetch.
The main purpose of the Terraform language is declaring resources, which represent infrastructure objects. The following sections describe how to define the resource eaa_application in terraform configuration file.

## Related Documentation

- [Advanced Settings Reference](advanced-settings.md) - Comprehensive guide to all advanced settings parameters
- [Application Type Configurations](app-type-configurations.md) - App type specific configurations and restrictions

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
* ```advanced_settings``` - (Optional) JSON-encoded string of advanced settings. See [Advanced Settings Reference](advanced-settings.md) for complete documentation.

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

For detailed validation rules and app type specific configurations, see [Application Type Configurations](app-type-configurations.md).

#### Error Messages

For complete error message reference, see [Advanced Settings Reference](advanced-settings.md) and [Application Type Configurations](app-type-configurations.md).

#### Special Behaviors

For detailed information about special behaviors for SAML, WS-Federation, OpenID Connect, and JWT authentication, see [Advanced Settings Reference](advanced-settings.md).

#### Example Usage

For comprehensive examples of different application types and configurations, see:
- [Advanced Settings Reference](advanced-settings.md) - Examples for advanced settings
- [Application Type Configurations](app-type-configurations.md) - Examples for each app type
* ```app_operational``` - (Computed) if the app is operational	
* ```app_status```  - (Computed) status of the app
* ```app_deployed``` - (Computed) is the app deployed	
* ```cname``` - (Computed) cname of the app
* ```uuid_url``` - (Computed) uuid of the app

#### Basic Example

```hcl
resource "eaa_application" "example_app" {
  provider = eaa

  name        = "example-app"
  description = "Example EAA application"
  host        = "example.acmewapp.com"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  client_app_mode = "tcp"
  
  servers {
    orig_tls        = true
    origin_protocol = "https"
    origin_port     = 443
    origin_host     = "10.2.0.201"
  }
  
  popregion = "us-east-1"
  agents = ["agent1", "agent2"]
  auth_enabled = "true"
  
  app_authentication {
    app_idp = "enterprise-idp"
    
    app_directories {
      name = "Cloud Directory"
      app_groups {
        name = "group-1"
      }
    }
  }

}
```

For more examples, see the `examples/` directory in the repository.
