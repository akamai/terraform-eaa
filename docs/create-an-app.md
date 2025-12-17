# Create a new EAA Application

A Terraform configuration is a complete document written in HCL (Hashicorp Configuration language) that tells Terraform how to manage a given collection of infrastructure.
Configuration files tell Terraform what plugins to install, what infrastructure to create, and what data to fetch.
The main purpose of the Terraform language is declaring resources, which represent infrastructure objects. The following sections describe how to define the resource eaa_application in terraform configuration file.

## Related Documentation

- [Advanced Settings Reference](./advanced-settings.md) - Comprehensive guide to all advanced settings parameters
- [Application Type Configurations](./app-type-configurations.md) - App type specific configurations and restrictions
 - [Create a Connector](./create-connector.md) - How to provision a connector with Terraform
 - [Connector Pool Management](./connector-pool.md) - Manage connector pools, tokens, and assignments

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
* ```auth_enabled``` - (Required) - Is the application authentication enabled
* ```app_authentication``` - (Optional) dictionary with the application authentication data
  * app_idp - Name of the application IDP
    * app_directories - List of application directories
      * name - Name of the dictionary
      * app_groups - list of subset of directory's groups that are assigned to the application.
* ```app_auth``` - (Optional) Application-to-origin authentication method (configured in `advanced_settings`). See [Authentication Parameters](./authentication_advsettings.md). Default "none"
* ```wapp_auth``` - (Optional) User-facing authentication at the access page (configured in `advanced_settings`). See [Authentication Parameters](./authentication_advsettings.md). Default "form"
* ```protocol``` - (Optional, for SaaS apps) Authentication protocol. Allowed values: "SAML", "SAML2.0", "OpenID Connect 1.0", "OIDC", "WSFed", "WS-Federation". Note: For WS-Federation, both "WSFed" and "WS-Federation" are supported (lowercase "wsfed" is NOT supported). See [Application Type Configurations](./app-type-configurations.md) for settings, limitations, and restrictions, and [Authentication Parameters](./authentication_advsettings.md) for details.
* ```saml``` - (Computed) Boolean flag indicating if SAML authentication is enabled (deprecated - use `app_auth` in advanced_settings for enterprise apps, or `protocol` for SaaS apps)
* ```wsfed``` - (Computed) Boolean flag indicating if WS-Federation authentication is enabled (deprecated - use `app_auth` in advanced_settings for enterprise apps, or `protocol` for SaaS apps)
* ```oidc``` - (Computed) Boolean flag indicating if OpenID Connect authentication is enabled (deprecated - use `app_auth` in advanced_settings for enterprise apps, or `protocol` for SaaS apps)
* ```saml_settings``` - (Optional) SAML configuration settings
* ```wsfed_settings``` - (Optional) WS-Federation configuration settings
* ```oidc_settings``` - (Optional) OpenID Connect configuration settings

#### Computed Attributes

The following attributes are computed (read-only) and are set by the provider:

* ```app_operational``` - (Computed) Indicates if the app is operational
* ```app_status``` - (Computed) Status of the app
* ```app_deployed``` - (Computed) Indicates if the app is deployed
* ```cname``` - (Computed) CNAME of the app
* ```uuid_url``` - (Computed) UUID of the app
* ```popname``` - (Computed) The name for the target pop to deploy the application

#### Advanced Settings

For comprehensive documentation of all advanced settings parameters, see [Advanced Settings Reference](./advanced-settings.md).

#### Authentication Settings

For detailed documentation of authentication parameters including SAML, WS-Federation, OpenID Connect, JWT, and Kerberos configurations, see [Advanced Settings Reference](./advanced-settings.md).

#### Validation Rules

For detailed validation rules and app type specific configurations, see [Application Type Configurations](./app-type-configurations.md).

#### Error Messages

For complete error message reference, see [Advanced Settings Reference](./advanced-settings.md) and [Application Type Configurations](./app-type-configurations.md).

#### Special Behaviors

For detailed information about special behaviors for SAML, WS-Federation, OpenID Connect, and JWT authentication, see [Advanced Settings Reference](./advanced-settings.md).

#### Example Usage

For comprehensive examples of different application types and configurations, see:
- [Advanced Settings Reference](./advanced-settings.md) - Examples for advanced settings
- [Application Type Configurations](./app-type-configurations.md) - Examples for each app type

#### Examples

For comprehensive examples of different application types and configurations, see the [examples/](../examples/) directory in the repository.
