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
