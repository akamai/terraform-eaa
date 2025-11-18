# Authentication Parameters

Configure application-level authentication mechanisms.

## User-Facing Authentication (`wapp_auth`)
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

## Application Authentication (`app_auth`)
* `app_auth` - (Optional) Defines how the application authenticates to the origin; select one of the methods below.

* `none` - (Optional) No application-level authentication performed to the origin
* `kerberos` - (Optional) Authenticates to the origin using Kerberos 
* `basic` - (Optional) Uses HTTP Basic authentication to the origin
* `NTLMv1` - (Optional) Authenticates to the origin using NTLMv1 
* `NTLMv2` - (Optional) Authenticates to the origin using NTLMv2
* `SAML2.0` - (Optional) Federated SSO using SAML 2.0
* `WS-Federation` - (Optional)  using the WS-Federation 
* `OpenID Connect 1.0` - (Optional)  using OpenID Connect 1.0

### Optional Fields (Kerberos)
* `app_auth_domain` - (Optional) Kerberos domain name. Default ""
* `forward_ticket_granting_ticket` - (Optional) Forward TGT. Allowed values: "true", "false". Default "false"
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

## Examples
Example files:
- [examples/jwt_application.tf](../examples/jwt_application.tf)
- [examples/kerberos_application.tf](../examples/kerberos_application.tf)
- [examples/saml_application.tf](../examples/saml_application.tf)
- [examples/oidc_application.tf](../examples/oidc_application.tf)
- [examples/wsfederation_application.tf](../examples/wsfederation_application.tf)
