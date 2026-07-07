# eaa_idp

Manages the lifecycle of an EAA Identity Provider (IDP).

## Overview

The `eaa_idp` resource provides full CRUD support for EAA Identity Providers. An IDP authenticates users accessing EAA applications and can be associated with directories containing users and groups.

Key features:
- Automatic rollback on create failure
- Name-based resolution for certificates, PoPs, and directories
- Auto-deploy after create and update
- Support for all IDP types (certificate-based, SAML, OIDC, WS-Federation)

## Argument Reference

### Required

* `name` - (Required) IDP name.

### Optional - Core Settings

* `description` - (Optional) IDP description.
* `idp_type` - (Optional) IDP type. Common values: `2` = certificate-based.
* `login_host` - (Optional) Login hostname prefix (without domain suffix).
* `login_domain` - (Optional) Login domain type. `2` = WAPP (Akamai-managed domain).
* `pop` - (Optional) PoP name (resolved to uuid_url via PoPs list API).
* `failover_pop` - (Optional) Failover PoP name (resolved to uuid_url via PoPs list API).

### Optional - Session & Security

* `cookie_expiry` - (Optional) Session cookie expiry in minutes.
* `trust_expiry` - (Optional) Trust expiry in days.
* `login_lockout` - (Optional) Login lockout. Values: `"true"` or `"off"` (string, not boolean).
* `max_login_failures` - (Optional) Failed logins before lockout.
* `lockout_interval` - (Optional) Lockout duration in minutes.

### Optional - Authentication & Certificates

* `cert` - (Optional) TLS certificate name (resolved to uuid_url via GetCertificates).
* `client_cert` - (Optional) Client certificate name (resolved to uuid_url via GetCertificates).
* `saml_idp_custom_sign_cert` - (Optional) Custom SAML signing certificate name (resolved via GetCertificates).
* `saml_cert_type` - (Optional) `1` = self-signed, `2` = custom.
* `auth_request_signed` - (Optional) Sign SAML auth requests.
* `auth_response_encrypt` - (Optional) Encrypt SAML auth responses.
* `client_principle_name` - (Optional) Client principal name template.

### Optional - SAML & Federation

* `saml_url` - (Optional) SAML URL.
* `logout_url` - (Optional) Post-logout URL.

### Optional - Multi-Factor Authentication

* `enable_mfa` - (Optional) Enable MFA.
* `mfa_settings` - (Optional) Map of MFA sub-fields (duo, pushzero, totp, sms, email, etc.).

### Optional - Client & Integration

* `enable_access_client` - (Optional) Enable EAA Client.
* `gc_client_enabled` - (Optional) Enable Global Cloud client.
* `etp_enabled` - (Optional) Enable ETP integration.
* `agent_installation_profile` - (Optional) Enable agent install profile.

### Optional - TLS & Customization

* `default_tls_suite` - (Optional) Use default TLS suite.
* `custom_tls_suite_name` - (Optional) Custom TLS suite name.
* `domains` - (Optional) List of custom domains.
* `default_language` - (Optional) Login portal language (e.g., "english").

### Optional - Redirects & UI

* `post_auth_failure_redirect_type` - (Optional) Auth failure redirect type. Values: `EAA_APPS_PORTAL` or custom.
* `post_auth_failure_redirect_custom_url` - (Optional) Custom auth failure redirect URL (when type is custom).
* `post_logout_redirect_type` - (Optional) Logout redirect type. Values: `EAA_APPS_PORTAL` or custom.
* `post_logout_redirect_custom_url` - (Optional) Custom logout redirect URL (when type is custom).
* `helpdesk_email` - (Optional) Helpdesk contact email.

### Optional - Flat Maps

* `settings` - (Optional) Map of IDP settings (portal theme, client cert auth, IWA, force login, etc.).
* `attribute_map` - (Optional) Map of SAML attribute mappings.
* `multilang_fields` - (Optional) Map of multi-language field overrides.

### Optional - Miscellaneous

* `source` - (Optional) Source identifier.

### Optional - Directory Association

* `directories` - (Optional) List of directory names to associate. Directory names are resolved to uuid_url via the directories list API.

## Computed Attributes

The following attributes are computed and read-only:

* `uuid_url` - Unique identifier for the IDP.
* `created_at` - Creation timestamp.
* `modified_at` - Last modification timestamp.
* `company_id` - Company identifier.
* `localization` - Data center localization code.
* `status` - IDP status code.
* `dns_added` - Whether DNS records have been created.
* `login_cname` - Full login CNAME.
* `login_dialin_server` - Dial-in server hostname.
* `login_suffix` - Login domain suffix.
* `domain_suffix` - Domain suffix for login host.
* `client_host` - Full client-facing URL.
* `pop_name` - Name of the assigned PoP.
* `idp_status` - Deployment status code.
* `idp_operational` - Operational status code.
* `idp_deployed` - Whether the IDP is deployed.
* `directory_count` - Number of attached directories.
* `app_count` - Number of applications using this IDP.
* `tls_suite_name` - Resolved TLS suite name.

## Gotchas

### login_lockout String Value

`login_lockout` uses string values `"true"` or `"off"`, not boolean `true`/`false`. This mirrors the API's behavior.

```hcl
# Correct
login_lockout = "true"

# Incorrect
login_lockout = true
```

### Name Resolution

The resource accepts human-readable names for certificates, PoPs, and directories. The provider automatically resolves them to uuid_url internally:

| Field | Resolution Method |
|-------|-------------------|
| `cert` | `GetCertificates` - find cert by name |
| `client_cert` | `GetCertificates` - find cert by name |
| `saml_idp_custom_sign_cert` | `GetCertificates` - find cert by name |
| `pop` | PoPs list API - find PoP by name |
| `failover_pop` | PoPs list API - find PoP by name |
| `directories` | `ListDirectories` - find directory by name |

On Read, UUIDs from the API are reverse-resolved back to names so Terraform state matches your config. This prevents unnecessary plan diffs.

### Auto-Deploy

The provider automatically deploys the IDP after every create and update operation. No manual deploy step is required.

### Create Rollback

If any step fails after the initial IDP creation (PUT update, directory association, or deploy), the provider automatically deletes the IDP and returns the original error. This prevents orphaned IDPs from failed configurations.

### Directory Disassociation

When removing directories from an IDP, the provider uses the **membership uuid_url** (from the `directories_membership` endpoint), not the directory uuid_url. This is handled automatically by the provider.

### GET-Modify-PUT Pattern

Like the connector resource, updating an IDP requires a GET-modify-PUT pattern. The provider fetches the current state, overlays your changes, and sends the full configuration to the API.

## Examples

### Basic IDP with Directory Association

```hcl
resource "eaa_idp" "corp_idp" {
  name        = "Corp IDP"
  description = "Corporate identity provider"
  idp_type    = 2
  login_host  = "corp-login"
  pop         = "us-east-pop"

  cookie_expiry = 120
  trust_expiry  = 365

  directories = ["Cloud Directory"]

  settings = {
    force_login       = "true"
    force_login_after = "7200"
    captive_portal    = "true"
  }
}
```

### IDP with MFA and Login Lockout

```hcl
resource "eaa_idp" "secure_idp" {
  name        = "Secure IDP"
  description = "IDP with MFA and lockout policies"
  idp_type    = 2
  login_host  = "secure-login"
  pop         = "us-west-pop"

  login_lockout       = "true"
  max_login_failures  = 5
  lockout_interval    = 30
  cookie_expiry       = 60
  trust_expiry        = 180

  enable_mfa = true

  mfa_settings = {
    duo_enabled   = "true"
    totp_enabled  = "true"
    email_enabled = "true"
  }

  directories = ["Corporate LDAP", "Cloud Directory"]
}
```

### IDP with Custom Certificates

```hcl
resource "eaa_custom_app_certificate" "idp_cert" {
  name        = "idp-tls-cert"
  cert        = file("certs/idp.crt")
  private_key = file("certs/idp.key")
}

resource "eaa_idp" "custom_cert_idp" {
  name       = "Custom Cert IDP"
  idp_type   = 2
  login_host = "custom-login"
  pop        = "eu-west-pop"

  cert        = eaa_custom_app_certificate.idp_cert.name
  client_cert = "client-auth-cert"

  cookie_expiry = 90
  trust_expiry  = 365
}
```

### IDP with SAML Configuration

```hcl
resource "eaa_idp" "saml_idp" {
  name        = "SAML IDP"
  description = "IDP with SAML authentication"
  idp_type    = 2
  login_host  = "saml-login"
  pop         = "us-east-pop"

  saml_url                   = "https://saml.example.com/sso"
  logout_url                 = "https://saml.example.com/logout"
  saml_cert_type             = 2
  saml_idp_custom_sign_cert  = "saml-signing-cert"
  auth_request_signed        = true
  auth_response_encrypt      = true

  cookie_expiry = 120
  trust_expiry  = 365

  attribute_map = {
    email      = "urn:oid:0.9.2342.19200300.100.1.3"
    first_name = "urn:oid:2.5.4.42"
    last_name  = "urn:oid:2.5.4.4"
  }

  directories = ["Cloud Directory"]
}
```

### Using Directories Data Source

```hcl
# Discover available directories
data "eaa_data_source_directories" "all" {}

output "directory_names" {
  value = [for d in data.eaa_data_source_directories.all.directories : d.name]
}

# Use a discovered directory in an IDP
resource "eaa_idp" "dynamic_idp" {
  name       = "Dynamic IDP"
  idp_type   = 2
  login_host = "dynamic-login"
  pop        = "us-east-pop"

  directories = [
    for d in data.eaa_data_source_directories.all.directories :
    d.name if d.service == 6  # Cloud Directory service type
  ]
}
```

## Import

Existing IDPs can be imported using their uuid_url:

```bash
terraform import eaa_idp.my_idp <uuid_url>
```

Example:

```bash
terraform import eaa_idp.corp_idp crux/v1/mgmt-pop/idp/a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6
```

After import, run `terraform plan` to see any configuration drift. The Read function will populate all attributes including directories (by name, not UUID).

## See Also

- [eaa_data_source_directories](data-sources.md#eaa_data_source_directories) - List available directories
- [eaa_data_source_idps](data-sources.md#eaa_data_source_idps) - List existing IDPs
- [eaa_data_source_pops](data-sources.md#eaa_data_source_pops) - Discover available PoPs
- [eaa_application](eaa_application.md) - Applications reference IDPs for authentication
- [examples/idp.tf](../examples/idp.tf) - Complete working examples
