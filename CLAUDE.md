# EAA Terraform Provider — Claude Guide

This guide helps Claude assist users in writing Terraform configurations for [Akamai Enterprise Application Access (EAA)](https://techdocs.akamai.com/eaa/docs).

## Provider Overview

Akamai EAA is a Zero Trust network access solution that provides secure access to enterprise applications without a VPN. This Terraform provider manages EAA resources as code.

### Provider Configuration

```hcl
terraform {
  required_providers {
    eaa = {
      source  = "terraform.eaaprovider.dev/eaaprovider/eaa"
      version = "2.0.0"
    }
  }
}

provider "eaa" {
  contractid       = "contract-id"
  accountswitchkey = "account-switch-key"  # optional
  edgerc           = ".edgerc"             # optional, defaults to ~/.edgerc
}
```

Authentication uses an `.edgerc` file created from Akamai Control Center with READ-WRITE permission to Enterprise Application Access. Environment variables are also supported — see [Akamai Terraform environment variables](https://techdocs.akamai.com/terraform/docs/environment-variables).

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Application** | A resource accessed through EAA — web apps, RDP, SSH, tunnels, bookmarks, or SaaS apps |
| **Connector** | A VM deployed in the customer's data center that bridges EAA cloud to internal networks |
| **Connector Pool** | A group of connectors with shared registration tokens and application assignments |
| **App Type** | `enterprise` (default, proxied access), `tunnel` (TCP/UDP tunnel via EAA Client), `bookmark` (URL shortcut), `saas` (federated SSO) |
| **App Profile** | Protocol: `http`, `tcp`, `rdp`, `ssh`, `vnc`, `smb`, `sharepoint`, `jira`, `jenkins`, `confluence` |
| **PoP** | Point of Presence — EAA edge location where traffic is processed |
| **IDP** | Identity Provider used for authentication (SAML, OIDC, WS-Fed) |
| **Domain** | `wapp` (Akamai-managed hostname) or `custom` (customer-owned hostname, requires certificate) |

## Resources

### eaa_application

Manages the full lifecycle of an EAA application including servers, authentication, ACL rules, certificates, and advanced settings.

**Key attributes:**

| Attribute | Required | Description |
|-----------|----------|-------------|
| `name` | Yes | Application name |
| `app_profile` | No | Protocol: `http` (default), `tcp`, `rdp`, `ssh`, `vnc`, `smb` |
| `app_type` | No | `enterprise` (default), `tunnel`, `bookmark`, `saas` |
| `domain` | No | `wapp` (default) or `custom` |
| `host` | No | External hostname |
| `popregion` | No | Target deployment region |
| `agents` | No | List of connector names to assign |
| `auth_enabled` | No | `"true"` or `"false"` (string, not bool). Default `"false"` |
| `servers` | No | Origin server list (`origin_host`, `origin_port`, `origin_protocol`) |
| `tunnel_internal_hosts` | No | For tunnel apps: `host`, `port_range`, `proto_type` (1=TCP, 2=UDP, 3=ALL) |
| `advanced_settings` | No | Flat map of key/value pairs for health checks, load balancing, auth, CORS, etc. |
| `app_authentication` | No | IDP, directories, and groups for auth |
| `saml_settings` | No | SAML SP/IDP/subject/attribute configuration |
| `oidc_settings` | No | OpenID Connect configuration |
| `wsfed_settings` | No | WS-Federation configuration |
| `service` | No | ACL access rules |
| `cert_type` | No | `self_signed` (default) or `uploaded` for custom domains |
| `cert_name` | No | Name of uploaded certificate (required when `cert_type = "uploaded"`) |
| `protocol` | No | SaaS only: `SAML`, `SAML2.0`, `OIDC`, `OpenID Connect 1.0`, `WSFed`, `WS-Federation` |

**Gotchas:**
- `auth_enabled` uses **string** `"true"`/`"false"`, not boolean
- `orig_tls` is deprecated — do not set it; it's computed from `origin_protocol`
- `protocol` is case-sensitive — `wsfed` (lowercase) is NOT valid; use `WSFed` or `WS-Federation`
- `tls_suite_name = ""` (empty string) has no effect — the API ignores it
- `advanced_settings` accepts any key the EAA API supports, not just the ones documented

Full reference: [docs/eaa_application.md](docs/eaa_application.md)

### eaa_connector

Manages an EAA connector VM.

**Key attributes:**

| Attribute | Required | Description |
|-----------|----------|-------------|
| `name` | Yes | Connector name |
| `description` | No | Description |
| `package` | Yes | Installer: `vmware`, `vbox`, `aws`, `kvm`, `hyperv`, `docker`, `azure`, `google`, `softlayer`, `fujitsu_k5` |
| `debug_channel_permitted` | No | Enable debug channel for support |
| `advanced_settings.network_info` | Yes (nested) | List of CIDRs/IPs the connector can reach |

**Computed:** `uuid_url`, `reach`, `state`, `download_url`, `public_ip`, `private_ip`

Full reference: [docs/eaa_connector.md](docs/eaa_connector.md)

### eaa_connector_pool

Manages a connector pool with connectors, registration tokens, and app assignments.

**Key attributes:**

| Attribute | Required | Description |
|-----------|----------|-------------|
| `name` | Yes | Pool name |
| `package_type` | Yes | Same values as connector `package` |
| `description` | No | Description |
| `infra_type` | No | `eaa`, `unified`, `broker`, `cpag` |
| `operating_mode` | No | `connector`, `peb`, `combined`, `cpag_public`, `cpag_private`, `connector_with_china_acceleration` |
| `connectors` | No | List of connector names |
| `apps` | No | List of app names assigned to this pool |
| `registration_tokens` | No | Tokens: `name` (required), `max_use`, `expires_at` (RFC3339), `generate_embedded_img` |

**Gotcha:** `infra_type = "cpag"` requires `operating_mode` to be `cpag_public` or `cpag_private`, and vice versa.

Full reference: [docs/eaa_connector_pool.md](docs/eaa_connector_pool.md)

## Data Sources

| Data Source | Returns | When to Use |
|-------------|---------|-------------|
| `eaa_data_source_pops` | PoPs with region, facility, failover info | Discover available regions for `popregion` |
| `eaa_data_source_appcategories` | App category names and UUIDs | Look up valid values for `app_category` |
| `eaa_data_source_agents` | Connectors with reachability, IPs, pool membership | Find connector names for `agents`, check reach status |
| `eaa_data_source_idps` | IDPs with directories and groups | Look up IDP/directory/group names for `app_authentication` |
| `eaa_data_source_tls_cipher_suites` | TLS suites for a specific app (requires `app_uuid_url`) | Discover valid `tls_suite_name` values |
| `eaa_connector_pools` | Pools with connectors, tokens, and app assignments | List existing pools, connectors, and tokens |
| `eaa_data_source_apps` | App names and UUIDs | Reference existing apps by name |

Usage examples and full attribute lists: [docs/data-sources.md](docs/data-sources.md)

### Quick Data Source Examples

```hcl
# Discover available connectors
data "eaa_data_source_agents" "all" {}
output "reachable" {
  value = [for a in data.eaa_data_source_agents.all.agents : a.name if a.reach == 1]
}

# Look up IDP and directory names for auth config
data "eaa_data_source_idps" "all" {}
output "idps" {
  value = [for idp in data.eaa_data_source_idps.all.idps : idp.name]
}

# Get TLS suites for an app
data "eaa_data_source_tls_cipher_suites" "app_tls" {
  app_uuid_url = eaa_application.web_app.uuid_url
}
```

## Common Patterns

### Enterprise HTTP App with Auth

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

### Tunnel App with Internal Hosts

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

### Connector + Pool + App Wiring

```hcl
resource "eaa_connector" "dc1" {
  name    = "dc1-connector"
  package = "aws"
  advanced_settings {
    network_info = ["10.0.0.0/16"]
  }
}

resource "eaa_connector_pool" "main" {
  name         = "main-pool"
  package_type = "aws"
  connectors   = [eaa_connector.dc1.name]
  apps         = [eaa_application.web_app.name]

  registration_tokens {
    name       = "onboard-token"
    max_use    = 5
    expires_at = "2030-01-01T00:00:01Z"
  }
}
```

### Auth Methods

**Enterprise SAML** — set `app_auth = "SAML2.0"` in `advanced_settings`, optionally add `saml_settings` block:
```hcl
advanced_settings = { app_auth = "SAML2.0" }
saml_settings {
  idp { self_signed = true }
}
```

**Enterprise OIDC** — set `app_auth = "OpenID Connect 1.0"` in `advanced_settings`:
```hcl
advanced_settings = { app_auth = "OpenID Connect 1.0" }
```

**SaaS SAML/OIDC/WSFed** — use top-level `protocol` field (NOT `advanced_settings`):
```hcl
app_type = "saas"
protocol = "SAML2.0"  # or "OpenID Connect 1.0" or "WS-Federation"
```

**JWT** — set `wapp_auth = "jwt"` in `advanced_settings` (user-facing auth, not app-to-origin):
```hcl
advanced_settings = {
  wapp_auth        = "jwt"
  jwt_issuers      = "https://auth.example.com"
  jwt_audience     = "my-app"
  jwt_grace_period = "90"
  jwt_username     = "sub"
}
```

**Kerberos** — set `app_auth = "kerberos"` with keytab and SPN fields.

See full auth examples: [examples/auth_saml.tf](examples/auth_saml.tf), [examples/auth_oidc.tf](examples/auth_oidc.tf), [examples/auth_wsfed.tf](examples/auth_wsfed.tf), [examples/auth_kerberos.tf](examples/auth_kerberos.tf), [examples/auth_jwt.tf](examples/auth_jwt.tf)

### Custom Domain with Certificate

```hcl
resource "eaa_application" "custom_app" {
  name      = "Custom App"
  domain    = "custom"
  host      = "app.example.com"
  cert_type = "self_signed"   # or "uploaded" with cert_name = "my-cert"
  # ... rest of config
}
```

## Writing Terraform Configs — Guidance for Claude

When helping users compose Terraform configurations for this provider:

1. **Reference the docs** — Always check `docs/eaa_application.md`, `docs/eaa_connector.md`, `docs/eaa_connector_pool.md`, and `docs/data-sources.md` for attribute details. Check `examples/*.tf` for working configurations.

2. **Validate app type compatibility** — Not all settings work with all app types. Check the compatibility table in `docs/eaa_application.md` under "App Type Compatibility". Key rules:
   - Bookmark and SaaS apps do NOT support `advanced_settings`
   - Tunnel apps block most auth settings
   - `tunnel_internal_hosts` is only for `app_type = "tunnel"` with `client_app_mode = "tunnel"`
   - `servers` is used for enterprise apps and TCP-mode tunnels

3. **Suggest data sources** when users need dynamic values:
   - Need connector names? → `eaa_data_source_agents`
   - Need IDP/directory/group names? → `eaa_data_source_idps`
   - Need PoP regions? → `eaa_data_source_pops`
   - Need app categories? → `eaa_data_source_appcategories`
   - Need TLS suite names? → `eaa_data_source_tls_cipher_suites`

4. **Watch for common mistakes:**
   - `auth_enabled` is a **string** (`"true"`), not a boolean
   - `orig_tls` is deprecated — never set it
   - SaaS apps use `protocol` field, enterprise apps use `advanced_settings.app_auth`
   - `protocol` values are case-sensitive: `WSFed` or `WS-Federation`, NOT `wsfed`
   - Registration token `expires_at` must be RFC3339 with non-zero seconds (`:01` not `:00`)

5. **When unsure about advanced settings**, point the user to the full list in `docs/eaa_application.md`. The `advanced_settings` map accepts any key the EAA API supports.

## EAA API Reference

The provider is built on the [EAA API](https://techdocs.akamai.com/eaa-api/reference). Key endpoints by resource:

### Applications
| Operation | API Docs |
|-----------|----------|
| List applications | [GET /apps](https://techdocs.akamai.com/eaa-api/reference/get-apps) |
| Get application | [GET /app](https://techdocs.akamai.com/eaa-api/reference/get-app) |
| Create application | [POST /app](https://techdocs.akamai.com/eaa-api/reference/post-app) |
| Update application | [PUT /app](https://techdocs.akamai.com/eaa-api/reference/put-app) |
| Delete application | [DELETE /app](https://techdocs.akamai.com/eaa-api/reference/delete-app) |
| Deploy application | [POST /app/deploy](https://techdocs.akamai.com/eaa-api/reference/post-app-deploy) |
| G2O update | [POST /app/g2o](https://techdocs.akamai.com/eaa-api/reference/post-app-g2o) |
| Edge authentication | [POST /app/edgekey](https://techdocs.akamai.com/eaa-api/reference/post-app-edgekey) |
| List app connectors | [GET /app/connectors](https://techdocs.akamai.com/eaa-api/reference/get-app-connectors) |
| Assign connectors | [POST /app/connectors](https://techdocs.akamai.com/eaa-api/reference/post-app-connectors) |

### Connectors
| Operation | API Docs |
|-----------|----------|
| List connectors | [GET /connectors](https://techdocs.akamai.com/eaa-api/reference/get-connectors) |
| Get connector | [GET /connector](https://techdocs.akamai.com/eaa-api/reference/get-connector) |
| Create connector | [POST /connector](https://techdocs.akamai.com/eaa-api/reference/post-connector) |
| Update connector | [PUT /connector](https://techdocs.akamai.com/eaa-api/reference/put-connector) |
| Delete connector | [DELETE /connector](https://techdocs.akamai.com/eaa-api/reference/delete-connector) |
| Approve connector | [POST /connector/approve](https://techdocs.akamai.com/eaa-api/reference/post-connector-approve) |

### Identity Providers
| Operation | API Docs |
|-----------|----------|
| List IDPs | [GET /idps](https://techdocs.akamai.com/eaa-api/reference/get-idps) |
| List IDP directories | [GET /idp/directories](https://techdocs.akamai.com/eaa-api/reference/get-idp-directories) |
| Assign IDP to app | [POST /app/idp](https://techdocs.akamai.com/eaa-api/reference/post-app-idp) |
| Unassign IDP | [DELETE /app/idp](https://techdocs.akamai.com/eaa-api/reference/delete-app-idp) |
| Assign directory | [POST /app/directory](https://techdocs.akamai.com/eaa-api/reference/post-app-directory) |
| Assign directory groups | [POST /assign/app/groups](https://techdocs.akamai.com/eaa-api/reference/post-assign-app-groups) |
| Get directory membership | [GET /idp/directories/membership](https://techdocs.akamai.com/eaa-api/reference/get-idp-directories-membership) |

### Certificates
| Operation | API Docs |
|-----------|----------|
| Get certificate | [GET /certificate](https://techdocs.akamai.com/eaa-api/reference/get-certificate) |
| List certificates | [GET /certificates](https://techdocs.akamai.com/eaa-api/reference/get-certificates) |
| Create self-signed cert | [POST /certificate](https://techdocs.akamai.com/eaa-api/reference/post-certificate) |

### Access Control
| Operation | API Docs |
|-----------|----------|
| Get ACL service | [GET /app/services](https://techdocs.akamai.com/eaa-api/reference/get-app-services) |
| Enable/disable service | [PUT /rule](https://techdocs.akamai.com/eaa-api/reference/put-rule) |
| Create access rule | [POST /access-control-rule](https://techdocs.akamai.com/eaa-api/reference/post-access-control-rule) |
| Modify access rule | [PUT /access-control-rule](https://techdocs.akamai.com/eaa-api/reference/put-access-control-rule) |

### Other
| Operation | API Docs |
|-----------|----------|
| List app categories | [GET /app-categories](https://techdocs.akamai.com/eaa-api/reference/get-app-categories) |
| List app bundles | [GET /appbundles](https://techdocs.akamai.com/eaa-api/reference/get-appbundles) |

> **Note:** Some endpoints (POPs, TLS cipher suites, connector pools, registration tokens, some group/membership APIs) do not yet have published techdocs. For those, refer to the provider source code in `pkg/client/`.

## Development Quick Reference

| Command | Purpose |
|---------|---------|
| `make` | Full pipeline: setup → fmt → lint → test → install → buildtool |
| `make test` | Run all tests with race detection (10m timeout) |
| `make test-short` | Short tests only |
| `make test-coverage` | Tests + HTML coverage report |
| `make lint` | Run golangci-lint |
| `make fmt-check` | Check Go formatting |
| `make build` | Compile provider binary to `bin/` |
| `make install` | Install provider to local Terraform plugin directory |
| `make security` | Run gosec security scanner |
| `make vuln-check` | Run govulncheck |

For contributor workflows (adding resources, debugging), see the Claude Code skills in `.claude/skills/`.
