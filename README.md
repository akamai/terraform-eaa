# EAA Terraform Provider

Terraform provider for [Akamai Enterprise Application Access (EAA)](https://techdocs.akamai.com/eaa/docs).

## Install

```sh
# From the repository root
make
```

Outputs:
- `bin/terraform-provider-eaa` — provider binary
- `bin/import-config` — bulk import tool

Platform support: macOS (darwin_amd64, darwin_arm64), Linux (linux_amd64, linux_arm64), Windows (windows_amd64, windows_arm64).

## Provider Configuration

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

| Argument | Required | Description |
|---|---|---|
| `contractid` | Yes | Akamai contract ID for EAA |
| `accountswitchkey` | No | Run operations from another account |
| `edgerc` | No | Path to `.edgerc` file (default `~/.edgerc`) |

Authentication can also use [environment variables](https://techdocs.akamai.com/terraform/docs/environment-variables).

### .edgerc Setup

Create an API client in Akamai Control Center with READ-WRITE permission to *Enterprise Application Access*. For legacy API keys: EAA > System > Settings > Generate new API Key.

```ini
[default]
host = akaa-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net
client_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx
client_secret = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
access_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx
```

## Quick Start

```hcl
resource "eaa_application" "my_app" {
  name        = "My App"
  app_profile = "http"
  app_type    = "enterprise"
  domain      = "wapp"
  host        = "my-app"
  popregion   = "us-east-1"
  agents      = ["my-connector"]

  servers {
    origin_host     = "app.internal.example.com"
    origin_port     = 443
    origin_protocol = "https"
  }

  auth_enabled = "true"
}
```

```sh
terraform init && terraform plan && terraform apply
```

## Documentation

### Resources

| Resource | Description | Doc | Examples |
|---|---|---|---|
| `eaa_application` | Application lifecycle, advanced settings, auth, ACL rules | [docs/eaa_application.md](docs/eaa_application.md) | [enterprise_http](examples/enterprise_http.tf), [enterprise_rdp](examples/enterprise_rdp.tf), [tunnel](examples/tunnel.tf), [auth_*](examples/) |
| `eaa_connector` | Connector VM provisioning | [docs/eaa_connector.md](docs/eaa_connector.md) | [connector](examples/connector.tf) |
| `eaa_connector_pool` | Pool management, registration tokens, app/connector assignment | [docs/eaa_connector_pool.md](docs/eaa_connector_pool.md) | [connector_pool](examples/connector_pool.tf) |

### Data Sources

`eaa_data_source_pops`, `eaa_data_source_appcategories`, `eaa_data_source_agents`, `eaa_data_source_idps`, `eaa_data_source_tls_cipher_suites`, `eaa_connector_pools`, `eaa_data_source_apps` — see [docs/data-sources.md](docs/data-sources.md).

### Other

| Topic | Doc |
|---|---|
| Importing existing resources | [docs/import.md](docs/import.md) |
| Troubleshooting & log tags | [docs/troubleshooting.md](docs/troubleshooting.md) |
| CI/CD pipeline & Makefile targets | [docs/ci-cd-pipeline.md](docs/ci-cd-pipeline.md) |

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md) for logging setup, log tag format, and a full reference of all `[SOURCE][RESOURCE][OPERATION]` log tags.

## Using with Claude Code

This repository includes [Claude Code](https://claude.ai/code) configuration to help both users and contributors.

### CLAUDE.md

The `CLAUDE.md` file at the repository root teaches Claude about the EAA provider's resources, data sources, common patterns, and gotchas. With it, Claude can help you write Terraform configurations — for example:

- "Help me write a Terraform config for an HTTP application with SAML auth"
- "Set up a connector pool with two connectors and a registration token"
- "What data source do I use to look up IDP names?"

### Skills

Two Claude Code skills are available in `.claude/skills/`:

| Skill | Audience | Purpose |
|-------|----------|---------|
| `add-resource` | Contributors | Guides adding a new resource or data source through the full brainstorming → spec → plan → execution workflow |
| `debug-provider` | Users | Helps troubleshoot `terraform plan`/`terraform apply` failures with structured log analysis and issue reporting |

To use a skill, type `/add-resource` or `/debug-provider` in Claude Code.

## Support

EAA Terraform provider is provided as-is and not supported by Akamai Support. Report issues at the [GitHub Issues page](https://github.com/akamai/terraform-eaa/issues).
