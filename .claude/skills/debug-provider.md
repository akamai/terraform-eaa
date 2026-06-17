---
name: debug-provider
description: Help users troubleshoot terraform plan/apply failures with the EAA provider. Guides through log analysis, error identification, and issue reporting.
---

# Debug EAA Provider Issues

This skill helps users systematically diagnose and report issues when `terraform plan`, `terraform apply`, or `terraform destroy` fails with the EAA provider.

## Step 1: Gather Context

Ask the user for:

1. **Which command failed?** — `terraform plan`, `terraform apply`, or `terraform destroy`
2. **The error message** — The full error output from Terraform
3. **The Terraform config** — The resource block(s) involved (remind them to redact secrets)

If the user doesn't have all three, work with what they have. The error message is the most important.

## Step 2: Enable Provider Logging

If the error message alone isn't enough to diagnose the issue, guide the user to enable logging:

```sh
# Set log level and output to a file
export TF_LOG=DEBUG
export TF_LOG_PATH=./terraform.log
terraform plan   # or terraform apply
```

**Log levels** (from least to most verbose):

| Level | What it shows | When to use |
|-------|--------------|-------------|
| `ERROR` | Only failures | Quick check — is there a clear error? |
| `WARN` | Failures + warnings | Check for deprecation or config warnings |
| `INFO` | Operations + API endpoints | See which API calls are made and in what order |
| `DEBUG` | Request/response payloads, state operations | **Recommended starting point** — see exactly what's sent to and received from the EAA API |
| `TRACE` | Full SDK protocol detail | Last resort — very verbose, includes Terraform plugin protocol internals |

Recommend starting with `DEBUG`. Only escalate to `TRACE` if `DEBUG` doesn't show enough.

## Step 3: Analyze Logs

The EAA provider uses structured log tags in the format `[SOURCE][RESOURCE][OPERATION]`. Use `grep` to filter:

```sh
# See all API calls for a specific resource
grep '\[API\]\[APP\]' terraform.log          # application API calls
grep '\[API\]\[CONNECTOR\]' terraform.log    # connector API calls
grep '\[API\]\[CONN_POOL\]' terraform.log    # connector pool API calls

# See all operations of a specific type
grep '\[CREATE\]' terraform.log              # all create operations
grep '\[VALIDATE\]' terraform.log            # all validation errors

# See everything at a specific layer
grep '\[API\]' terraform.log                 # all HTTP client calls
grep '\[PROVIDER\]' terraform.log            # all provider-level operations
```

**Source tags:**

| Tag | Layer | What it tells you |
|-----|-------|-------------------|
| `API` | HTTP client | Outbound EAA API requests and responses — look here for HTTP errors, auth failures, unexpected payloads |
| `PROVIDER` | Terraform provider | Resource CRUD, state mapping, plan diffs — look here for schema mismatches, state drift |
| `CONFIG` | Validation | Input validation — look here for invalid attribute values or combinations |

**Resource tags:** `APP`, `CONNECTOR`, `CONN_POOL`, `IDP`, `CERT`, `APP_SVC`, `AGENT`, `DIRECTORY`, `APP_BUNDLE`, `CIPHER`, `POP_TRAFFIC`

**Operation tags:** `CREATE`, `READ`, `UPDATE`, `DELETE`, `VALIDATE`, `ASSIGN`, `DEPLOY`, `LIST`, `MARSHAL`, `AUTH`

Full tag reference: [docs/troubleshooting.md](docs/troubleshooting.md)

## Step 4: Identify the Issue

Based on the error message and logs, determine the category:

### Configuration Error (user can fix)

- **Missing required field** — Error message names the field. Add it to the config.
- **Invalid attribute combination** — e.g., `tunnel_internal_hosts` on a non-tunnel app, `protocol` on an enterprise app. Check the app type compatibility table in `docs/eaa_application.md`.
- **Auth mismatch** — Enterprise apps use `advanced_settings.app_auth`, SaaS apps use top-level `protocol`. Mixing them silently fails.
- **String vs boolean** — `auth_enabled` requires `"true"` (string), not `true` (boolean).
- **Case sensitivity** — `protocol = "wsfed"` is invalid; must be `WSFed` or `WS-Federation`.
- **CPAG mismatch** — `infra_type = "cpag"` requires `operating_mode = "cpag_public"` or `"cpag_private"`.

### Provider Bug (needs a GitHub issue)

- **API call returns unexpected error** — The logs show a valid-looking request but the API returns 400/500
- **State drift** — Terraform shows changes on every plan even when nothing changed
- **Crash or panic** — Stack trace in the output
- **Silent data loss** — Attributes set in config are not reflected after apply

### EAA Service Issue (not a provider bug)

- **401/403 from API** — Authentication issue. Check `.edgerc` credentials and permissions.
- **503/timeout** — EAA service may be experiencing issues.
- **Connector unreachable** — The connector VM may be down or misconfigured, not a provider issue.

## Step 5: Explain and Resolve

Give the user a plain-language explanation of:
1. **What happened** — Which operation failed and why
2. **Whether they can fix it** — If it's a config error, show the corrected config
3. **Next steps** — If it's a provider bug, guide them to file an issue (see below)

## Step 6: Guide Issue Reporting (if provider bug)

Help the user compose a GitHub issue at https://github.com/akamai/terraform-eaa/issues with:

```markdown
## Environment
- Terraform version: (output of `terraform version`)
- EAA provider version: 2.0.0
- OS: (e.g., macOS 15, Ubuntu 24.04)

## Terraform Configuration
(Paste the relevant resource block — REDACT secrets, .edgerc values, and internal hostnames)

## Expected Behavior
(What should have happened)

## Actual Behavior
(What actually happened — paste the error message)

## Debug Logs
(Set TF_LOG=DEBUG and paste the relevant log section — REDACT any API keys, tokens, or internal IPs)

## Steps to Reproduce
1. ...
2. ...
```

**Remind the user to redact:**
- `.edgerc` credentials (`client_token`, `client_secret`, `access_token`)
- Internal hostnames and IPs
- Any tokens or secrets from registration tokens
- Group/user names if sensitive
