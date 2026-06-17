---
name: add-resource
description: Guide for adding a new Terraform resource or data source to the EAA provider. Follows brainstorming → spec → plan → execution workflow.
---

# Add Resource / Data Source

This skill guides adding a new Terraform resource or data source to the EAA provider end-to-end.

## Prerequisite: Superpowers Plugin

Before proceeding, check if the `superpowers:brainstorming` skill is available.

If it is NOT available, stop and tell the user:

> The `add-resource` skill requires the **superpowers** plugin to be installed. This plugin provides the brainstorming → spec → plan → execution workflow used to build new resources.
>
> Install it by running:
> ```
> claude install claude-plugins-official/superpowers
> ```
>
> After installation, re-run this skill.

Do NOT proceed without the superpowers plugin.

## Workflow

This skill does NOT directly implement the resource. It orchestrates the superpowers workflow with EAA-specific context injected at each phase.

### Phase 1: Brainstorming

Invoke `superpowers:brainstorming` with the following domain context included in the brainstorming prompt:

**Questions to resolve during brainstorming:**

1. Is this a **resource** (full CRUD — create, read, update, delete) or a **data source** (read-only)?
2. What EAA API endpoints does it use? What does the request/response JSON look like?
3. How does it relate to existing resources? (e.g., does it reference applications, connectors, pools?)
4. What attributes are required vs optional vs computed?
5. Are there any validation rules or constraints?
6. What log tags should it use? (follows `[SOURCE][RESOURCE][OPERATION]` format — see `docs/troubleshooting.md`)

**Project structure context to include:**

```
Code layout:
- pkg/client/          — API data model structs and HTTP methods
- pkg/eaaprovider/     — Terraform schema definitions and CRUD functions
- pkg/testsupport/     — HTTP mocking and test assertion helpers
- pkg/eaaprovider/provider.go — ResourcesMap and DataSourcesMap registration

Logging convention:
- All log lines use [SOURCE][RESOURCE][OPERATION] tags
- Source tags: API (client layer), PROVIDER (provider layer), CONFIG (validation)
- See docs/troubleshooting.md for the full tag reference

Test convention:
- Test files named *_test.go alongside implementation files
- Client tests use HTTP mocking from pkg/testsupport/
- Run with: make test

EAA API techdocs (use for understanding request/response shapes):
- API root: https://techdocs.akamai.com/eaa-api/reference
- Applications: get-apps, get-app, post-app, put-app, delete-app, post-app-deploy
- Connectors: get-connectors, get-connector, post-connector, put-connector, delete-connector
- IDPs: get-idps, get-idp-directories, post-app-idp, post-app-directory, post-assign-app-groups
- Certificates: get-certificate, get-certificates, post-certificate
- ACL: get-app-services, put-rule, post-access-control-rule, put-access-control-rule
- Note: POPs, TLS suites, connector pools, registration tokens lack published techdocs — use pkg/client/ source

Reference implementations to study:
- Simple resource:  eaa_connector
  - Client:   pkg/client/agents.go
  - Provider: pkg/eaaprovider/resource_eaa_connector.go
  - Tests:    pkg/client/agents_test.go, pkg/eaaprovider/data_source_agents_test.go

- Complex resource: eaa_application
  - Client:   pkg/client/application.go (+ app_advanced_settings.go, app_facing_auth.go, etc.)
  - Provider: pkg/eaaprovider/resource_eaa_application.go (+ app_auth_helpers.go, app_read_helpers.go, etc.)

- Simple data source: eaa_data_source_apps
  - Client:   pkg/client/application.go (ListApplications method)
  - Provider: pkg/eaaprovider/data_source_apps.go

- Complex data source: eaa_connector_pools
  - Client:   pkg/client/connectorpool.go
  - Provider: pkg/eaaprovider/data_source_connector_pools.go
```

The brainstorming phase produces a design spec saved to `docs/superpowers/specs/`.

### Phase 2: Spec Review

The spec (output of brainstorming) should cover:
- Client layer: API data model structs, HTTP method signatures, error handling
- Provider layer: Terraform schema definition, CRUD function signatures
- Test strategy: what to mock, key test cases
- Documentation: what goes in `docs/`, what example `.tf` to create
- Log tags: new `[SOURCE][RESOURCE][OPERATION]` entries to add

### Phase 3: Planning

Invoke `superpowers:writing-plans` to create the implementation plan from the approved spec.

### Phase 4: Execution

Invoke `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement the plan.

### Validation Checklist

Before marking the work complete, ALL of these must pass:

- [ ] `make fmt` — code is formatted
- [ ] `make lint` — no lint errors
- [ ] `make test` — all tests pass
- [ ] Documentation added to `docs/` with full attribute reference
- [ ] Example `.tf` file added to `examples/`
- [ ] `CLAUDE.md` updated with the new resource or data source
- [ ] New log tags documented in `docs/troubleshooting.md`
- [ ] Resource/data source registered in `pkg/eaaprovider/provider.go`
