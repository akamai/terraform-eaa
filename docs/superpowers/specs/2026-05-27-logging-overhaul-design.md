# BWVONE-48761: Logging & Error Handling Overhaul

## Problem

The terraform-eaa provider has virtually no structured logging (1 hclog call in 51 Go files) and ~485 error creation points with inconsistent formatting. Users cannot distinguish API errors from provider errors from config errors. Developers debugging with `TF_LOG` get almost no internal visibility.

## Goals

1. Every user-facing error/warning carries prefixed tags identifying source, resource, and operation (e.g., `[API][APP][CREATE]`)
2. Developers get structured, leveled logging via `TF_LOG=INFO|DEBUG|TRACE`
3. Centralized logging/error utilities in a single package — no scattered patterns
4. Full migration: all 51 Go files updated, old patterns removed

## Non-Goals

- Changing the `tools/` CLI utility (keeps `fmt.Print` usage)
- Adding retry logic or circuit breakers
- Changing provider configuration schema

---

## Design

### 1. Tag-Based Error System (`pkg/logging/errors.go`)

#### Tag type and constants

```go
package logging

type Tag string

const (
    // Source tags — WHERE the error originated
    TagAPI      Tag = "API"
    TagProvider Tag = "PROVIDER"
    TagConfig   Tag = "CONFIG"
    TagAuth     Tag = "AUTH"

    // Resource tags — WHAT resource is involved
    TagApp        Tag = "APP"
    TagConnector  Tag = "CONNECTOR"
    TagConnPool   Tag = "CONN_POOL"
    TagIdP        Tag = "IDP"
    TagCert       Tag = "CERT"
    TagAppService Tag = "APP_SVC"
    TagAgent      Tag = "AGENT"
    TagDirectory  Tag = "DIRECTORY"
    TagAppBundle  Tag = "APP_BUNDLE"
    TagCipher     Tag = "CIPHER"
    TagPopTraffic Tag = "POP_TRAFFIC"

    // Operation tags — WHAT action failed
    TagCreate   Tag = "CREATE"
    TagRead     Tag = "READ"
    TagUpdate   Tag = "UPDATE"
    TagDelete   Tag = "DELETE"
    TagValidate Tag = "VALIDATE"
    TagAssign   Tag = "ASSIGN"
    TagDeploy   Tag = "DEPLOY"
    TagList     Tag = "LIST"
)
```

#### EAAError type

```go
type EAAError struct {
    Tags    []Tag
    Message string
    Wrapped error
}

func (e *EAAError) Error() string {
    // Produces: "[API][APP][CREATE] message: wrapped error"
    prefix := ""
    for _, t := range e.Tags {
        prefix += "[" + string(t) + "]"
    }
    msg := prefix + " " + e.Message
    if e.Wrapped != nil {
        msg += ": " + e.Wrapped.Error()
    }
    return msg
}

func (e *EAAError) Unwrap() error { return e.Wrapped }

func (e *EAAError) HasTag(t Tag) bool {
    for _, tag := range e.Tags {
        if tag == t {
            return true
        }
    }
    return false
}
```

#### Constructor helpers

```go
func Errorf(tags []Tag, format string, args ...any) *EAAError
func Wrapf(err error, tags []Tag, format string, args ...any) *EAAError
func HasTag(err error, t Tag) bool  // walks the error chain
```

#### What this replaces

- All 110+ `errors.New` sentinel constants in `pkg/client/constants.go` — deleted entirely
- All `fmt.Errorf` calls at error creation sites → `logging.Errorf` or `logging.Wrapf`
- `errors.Is()` checks against sentinel errors → `logging.HasTag()` checks

### 2. Structured Logging with tflog (`pkg/logging/logger.go`)

#### Migration from hclog to tflog

Remove `hclog.Logger` from `EaaClient` struct. Use `tflog` via `context.Context` (already available in all resource CRUD functions).

#### Log level assignments

| Level | Content | Example |
|-------|---------|---------|
| WARN | Deprecation notices, retries, fallback behavior | `"field 'aws_classic' is deprecated, use 'aws_vpc'"` |
| INFO | CRUD lifecycle start/end, major state transitions | `"creating application" / "application created"` |
| DEBUG | API request/response summaries, state mapping decisions, config resolution | `"API POST /apps → 201" / "mapping 'servers' block"` |
| TRACE | Raw JSON payloads, internal struct dumps, helper function entries, field-level diffs | `"request body: {...}" / "flattenAppServers input: [...]"` |

Level hierarchy is automatic via tflog: `TF_LOG=DEBUG` shows DEBUG + INFO + WARN.

#### Wrapper functions

```go
func Info(ctx context.Context, msg string, tags []Tag, fields ...map[string]interface{})
func Debug(ctx context.Context, msg string, tags []Tag, fields ...map[string]interface{})
func Trace(ctx context.Context, msg string, tags []Tag, fields ...map[string]interface{})
func Warn(ctx context.Context, msg string, tags []Tag, fields ...map[string]interface{})
```

These wrappers:
1. Format tags as prefix in log message: `[API][APP][CREATE] creating application`
2. Pass structured key-value fields to `tflog` for machine-parseable output
3. Automatically include `resource_type` and `operation` as structured fields extracted from tags

### 3. Diagnostic Helpers (`pkg/logging/diagnostics.go`)

```go
func DiagError(err *EAAError) diag.Diagnostics
func DiagWarning(err *EAAError) diag.Diagnostics
func DiagErrorf(tags []Tag, format string, args ...any) diag.Diagnostics
func DiagWarningf(tags []Tag, format string, args ...any) diag.Diagnostics
```

#### What users see in terraform apply

```
Error: [API][APP][CREATE] failed to create application: 401 unauthorized

Error: [PROVIDER][CONN_POOL][VALIDATE] field 'name' is required

Warning: [PROVIDER][CONNECTOR] field 'private_ip' is deprecated, use 'connector_ip'
```

#### Replacement mapping

| Before | After |
|--------|-------|
| `diag.FromErr(fmt.Errorf("...: %w", err))` | `logging.DiagError(logging.Wrapf(err, tags, "..."))` |
| `diag.Errorf("...")` | `logging.DiagErrorf(tags, "...")` |
| `diag.Diagnostics{diag.Diagnostic{...}}` | `logging.DiagWarningf(tags, "...")` |

### 4. Context Threading in Client Package

All exported methods in `pkg/client/` gain `ctx context.Context` as their first parameter. This enables:
- `tflog` calls within client methods (API request/response logging)
- Cancellation propagation (future-proofing)

The `EaaClient` struct drops its `Logger hclog.Logger` field.

---

## Package Structure

```
pkg/
├── logging/
│   ├── errors.go       # EAAError type, Tag constants, Errorf/Wrapf/HasTag
│   ├── logger.go       # tflog wrappers (Info/Debug/Trace/Warn)
│   └── diagnostics.go  # DiagError/DiagWarning/DiagErrorf/DiagWarningf
├── client/
│   ├── client.go       # Remove hclog.Logger, thread ctx through methods
│   ├── constants.go    # Remove all error constants (only non-error constants remain)
│   ├── utils.go        # Validation helpers refactored to use logging package
│   └── ...             # All methods get ctx + tagged errors
└── eaaprovider/
    └── ...             # All resources get tflog calls + tagged diagnostics
```

## Tag Assignment Conventions

| Layer | Source tag | Example |
|-------|-----------|---------|
| `pkg/client/*` (API calls) | `TagAPI` | `[API][APP][CREATE]` |
| `pkg/eaaprovider/*` (resource logic) | `TagProvider` | `[PROVIDER][APP][VALIDATE]` |
| Provider config / auth | `TagConfig` or `TagAuth` | `[CONFIG][VALIDATE]` |
| Deprecation warnings | `TagProvider` | `[PROVIDER][CONNECTOR][VALIDATE]` |

## Migration Strategy

### Per-file migration (all resource/data-source files):

1. Replace `diag.FromErr(fmt.Errorf(...))` → `logging.DiagError(logging.Wrapf(...))`
2. Replace `diag.Errorf(...)` → `logging.DiagErrorf(tags, ...)`
3. Add tflog lifecycle logging: INFO at CRUD start/end, DEBUG for API details, TRACE for payloads
4. Thread `ctx` into client calls that don't have it

### Client package migration:

1. Add `ctx context.Context` as first parameter to all exported methods
2. Replace `fmt.Errorf` returns with `logging.Errorf` / `logging.Wrapf`
3. Add DEBUG/TRACE logging for HTTP request/response cycles
4. Remove `hclog.Logger` from `EaaClient` struct
5. Delete all sentinel error constants (`Err*` variables) from `constants.go` — non-error constants (URL paths, enums, field names) remain untouched

### Files excluded from migration:

- `tools/import_tf_config.go` and `tools/utils.go` — CLI tool, not provider code
- `main.go` — minimal changes (go.mod dependency addition only)

## Usage Examples

### Resource CRUD function

```go
func resourceApplicationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
    tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}

    logging.Info(ctx, "creating application", tags)
    logging.Trace(ctx, "request payload", tags, map[string]interface{}{"body": string(reqBody)})

    resp, err := client.CreateApp(ctx, req)
    if err != nil {
        return logging.DiagError(logging.Wrapf(err, tags, "failed to create application"))
    }

    logging.Debug(ctx, "API response received", tags, map[string]interface{}{
        "status": resp.StatusCode,
        "app_id": resp.UUID,
    })
    logging.Info(ctx, "application created successfully", tags, map[string]interface{}{"app_id": resp.UUID})
    return nil
}
```

### Client method

```go
func (ec *EaaClient) CreateApp(ctx context.Context, req AppRequest) (*AppResponse, error) {
    tags := []logging.Tag{logging.TagAPI, logging.TagApp, logging.TagCreate}

    logging.Debug(ctx, "sending create app request", tags, map[string]interface{}{"url": apiURL})
    logging.Trace(ctx, "request body", tags, map[string]interface{}{"body": req})

    resp, err := ec.doRequest(ctx, "POST", apiURL, body)
    if err != nil {
        return nil, logging.Wrapf(err, tags, "HTTP request failed")
    }

    logging.Debug(ctx, "received response", tags, map[string]interface{}{"status": resp.StatusCode})
    return result, nil
}
```

### Validation helper

```go
func (ec *EaaClient) ValidateRequiredString(ctx context.Context, data map[string]interface{}, key string) (string, error) {
    tags := []logging.Tag{logging.TagProvider, logging.TagValidate}

    val, ok := data[key]
    if !ok || val.(string) == "" {
        return "", logging.Errorf(tags, "field '%s' is required", key)
    }
    logging.Trace(ctx, "validated required string", tags, map[string]interface{}{"key": key, "value": val})
    return val.(string), nil
}
```

## Dependencies

### New Go module dependency

```
github.com/hashicorp/terraform-plugin-log  (tflog)
```

### Removed dependency (if no longer used elsewhere)

```
github.com/hashicorp/go-hclog  (check if terraform-plugin-sdk still needs it transitively)
```
