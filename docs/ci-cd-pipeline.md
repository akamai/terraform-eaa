# CI/CD Pipeline

## GitHub Actions (`.github/workflows/ci.yml`)

Runs on every push and PR to main branches:

| Stage | What it does | Run locally |
|---|---|---|
| Format | Verifies `gofmt` compliance | `make fmt-check` |
| Lint | `golangci-lint` static analysis (config: `.golangci.yml`) | `make lint` |
| Security | `gosec` + `govulncheck` | `make security && make vuln-check` |
| Test | Unit tests with race detection (Ubuntu, macOS, Windows) | `make test` |
| Build | Provider + import tool build verification | `make build && make buildtool` |

## Makefile Targets

```sh
# Build
make build              # Provider binary
make buildtool          # Import tool binary
make install            # Install to local Terraform plugins

# Test
make test               # All tests with race detection
make test-coverage      # Tests + coverage report
make test-short         # Short tests only

# Quality
make fmt                # Format Go code
make fmt-check          # Check formatting (CI)
make lint               # golangci-lint

# Security
make security           # gosec scanner
make vuln-check         # Known vulnerability check

# Misc
make tidy               # Tidy Go modules
make vendor             # Vendor dependencies
make clean              # Remove build artifacts
```

## Pre-Push Checklist

```sh
make fmt-check && make lint && make test && make build
```

## Dependabot

Configured (`.github/dependabot.yml`) to update Go modules and GitHub Actions weekly.

## Coverage

```sh
make test-coverage
open coverage.html      # macOS
```
