# CI/CD Pipeline Documentation

This document describes the CI/CD pipeline setup for the terraform-eaa provider.

## GitHub Actions Workflows

### CI Pipeline (`.github/workflows/ci.yml`)

The main CI pipeline runs on every push and pull request to the main branches. It includes:

#### 1. **Format Check**
- Verifies that all Go code is properly formatted using `gofmt`
- Fails if any files are not formatted correctly
- Run locally: `make fmt-check`

#### 2. **Linting**
- Uses `golangci-lint` for comprehensive static analysis
- Configuration: `.golangci.yml`
- Checks for:
  - Code style issues
  - Potential bugs
  - Performance problems
  - Security vulnerabilities
  - Best practices violations
- Run locally: `make lint`

#### 3. **Security Scanning**
- **Gosec**: Scans for common security issues in Go code
- **Govulncheck**: Checks for known vulnerabilities in dependencies
- Results are uploaded to GitHub Security tab
- Run locally: `make security` and `make vuln-check`

#### 4. **Testing**
- Runs on multiple platforms: Ubuntu, macOS, and Windows
- Executes all unit tests with race detection
- Generates coverage reports on Ubuntu
- Uploads coverage to Codecov (optional)
- Run locally: `make test` or `make test-coverage`

#### 5. **Build Verification**
- Ensures the provider builds successfully on all platforms
- Verifies both provider and tools can be built
- Run locally: `make build` and `make buildtool`

## Makefile Targets

### Development Targets
```bash
make build              # Build the provider binary
make buildtool          # Build the import tool binary
make install            # Install provider to local Terraform plugins
```

### Testing Targets
```bash
make test               # Run all tests with race detection
make test-coverage      # Run tests and generate coverage report
make test-short         # Run only short tests
```

### Code Quality Targets
```bash
make fmt                # Format all Go code
make fmt-check          # Check if code is formatted (CI)
make lint               # Run golangci-lint
```

### Security Targets
```bash
make security           # Run gosec security scanner
make vuln-check         # Check for known vulnerabilities
```

### Utility Targets
```bash
make tidy               # Tidy and verify Go modules
make vendor             # Vendor dependencies
make clean              # Remove build artifacts
make help               # Show all available targets
```

## Local Development Setup

### Prerequisites
1. Go 1.23.0 or later
2. golangci-lint (optional, but recommended)
   ```bash
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   ```
3. gosec (optional, for security scanning)
   ```bash
   go install github.com/securego/gosec/v2/cmd/gosec@latest
   ```
4. govulncheck (optional, for vulnerability scanning)
   ```bash
   go install golang.org/x/vuln/cmd/govulncheck@latest
   ```

### Running CI Checks Locally

Before pushing code, run these commands to ensure CI will pass:

```bash
# Format check
make fmt-check

# Lint
make lint

# Security scan
make security
make vuln-check

# Tests
make test

# Build
make build
```

Or run the complete CI suite:
```bash
make fmt-check && make lint && make test && make build
```

## Dependabot

Dependabot is configured (`.github/dependabot.yml`) to automatically:
- Update Go module dependencies weekly
- Update GitHub Actions versions weekly
- Create pull requests with dependency updates

## Coverage Reports

Coverage reports are:
- Generated on every test run with `make test-coverage`
- Saved as `coverage.out` (machine-readable) and `coverage.html` (human-readable)
- Uploaded to Codecov in CI (optional, requires Codecov token)

View coverage locally:
```bash
make test-coverage
open coverage.html  # macOS
xdg-open coverage.html  # Linux
start coverage.html  # Windows
```

## Troubleshooting

### CI Fails on Format Check
Run `make fmt` to auto-format code, then commit the changes.

### Linter Errors
Review the linter output and fix issues. Some common fixes:
- Add error handling
- Remove unused variables/imports
- Fix code style issues

### Security Warnings
Review gosec output carefully:
- Some warnings may be false positives (configure in `.golangci.yml`)
- Address genuine security concerns before merging

### Test Failures
- Run tests locally: `make test`
- Check for race conditions: `go test -race ./...`
- Review test logs for specific failures

## CI Badge

Add this badge to your README.md to show CI status:

```markdown
[![CI](https://github.com/akamai/terraform-eaa/actions/workflows/ci.yml/badge.svg)](https://github.com/akamai/terraform-eaa/actions/workflows/ci.yml)
```

## Additional Resources

- [golangci-lint documentation](https://golangci-lint.run/)
- [gosec documentation](https://github.com/securego/gosec)
- [GitHub Actions documentation](https://docs.github.com/en/actions)
- [Terraform Provider development guide](https://www.terraform.io/docs/extend/writing-custom-providers.html)
