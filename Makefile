.PHONY: default fmt lint build buildtool install clean setup

# Detect Go binary automatically (safe and portable)
GO ?= $(shell which go)
ifeq ($(GO),)
$(error Go binary not found in PATH. Please install Go or specify GO=<path>)
endif

GO_BIN_DIR := $(shell $(GO) env GOBIN)
ifeq ($(GO_BIN_DIR),)
GO_BIN_DIR := $(shell $(GO) env GOPATH)/bin
endif

export PATH := $(GO_BIN_DIR):$(PATH)

BINDIR          := $(CURDIR)/bin

BINNAME := terraform-provider-eaa
BINNAME_TOOL := import-config

# Detect OS and architecture dynamically
# Check if we're on Windows (Git Bash uses MSYSTEM, WSL uses specific env, PowerShell uses OS)
ifeq ($(OS),Windows_NT)
    # Windows - detect architecture
    ifeq ($(PROCESSOR_ARCHITECTURE),ARM64)
        PLUGIN_ARCH := windows_arm64
    else ifneq (,$(or $(PROCESSOR_ARCHITEW6432),$(findstring AMD64,$(PROCESSOR_ARCHITECTURE))))
        PLUGIN_ARCH := windows_amd64
    else
        PLUGIN_ARCH := windows_amd64
    endif
else
    # Unix-like systems (Linux, macOS, WSL)
    UNAME_S := $(shell uname -s)
    UNAME_M := $(shell uname -m)

    # Detect OS type
    ifeq ($(UNAME_S),Darwin)
        PLUGIN_OS := darwin
    else ifeq ($(UNAME_S),Linux)
        PLUGIN_OS := linux
    else
        # Default fallback
        PLUGIN_OS := darwin
    endif

    # Detect architecture and build final plugin arch
    # Handle both arm64 (macOS) and aarch64 (Linux)
    ifeq ($(UNAME_M),arm64)
        PLUGIN_ARCH := $(PLUGIN_OS)_arm64
    else ifeq ($(UNAME_M),aarch64)
        PLUGIN_ARCH := $(PLUGIN_OS)_arm64
    else
        PLUGIN_ARCH := $(PLUGIN_OS)_amd64
    endif
endif

VERSION_STR := 1.0.0
GOLANGCI_LINT_VERSION := v2.11.4
SRC          := $(shell find . -type f -name '*.go' -print)

SHELL      = /usr/bin/env bash

define section_banner
	@printf '\n%s\n' '============================================================'
	@printf '====== %-46s ======\n' '$(1)'
	@printf '%s\n' '============================================================'
endef


default: install buildtool

build: lint $(SRC)
	$(call section_banner,BUILD)
	@echo "Building for $(PLUGIN_ARCH)"
	$(GO) build -v -o $(BINDIR)/$(BINNAME) .

buildtool: setup $(SRC)
	$(call section_banner,BUILD TOOL)
	@echo build import tool binary
	$(GO) build -v -o $(BINDIR)/$(BINNAME_TOOL) ./tools

fmt: setup
	$(call section_banner,FORMAT)
	@echo go fmt ./...
	$(GO) fmt ./...

install: build
	$(call section_banner,INSTALL)
	@echo "Installing for $(PLUGIN_ARCH)"
ifeq ($(OS),Windows_NT)
	@echo "Creating Windows Terraform plugins directory..."
	@if not exist "%USERPROFILE%\.terraform.d\plugins\terraform.eaaprovider.dev\eaaprovider\eaa\$(VERSION_STR)\$(PLUGIN_ARCH)" mkdir "%USERPROFILE%\.terraform.d\plugins\terraform.eaaprovider.dev\eaaprovider\eaa\$(VERSION_STR)\$(PLUGIN_ARCH)"
	@copy /Y "$(BINDIR)\$(BINNAME).exe" "%USERPROFILE%\.terraform.d\plugins\terraform.eaaprovider.dev\eaaprovider\eaa\$(VERSION_STR)\$(PLUGIN_ARCH)\terraform-provider-eaa.exe"
	@echo "Provider installed to: %USERPROFILE%\.terraform.d\plugins\terraform.eaaprovider.dev\eaaprovider\eaa\$(VERSION_STR)\$(PLUGIN_ARCH)"
else
	@echo "Creating Unix Terraform plugins directory..."
	@mkdir -p "$$HOME/.terraform.d/plugins/terraform.eaaprovider.dev/eaaprovider/eaa/$(VERSION_STR)/$(PLUGIN_ARCH)"
	@cp "$(BINDIR)/$(BINNAME)" "$$HOME/.terraform.d/plugins/terraform.eaaprovider.dev/eaaprovider/eaa/$(VERSION_STR)/$(PLUGIN_ARCH)"
	@echo "Provider installed to: $$HOME/.terraform.d/plugins/terraform.eaaprovider.dev/eaaprovider/eaa/$(VERSION_STR)/$(PLUGIN_ARCH)"
endif

lint: fmt
	$(call section_banner,LINT)
	@echo run golangci-lint on project
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --allow-parallel-runners ./...; \
	else \
		echo "golangci-lint not found. Run 'make setup' to install it."; \
		exit 1; \
	fi

clean:
	@rm -rf $(BINDIR)

# TESTS
test:
	$(call section_banner,TEST)
	@echo "Running tests..."
	$(GO) test -v -race -timeout 10m ./...

test-coverage:
	$(call section_banner,TEST COVERAGE)
	@echo "Running tests with coverage..."
	$(GO) test -v -race -timeout 10m -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-short:
	$(call section_banner,TEST SHORT)
	@echo "Running short tests..."
	$(GO) test -short -v ./...

# FORMAT CHECK
fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "The following files are not formatted:"; \
		gofmt -l .; \
		echo "Please run 'make fmt' to format the code."; \
		exit 1; \
	fi

# SECURITY CHECKS
security:
	$(call section_banner,SECURITY)
	@echo "Running security checks..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -quiet ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi

vuln-check:
	$(call section_banner,VULNERABILITY CHECK)
	@echo "Checking for vulnerabilities..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

# DEPENDENCY MANAGEMENT
tidy:
	$(call section_banner,TIDY)
	@echo "Tidying Go modules..."
	$(GO) mod tidy
	$(GO) mod verify

vendor:
	$(call section_banner,VENDOR)
	@echo "Vendoring dependencies..."
	$(GO) mod vendor

# SETUP DEVELOPMENT ENVIRONMENT
setup:
	$(call section_banner,SETUP)
	@echo "Setting up development environment..."
	@echo "Installing required tools..."
	@echo ""
	@echo "1. Installing golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "   ✓ golangci-lint already installed ($$(golangci-lint --version))"; \
	else \
		echo "   → Installing golangci-lint..."; \
		if command -v curl >/dev/null 2>&1; then \
			curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b "$(GO_BIN_DIR)" $(GOLANGCI_LINT_VERSION); \
		elif command -v wget >/dev/null 2>&1; then \
			wget -O- -nv https://golangci-lint.run/install.sh | sh -s -- -b "$(GO_BIN_DIR)" $(GOLANGCI_LINT_VERSION); \
		else \
			echo "   ✗ Neither curl nor wget is installed. Please install one of them and rerun 'make setup'."; \
			exit 1; \
		fi; \
		echo "   ✓ golangci-lint installed successfully"; \
	fi
	@echo ""
	@echo "2. Installing gosec..."
	@if command -v gosec >/dev/null 2>&1; then \
		echo "   ✓ gosec already installed ($$(gosec -version 2>&1 | head -n1))"; \
	else \
		echo "   → Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest && \
		echo "   ✓ gosec installed successfully"; \
	fi
	@echo ""
	@echo "3. Installing goimports..."
	@if command -v goimports >/dev/null 2>&1; then \
		echo "   ✓ goimports already installed ($$(goimports -version 2>/dev/null || echo installed))"; \
	else \
		echo "   → Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest && \
		echo "   ✓ goimports installed successfully"; \
	fi
	@echo ""
	@echo "4. Installing govulncheck..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		echo "   ✓ govulncheck already installed"; \
	else \
		echo "   → Installing govulncheck..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest && \
		echo "   ✓ govulncheck installed successfully"; \
	fi
	@echo ""
	@echo "5. Installing pre-commit..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		echo "   ✓ pre-commit already installed ($$(pre-commit --version))"; \
	else \
		echo "   → Installing pre-commit..."; \
		if command -v pip3 >/dev/null 2>&1; then \
			pip3 install pre-commit && \
			echo "   ✓ pre-commit installed successfully"; \
		elif command -v brew >/dev/null 2>&1; then \
			brew install pre-commit && \
			echo "   ✓ pre-commit installed successfully"; \
		else \
			echo "   ⚠ Could not install pre-commit. Please install manually:"; \
			echo "     pip3 install pre-commit"; \
		fi; \
	fi
	@echo ""
	@echo "6. Installing pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install --install-hooks && \
		pre-commit install --hook-type commit-msg && \
		echo "   ✓ Pre-commit hooks installed"; \
	else \
		echo "   ⚠ Skipping pre-commit hooks installation"; \
	fi
	@echo ""
	@echo "7. Downloading Go module dependencies..."
	@$(GO) mod download
	@echo "   ✓ Dependencies downloaded"
	@echo ""
	@echo "Go tool binaries are expected in: $(GO_BIN_DIR)"
	@echo "If hooks still report missing tools, add this to your shell profile:"
	@echo "  export PATH=\"$(GO_BIN_DIR):$$PATH\""
	@echo ""
	@echo "✓ Development environment setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  - Run 'make test' to verify tests pass"
	@echo "  - Run 'make lint' to check code quality"
	@echo "  - Run 'make build' to build the provider"
	@echo "  - Run 'make help' to see all available commands"

# PRE-COMMIT
pre-commit-install:
	$(call section_banner,PRE-COMMIT INSTALL)
	@echo "Installing pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install --install-hooks && \
		pre-commit install --hook-type commit-msg && \
		echo "✓ Pre-commit hooks installed"; \
	else \
		echo "pre-commit not found. Run 'make setup' to install it."; \
		exit 1; \
	fi

pre-commit-run:
	$(call section_banner,PRE-COMMIT RUN)
	@echo "Running pre-commit on all files..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit run --all-files; \
	else \
		echo "pre-commit not found. Run 'make setup' to install it."; \
		exit 1; \
	fi

pre-commit-update:
	$(call section_banner,PRE-COMMIT UPDATE)
	@echo "Updating pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit autoupdate; \
	else \
		echo "pre-commit not found. Run 'make setup' to install it."; \
		exit 1; \
	fi

# HELP
help:
	$(call section_banner,HELP)
	@echo "Available targets:"
	@echo "  make setup              - Install all required development tools"
	@echo "  make build              - Build the provider binary"
	@echo "  make buildtool          - Build the import tool binary"
	@echo "  make fmt                - Format Go code"
	@echo "  make fmt-check          - Check if code is formatted"
	@echo "  make lint               - Run golangci-lint"
	@echo "  make test               - Run all tests"
	@echo "  make test-coverage      - Run tests with coverage report"
	@echo "  make test-short         - Run short tests"
	@echo "  make security           - Run security scanner (gosec)"
	@echo "  make vuln-check         - Check for vulnerabilities (govulncheck)"
	@echo "  make pre-commit-install - Install pre-commit hooks"
	@echo "  make pre-commit-run     - Run pre-commit on all files"
	@echo "  make pre-commit-update  - Update pre-commit hook versions"
	@echo "  make install            - Install provider to local Terraform plugins"
	@echo "  make tidy               - Tidy and verify Go modules"
	@echo "  make vendor             - Vendor dependencies"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make help               - Show this help message"
