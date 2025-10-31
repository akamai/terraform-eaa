.PHONY: default fmt lint build buildtool install clean 

# Detect Go binary automatically (safe and portable)
GO ?= $(shell which go)
ifeq ($(GO),)
$(error Go binary not found in PATH. Please install Go or specify GO=<path>)
endif

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
SRC          := $(shell find . -type f -name '*.go' -print)


SHELL      = /usr/bin/env bash

GOLINTBIN := $(shell which golangci-lint)


default: fmt lint build buildtool install

build: $(SRC)
	@echo "Building for $(PLUGIN_ARCH)"
	$(GO) build -v -o $(BINDIR)/$(BINNAME) .

buildtool: $(SRC)
	@echo build import tool binary
	$(GO) build -v -o $(BINDIR)/$(BINNAME_TOOL) ./tools

fmt:
	@echo go fmt ./...
	$(GO) fmt ./...

install:
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

lint:
	@echo run golangci-lint on project
	if [ -z "$(GOLINTBIN)" ]; then \
		echo "skipping golangci-lint on project"; \
	else \
		$(GOLINTBIN) run --allow-parallel-runners ./...; \
	fi

clean:
	@rm -rf $(BINDIR)

# TESTS
