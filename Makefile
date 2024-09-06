.PHONY: default 

GO 			 := /usr/local/go
BINDIR       := $(CURDIR)/bin

BINNAME := terraform-provider-eaa
BINNAME_TOOL := import-config
PLUGIN_ARCH := darwin_amd64
VERSION_STR := 1.0.0
SRC          := $(shell find . -type f -name '*.go' -print)


SHELL      = /usr/bin/env bash

GOBIN		 := $(shell which go)
GOLINTBIN	 := $(shell which golangci-lint)

ifneq ("$(wildcard $(GOBIN))","")
	GO = $(GOBIN)
endif


default: fmt lint build buildtool install

build: $(SRC)
	@echo build eaa provider binary
	$(GO) build -v -o $(BINDIR)/$(BINNAME) $(CURDIR)

buildtool: $(SRC)
	@echo build import tool binary
	$(GO) build -v -o $(BINDIR)/$(BINNAME_TOOL) $(CURDIR)/tools

fmt:
	@echo go fmt ./...
	$(GO) fmt ./...

install:
	# install for macOS amd64
	# Create the directory holding the newly built Terraform plugins
	mkdir -p ~/.terraform.d/plugins/terraform.eaaprovider.dev/eaaprovider/eaa/${VERSION_STR}/${PLUGIN_ARCH}
	cp ./bin/terraform-provider-eaa ~/.terraform.d/plugins/terraform.eaaprovider.dev/eaaprovider/eaa/${VERSION_STR}/${PLUGIN_ARCH}

lint:
	@echo run golangci-lint on project
	if [ -z "$(GOLINTBIN)" ]; then \
		echo "skipping golangci-lint on project"; \
	else \
		golangci-lint run --allow-parallel-runners ./...; \
	fi

clean:
	@rm -rf $(BINDIR)

# TESTS
