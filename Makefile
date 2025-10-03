SHELL := /bin/bash

CBMPC_USE_DOCKER ?= 0
BUILD_TYPE ?= Release
GO_RUNNER := scripts/run_with_go.sh
GOLANGCI_RUNNER := scripts/run_golangci.sh
GO_PACKAGES := ./cmd/... ./pkg/...
GO_LINT_TARGETS := ./cmd/... ./pkg/...
GOLANGCI_CONFIG := .golangci.yml
GOVULNCHECK_VERSION := v1.1.4
GOSEC_VERSION := v2.20.0
GOSEC_EXCLUDES := -exclude-dir=third_party -exclude-dir=build -exclude-dir=pkg/cbmpc/internal/cgo

PKGS ?=
VULN_PACKAGES := $(if $(PKGS),$(PKGS),./...)
SEC_PACKAGES := $(if $(PKGS),$(PKGS),./...)

RUN_CMD = scripts/run_host_or_docker.sh $(1)

.PHONY: help
## Print available make targets.
help:
	@printf "Available targets:\n"
	@grep -hE '^([a-zA-Z0-9_-]|\.)+:|^##' $(MAKEFILE_LIST) | \
	  sed -e 's/:.*//' -e 's/^## /\t/' | \
	  awk 'NR%2{printf "  %-18s", $$0} !(NR%2){print $$0}'

.PHONY: bootstrap
## Initialize Git LFS, sync submodules, and build cb-mpc once.
bootstrap:
	git lfs install --skip-repo
	git submodule update --init --recursive
	$(MAKE) build-cbmpc

.PHONY: test
## Build cb-mpc and run Go unit tests.
test: build-cbmpc
	$(GO_RUNNER) test $(GO_PACKAGES)

.PHONY: lint
## Run static analysis.
lint:
	$(GOLANGCI_RUNNER) run --config $(GOLANGCI_CONFIG) $(GO_LINT_TARGETS)

.PHONY: lint-fix
## Apply autofixes where available.
lint-fix:
	$(GOLANGCI_RUNNER) run --config $(GOLANGCI_CONFIG) --fix $(GO_LINT_TARGETS)

.PHONY: vuln
## Run govulncheck against the module packages.
vuln:
	CGO_ENABLED=0 GOFLAGS=-mod=mod $(GO_RUNNER) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(VULN_PACKAGES)

.PHONY: sec
## Run gosec with exclusions for generated cgo stubs and vendored code.
sec:
	CGO_ENABLED=0 GOFLAGS=-mod=mod $(GO_RUNNER) run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) $(GOSEC_EXCLUDES) $(SEC_PACKAGES)

.PHONY: tidy-check
## Ensure go.mod and go.sum are tidy.
tidy-check:
	GOFLAGS=-mod=mod $(GO_RUNNER) mod tidy
	git diff --exit-code go.mod go.sum

.PHONY: openssl
## Build a local OpenSSL copy suitable for linking cb-mpc.
openssl:
	$(call RUN_CMD,scripts/build_openssl.sh)

.PHONY: build-cbmpc
## Configure and build the cb-mpc static library from source without installing system-wide.
build-cbmpc: openssl
	$(call RUN_CMD,scripts/build_cbmpc.sh $(BUILD_TYPE))

.PHONY: clean
## Remove build artefacts.
clean:
	rm -rf build
