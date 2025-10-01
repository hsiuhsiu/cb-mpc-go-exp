SHELL := /bin/bash

CBMPC_USE_DOCKER ?= 0
BUILD_TYPE ?= Release
GO ?= go
GOLANGCI_LINT ?= golangci-lint
GO_RUNNER := scripts/run_with_go.sh
GOLANGCI_RUNNER := scripts/run_golangci.sh
GO_PACKAGES := ./cmd/... ./pkg/...
GO_LINT_TARGETS := ./cmd/... ./pkg/...
DOCKER_RUN := scripts/docker_exec.sh

RUN_CMD = scripts/run_host_or_docker.sh $(1)

.PHONY: test
## Build cb-mpc and run Go unit tests.
test: build-cbmpc
	$(GO_RUNNER) test $(GO_PACKAGES)

.PHONY: lint
## Run static analysis.
lint:
	$(GOLANGCI_RUNNER) run $(GO_LINT_TARGETS)

.PHONY: lint-fix
## Apply autofixes where available.
lint-fix:
	$(GOLANGCI_RUNNER) run --fix $(GO_LINT_TARGETS)

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

