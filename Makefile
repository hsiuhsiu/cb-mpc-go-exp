SHELL := /bin/bash

CBMPC_USE_DOCKER ?= 0
BUILD_TYPE ?= Release
GO_RUNNER := scripts/run_with_go.sh
GOLANGCI_RUNNER := scripts/run_golangci.sh
GO_PACKAGES := ./pkg/...
GO_LINT_TARGETS := ./pkg/...
GOLANGCI_CONFIG := .golangci.yml
GOVULNCHECK_VERSION := latest
GOSEC_VERSION := v2.22.9
GOSEC_EXCLUDES := -exclude-dir=cb-mpc -exclude-dir=build -exclude-dir=pkg/cbmpc/internal/cgo
TOOLS_BIN := $(abspath build/tools/bin)
DEFAULT_GOSEC := $(TOOLS_BIN)/gosec
GOSEC_BIN ?=
SEC_GOSEC := $(if $(GOSEC_BIN),$(GOSEC_BIN),$(if $(wildcard $(DEFAULT_GOSEC)),$(DEFAULT_GOSEC),$(shell command -v gosec 2>/dev/null)))
GO_BIN_HOST := $(abspath build/go-host/go/bin)
GO_BIN_DOCKER := $(abspath build/go-docker/go/bin)

GOSEC_INSTALL = GOFLAGS=-mod=mod GOBIN=$(TOOLS_BIN) $(GO_RUNNER) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

PKGS ?=
VULN_PACKAGES := $(if $(PKGS),$(PKGS),./...)
SEC_PACKAGES := $(if $(PKGS),$(PKGS),./...)

WRAPPER_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-in-progress)
UPSTREAM_SHA ?= $(shell git -C cb-mpc rev-parse HEAD 2>/dev/null || echo unknown)
UPSTREAM_DIR ?= cb-mpc
GO_LDFLAGS := -X github.com/coinbase/cb-mpc-go/pkg/cbmpc.Version=$(WRAPPER_VERSION) -X github.com/coinbase/cb-mpc-go/pkg/cbmpc.UpstreamSHA=$(UPSTREAM_SHA) -X github.com/coinbase/cb-mpc-go/pkg/cbmpc.UpstreamDir=$(UPSTREAM_DIR)

RUN_CMD = scripts/run_host_or_docker.sh $(1)

.PHONY: tools
## Install developer tooling (gosec, etc.).
tools: $(DEFAULT_GOSEC)

$(DEFAULT_GOSEC):
	@mkdir -p $(TOOLS_BIN)
	@if ! $(GOSEC_INSTALL); then \
		echo "warning: unable to install gosec automatically; run 'go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)' or set GOSEC_BIN" >&2; \
	fi

.PHONY: help
## Print available make targets.
help:
	@printf "Available targets:\n"
	@awk 'BEGIN{target=""} \
	  /^\.PHONY:/ {target=$$2} \
	  /^## / {if (target != "") {printf "  %-18s %s\n", target, substr($$0,4); target=""}}' $(MAKEFILE_LIST)

.PHONY: bootstrap
## Initialize Git LFS, sync submodules, and build cb-mpc once.
bootstrap:
	git lfs install --skip-repo
	git submodule update --init --recursive
	CBMPC_SKIP_SUBMODULE_SYNC=1 scripts/check_submodule.sh
	$(MAKE) tools
	$(MAKE) build-cbmpc

.PHONY: test
## Build cb-mpc and run Go unit tests. Use RUN=TestName to run specific tests. Use V=1 for verbose output.
test: build-cbmpc
	$(GO_RUNNER) test $(if $(V),-v,) -ldflags "$(GO_LDFLAGS)" $(if $(RUN),-run $(RUN),) $(GO_PACKAGES)

.PHONY: test-nocache
## Build cb-mpc and run Go unit tests without using cached results. Use RUN=TestName to run specific tests. Use V=1 for verbose output.
test-nocache: build-cbmpc
	$(GO_RUNNER) test $(if $(V),-v,) -count=1 -ldflags "$(GO_LDFLAGS)" $(if $(RUN),-run $(RUN),) $(GO_PACKAGES)

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
	GOTOOLCHAIN=go1.25.2 CGO_ENABLED=0 GOFLAGS=-mod=mod $(GO_RUNNER) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(VULN_PACKAGES)

.PHONY: sec
## Run gosec with exclusions for generated cgo stubs and vendored code.
sec:
ifeq ($(strip $(SEC_GOSEC)),)
	@echo "gosec binary not found; run 'make tools' or set GOSEC_BIN" >&2
else
	@PATH=$(GO_BIN_HOST):$(GO_BIN_DOCKER):$$PATH GO111MODULE=on CGO_ENABLED=0 GOFLAGS=-mod=mod $(SEC_GOSEC) $(GOSEC_EXCLUDES) $(SEC_PACKAGES)
endif

.PHONY: tidy-check
## Ensure go.mod and go.sum are tidy.
tidy-check:
	GOFLAGS=-mod=mod $(GO_RUNNER) mod tidy
	git diff --exit-code go.mod go.sum

.PHONY: check-boundary
## Fail if import "C" appears outside pkg/cbmpc/internal/backend.
check-boundary:
	@files=$$(git ls-files '*.go' | grep -v '^pkg/cbmpc/internal/backend/' | grep -v '^cb-mpc/' || true); \
	if [ -n "$$files" ]; then \
		if grep -n 'import "C"' $$files; then \
			echo 'Error: import "C" used outside pkg/cbmpc/internal/backend' >&2; \
			exit 1; \
		fi; \
	fi


CBMPC_SRC_FILES := $(shell cd cb-mpc && git ls-files)
CBMPC_FLAVOR := $(if $(filter 1,$(CBMPC_USE_DOCKER)),docker,$(if $(CBMPC_ENV_FLAVOR),$(CBMPC_ENV_FLAVOR),host))
OPENSSL_ROOT := build/openssl-$(CBMPC_FLAVOR)
OPENSSL_LIB := $(OPENSSL_ROOT)/lib/libcrypto.a
CBMPC_STAMP := build/.cbmpc-$(CBMPC_FLAVOR)-$(BUILD_TYPE).stamp

.PHONY: openssl
## Build a local OpenSSL copy suitable for linking cb-mpc.
openssl: $(OPENSSL_LIB)

$(OPENSSL_LIB): scripts/build_openssl.sh scripts/run_host_or_docker.sh
	$(call RUN_CMD,scripts/build_openssl.sh $(OPENSSL_ROOT))

$(CBMPC_STAMP): $(OPENSSL_LIB) $(addprefix cb-mpc/,$(CBMPC_SRC_FILES)) scripts/build_cbmpc.sh scripts/run_host_or_docker.sh
	$(call RUN_CMD,scripts/build_cbmpc.sh $(BUILD_TYPE))
	@mkdir -p $(dir $@)
	@touch $@

## Configure and build the cb-mpc static library from source without installing system-wide.
build-cbmpc: $(CBMPC_STAMP)

.PHONY: clean
## Remove build artefacts.
clean:
	rm -rf build
