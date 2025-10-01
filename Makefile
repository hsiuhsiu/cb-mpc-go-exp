.PHONY: help build test test-short clean deps examples force-build-cpp image lint lint-fix lint-tools lint-local lint-fix-local lint-fix-docker lint-docker lint-strict

# Marker file to track if C++ library is built
CPP_LIB := cb-mpc/lib/Release/libcbmpc.a
SUBMODULE_INIT := cb-mpc/.git

# Tooling
GO ?= go
TOOLCHAIN_VERSION ?= go1.24.6
GOBIN := $(shell $(GO) env GOPATH)/bin
GOLANGCI_LINT := $(GOBIN)/golangci-lint
GOIMPORTS := $(GOBIN)/goimports

help:
	@echo "Available targets:"
	@echo "  deps         - Initialize git submodules"
	@echo "  build-cpp    - Build cb-mpc C++ library (only if needed)"
	@echo "  force-build-cpp - Force rebuild of C++ library"
	@echo "  build        - Build Go wrapper (builds C++ if needed)"
	@echo "  test         - Run Go tests (builds C++ if needed)"
	@echo "  test-short   - Run Go tests without checking C++ build"
	@echo "  examples     - Run example programs"
	@echo "  image        - Build Docker image for CI/CD"
	@echo "  clean        - Clean Go build artifacts"
	@echo "  clean-all    - Clean everything including cb-mpc build"
	@echo "  lint         - Run formatting, CGO isolation, and golangci-lint checks"
	@echo "  lint-fix     - Auto-fix formatting/imports and apply golangci-lint --fix"

# Initialize submodules if not already done
$(SUBMODULE_INIT):
	git submodule update --init --recursive

# Build C++ library only if it doesn't exist or is outdated
$(CPP_LIB): $(SUBMODULE_INIT)
	@echo "Building C++ library (this may take a few minutes)..."
	bash scripts/build_cpp.sh Release

# Convenience target that checks if rebuild is needed
build-cpp: $(CPP_LIB)
	@echo "✅ C++ library is up to date"

# Force rebuild of C++ library
force-build-cpp: $(SUBMODULE_INIT)
	@echo "Force rebuilding C++ library..."
	bash scripts/build_cpp.sh Release

# Build Go code (will build C++ if needed)
build: $(CPP_LIB)
	bash scripts/go_with_cpp.sh go build ./...

# Run tests (will build C++ if needed)
test: $(CPP_LIB)
	bash scripts/go_with_cpp.sh go test -v ./...

# Run tests without checking C++ build (fast)
test-short:
	bash scripts/go_with_cpp.sh go test -v -short ./...

examples: $(CPP_LIB)
	@echo "Running agree_random example..."
	bash scripts/go_with_cpp.sh go run examples/agree_random/main.go

clean:
	go clean ./...

clean-all: clean
	cd cb-mpc && make clean || true
	rm -rf cb-mpc/build cb-mpc/lib

# Build Docker image for CI/CD
image:
	@echo "Building Docker image for cb-mpc-go..."
	docker build -t cb-mpc-go .

# Install linting tools if missing (macOS/Linux)
lint-tools:
	@# Ensure goimports
	@if [ ! -x "$(GOIMPORTS)" ]; then \
		echo "Installing goimports..."; \
		GOTOOLCHAIN=$(TOOLCHAIN_VERSION) $(GO) install golang.org/x/tools/cmd/goimports@latest; \
	fi
	@# Ensure golangci-lint pinned version and built with modern Go
	@if [ ! -x "$(GOLANGCI_LINT)" ] || ! $(GOLANGCI_LINT) version 2>/dev/null | grep -q "v1.60.3" || ! $(GOLANGCI_LINT) version 2>/dev/null | grep -q "go1.24"; then \
		echo "Installing golangci-lint (v1.60.3) with toolchain $(TOOLCHAIN_VERSION)..."; \
		GOTOOLCHAIN=$(TOOLCHAIN_VERSION) $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.60.3; \
	fi

# Run formatting and linters (excludes cb-mpc/ submodule)
lint:
	@# Prefer Docker if available; otherwise run local-safe (typecheck disabled)
	@if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
	  $(MAKE) lint-docker; \
	else \
	  $(MAKE) lint-local; \
	fi

# Local lint (advanced): run on host toolchain
lint-local: lint-tools
	@echo "=== Checking Go formatting ==="
	@unformatted=$$(find . -path ./cb-mpc -prune -o -name '*.go' -print0 | xargs -0 -n 200 gofmt -s -l | sed 's|^\./||'); \
	if [ -n "$$unformatted" ]; then \
		echo "❌ The following files are not formatted correctly:"; \
		echo "$$unformatted"; \
		echo "Run \"gofmt -s -w .\" to fix"; \
		exit 1; \
	fi; \
	echo "✅ All Go files are properly formatted"
	@echo "=== Checking CGO isolation ==="
	@violations=$$(find . -path ./cb-mpc -prune -o -path ./internal/cgo -prune -o -type f -name '*.go' -print0 | xargs -0 grep -nE '^[[:space:]]*import[[:space:]]+"C"([[:space:]]*|$$)' || true); \
	if [ -n "$$violations" ]; then \
		echo "❌ ERROR: Found \"import \"C\"\" outside of repo-root internal/cgo/ or cb-mpc/:"; \
		echo "$$violations"; \
		exit 1; \
	fi; \
	echo "✅ CGO properly isolated to internal/cgo"
	@echo "=== Running golangci-lint (local-safe: typecheck disabled) ==="
	@GOTOOLCHAIN=$(TOOLCHAIN_VERSION) SKIP_CPP_BUILD=1 bash scripts/go_with_cpp.sh $(GOLANGCI_LINT) run --disable typecheck --timeout=10m

# Auto-fix formatting/imports and apply golangci-lint --fix (best-effort)
lint-fix: lint-fix-docker

# Local lint-fix (advanced)
lint-fix-local: lint-tools
	@echo "=== Fixing formatting and imports (excluding cb-mpc/) ==="
	@find . -path ./cb-mpc -prune -o -name '*.go' -print0 | xargs -0 gofmt -s -w
	@find . -path ./cb-mpc -prune -o -name '*.go' -print0 | xargs -0 $(GOIMPORTS) -w
	@echo "=== Applying golangci-lint --fix (best-effort) ==="
	@GOTOOLCHAIN=$(TOOLCHAIN_VERSION) SKIP_CPP_BUILD=1 bash scripts/go_with_cpp.sh $(GOLANGCI_LINT) run --disable typecheck --fix --timeout=10m || true

# Run lint inside CI Docker image for consistent environment
.PHONY: lint-docker
lint-docker:
	@echo "=== Building CI Docker image (cb-mpc-go) ===" && docker build -t cb-mpc-go .
	@echo "=== Running lint inside Docker (mirrors CI) ===" && \
	docker run --rm -v "$(shell pwd)":/workspace -w /workspace cb-mpc-go bash -c '
	  set -euo pipefail
	  echo "=== Checking Go formatting ===" && \
	  unformatted=$$(gofmt -s -l . | sed "s|^\./||" | grep -vE "^(cb-mpc/)" || true); \
	  if [ -n "$$unformatted" ]; then echo "❌ Not formatted:"; echo "$$unformatted"; exit 1; fi; \
	  echo "✅ All Go files are properly formatted"; \
	  echo "=== Checking CGO isolation ==="; \
	  violations=$$(find . -path "./cb-mpc" -prune -o -path "./internal/cgo" -prune -o -type f -name "*.go" -print0 | xargs -0 grep -nE "^[[:space:]]*import[[:space:]]+\\"C\\"([[:space:]]*|$$)" || true); \
	  if [ -n "$$violations" ]; then echo "❌ CGO violation:"; echo "$$violations"; exit 1; fi; \
	  echo "=== Installing golangci-lint ==="; \
	  SKIP_CPP_BUILD=1 bash scripts/go_with_cpp.sh go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.60.3; \
	  echo "=== Downloading modules ==="; \
	  SKIP_CPP_BUILD=1 bash scripts/go_with_cpp.sh go mod download; \
	  SKIP_CPP_BUILD=1 bash scripts/go_with_cpp.sh go mod verify; \
	  echo "=== Running golangci-lint ==="; \
	  SKIP_CPP_BUILD=1 bash scripts/go_with_cpp.sh $$(go env GOPATH)/bin/golangci-lint run --timeout=10m; \
	  echo "✅ Lint passed"; \
	'

.PHONY: lint-fix-docker
lint-fix-docker:
	@echo "=== Building CI Docker image (cb-mpc-go) ===" && docker build -t cb-mpc-go .
	@echo "=== Running lint --fix inside Docker (mirrors CI) ===" && \
	docker run --rm -v "$(shell pwd)":/workspace -w /workspace cb-mpc-go bash -c '
	  set -euo pipefail
	  echo "=== Fixing formatting and imports (excluding cb-mpc/) ==="; \
	  find . -path "./cb-mpc" -prune -o -name "*.go" -print0 | xargs -0 gofmt -s -w; \
	  find . -path "./cb-mpc" -prune -o -name "*.go" -print0 | xargs -0 goimports -w; \
	  echo "=== Installing golangci-lint ==="; \
	  SKIP_CPP_BUILD=1 bash scripts/go_with_cpp.sh go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.60.3; \
	  echo "=== Running golangci-lint --fix ==="; \
	  SKIP_CPP_BUILD=1 bash scripts/go_with_cpp.sh $$(go env GOPATH)/bin/golangci-lint run --fix --timeout=10m || true; \
	  echo "✅ Lint fix done"; \
	'
