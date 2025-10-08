#!/usr/bin/env bash
set -euo pipefail

ENV_FLAVOR="${CBMPC_ENV_FLAVOR:-host}"
DEFAULT_GOCACHE="${PWD}/build/.cache/go-build-${ENV_FLAVOR}"
DEFAULT_GOMODCACHE="${PWD}/build/.cache/go-mod-${ENV_FLAVOR}"
DEFAULT_GOLANGCI_CACHE="${PWD}/build/.cache/golangci-${ENV_FLAVOR}"
GOCACHE_DIR="${CBMPC_GOCACHE:-${DEFAULT_GOCACHE}}"
GOMODCACHE_DIR="${CBMPC_GOMODCACHE:-${DEFAULT_GOMODCACHE}}"
GOLANGCI_CACHE_DIR="${CBMPC_GOLANGCI_CACHE:-${DEFAULT_GOLANGCI_CACHE}}"
mkdir -p "${GOCACHE_DIR}" "${GOMODCACHE_DIR}" "${GOLANGCI_CACHE_DIR}"
export GOCACHE="${GOCACHE_DIR}"
export GOMODCACHE="${GOMODCACHE_DIR}"
export GOLANGCI_LINT_CACHE="${GOLANGCI_CACHE_DIR}"

if [[ "${CBMPC_USE_DOCKER:-0}" == "1" ]]; then
  CBMPC_ENV_FLAVOR=docker scripts/docker_exec.sh golangci-lint "$@"
  exit 0
fi

# Set CGO flags for OpenSSL based on build flavor (host only)
OPENSSL_ROOT="${PWD}/build/openssl-${ENV_FLAVOR}"
export CGO_CFLAGS="${CGO_CFLAGS:-} -I${OPENSSL_ROOT}/include"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:-} -I${OPENSSL_ROOT}/include"
export CGO_LDFLAGS="${CGO_LDFLAGS:-} -L${OPENSSL_ROOT}/lib"

if command -v golangci-lint >/dev/null 2>&1; then
  exec golangci-lint "$@"
fi

GO_VERSION="${GO_VERSION:-1.23.12}"
GO_ROOT="${CBMPC_GO_ROOT:-${PWD}/build/go-${ENV_FLAVOR}}"
LOCAL_GO="${GO_ROOT}/go/bin/go"

if ! command -v go >/dev/null 2>&1; then
  if [[ ! -x "${LOCAL_GO}" ]]; then
    scripts/install_go.sh "${GO_ROOT}" "${GO_VERSION}"
  fi
  PATH="${GO_ROOT}/go/bin:${PATH}"
fi

TOOLS_BIN="${CBMPC_TOOLS_BIN:-${PWD}/build/bin-${ENV_FLAVOR}}"
GOLANGCI_LINT_VERSION="${GOLANGCI_LINT_VERSION:-v1.64.8}"
LOCAL_BIN="${TOOLS_BIN}/golangci-lint"

if [[ ! -x "${LOCAL_BIN}" ]]; then
  mkdir -p "${TOOLS_BIN}"
  scripts/install_golangci.sh "${LOCAL_BIN}" "${GOLANGCI_LINT_VERSION}"
fi

PATH="${GO_ROOT}/go/bin:${TOOLS_BIN}:${PATH}" exec "${LOCAL_BIN}" "$@"
