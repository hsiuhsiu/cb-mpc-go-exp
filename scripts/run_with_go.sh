#!/usr/bin/env bash
set -euo pipefail

ENV_FLAVOR="${CBMPC_ENV_FLAVOR:-host}"
DEFAULT_GOCACHE="${PWD}/build/.cache/go-build-${ENV_FLAVOR}"
DEFAULT_GOMODCACHE="${PWD}/build/.cache/go-mod-${ENV_FLAVOR}"
GOCACHE_DIR="${CBMPC_GOCACHE:-${DEFAULT_GOCACHE}}"
GOMODCACHE_DIR="${CBMPC_GOMODCACHE:-${DEFAULT_GOMODCACHE}}"
mkdir -p "${GOCACHE_DIR}" "${GOMODCACHE_DIR}"
export GOCACHE="${GOCACHE_DIR}"
export GOMODCACHE="${GOMODCACHE_DIR}"

USE_DOCKER="${CBMPC_USE_DOCKER:-0}"

if [[ "${USE_DOCKER}" == "1" ]]; then
  if scripts/docker_available.sh >/dev/null 2>&1; then
    if CBMPC_ENV_FLAVOR=docker scripts/docker_exec.sh go "$@"; then
      exit 0
    fi
    echo "Go command failed inside Docker; falling back to host tooling." >&2
  else
    echo "Docker unavailable; running Go command on host." >&2
  fi
fi

if command -v go >/dev/null 2>&1; then
  exec go "$@"
fi

GO_VERSION="${GO_VERSION:-1.22.5}"
GO_ROOT="${CBMPC_GO_ROOT:-${PWD}/build/go-${ENV_FLAVOR}}"
LOCAL_GO="${GO_ROOT}/go/bin/go"

if [[ ! -x "${LOCAL_GO}" ]]; then
  scripts/install_go.sh "${GO_ROOT}" "${GO_VERSION}"
fi

PATH="${GO_ROOT}/go/bin:${PATH}" exec "${LOCAL_GO}" "$@"
