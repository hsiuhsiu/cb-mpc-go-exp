#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <go run arguments...>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GO_CACHE_DIR="${REPO_ROOT}/build/go-example-cache"
mkdir -p "${GO_CACHE_DIR}"

GOCACHE="${GO_CACHE_DIR}" GO111MODULE=on go "$@"
