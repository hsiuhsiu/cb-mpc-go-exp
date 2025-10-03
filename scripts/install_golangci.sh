#!/usr/bin/env bash
set -euo pipefail

DEST="${1:-}"
VERSION="${2:-v1.64.8}"

if [[ -z "${DEST}" ]]; then
  DEST="${PWD}/build/bin/golangci-lint"
fi

BIN_DIR="$(dirname "${DEST}")"
mkdir -p "${BIN_DIR}"

if [[ -x "${DEST}" ]]; then
  exit 0
fi

GOBIN="${BIN_DIR}" GOFLAGS=-mod=mod scripts/run_with_go.sh install "github.com/golangci/golangci-lint/cmd/golangci-lint@${VERSION}"

if [[ ! -x "${DEST}" ]]; then
  echo "failed to install golangci-lint to ${DEST}" >&2
  exit 1
fi

