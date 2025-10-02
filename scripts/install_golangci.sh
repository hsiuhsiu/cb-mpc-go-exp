#!/usr/bin/env bash
set -euo pipefail

DEST="${1:-}"
VERSION="${2:-v1.58.1}"

if [[ -z "${DEST}" ]]; then
  DEST="${PWD}/build/bin/golangci-lint"
fi

BIN_DIR="$(dirname "${DEST}")"
mkdir -p "${BIN_DIR}"

if [[ -x "${DEST}" ]]; then
  exit 0
fi

VERSION_STRIPPED="${VERSION#v}"

case "$(uname -s)" in
  Linux)
    OS_TAG="linux"
    ;;
  Darwin)
    OS_TAG="darwin"
    ;;
  *)
    echo "Unsupported OS: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64)
    ARCH_TAG="amd64"
    ;;
  arm64|aarch64)
    ARCH_TAG="arm64"
    ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

ARCHIVE="golangci-lint-${VERSION_STRIPPED}-${OS_TAG}-${ARCH_TAG}.tar.gz"
URL="https://github.com/golangci/golangci-lint/releases/download/${VERSION}/${ARCHIVE}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE}"

curl -fsSL "${URL}" -o "${ARCHIVE_PATH}"

tar -xzf "${ARCHIVE_PATH}" -C "${TMP_DIR}"

INSTALL_SOURCE="${TMP_DIR}/golangci-lint-${VERSION_STRIPPED}-${OS_TAG}-${ARCH_TAG}/golangci-lint"
if [[ ! -f "${INSTALL_SOURCE}" ]]; then
  echo "golangci-lint binary not found in archive" >&2
  exit 1
fi

mv "${INSTALL_SOURCE}" "${DEST}"
chmod +x "${DEST}"

