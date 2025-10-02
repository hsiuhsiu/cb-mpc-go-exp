#!/usr/bin/env bash
set -euo pipefail

DEST_ROOT="${1:-${PWD}/build/go}"
VERSION="${2:-1.22.5}"

INSTALL_DIR="${DEST_ROOT}/go"
GO_BIN="${INSTALL_DIR}/bin/go"

if [[ -x "${GO_BIN}" ]]; then
  CURRENT_VERSION="${3:-}" # optional override for comparison
  if [[ -z "${CURRENT_VERSION}" ]]; then
    exit 0
  fi
fi

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

ARCHIVE="go${VERSION}.${OS_TAG}-${ARCH_TAG}.tar.gz"
URL="https://go.dev/dl/${ARCHIVE}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE}"

curl -fsSL "${URL}" -o "${ARCHIVE_PATH}"

rm -rf "${INSTALL_DIR}"
mkdir -p "${DEST_ROOT}"

tar -xzf "${ARCHIVE_PATH}" -C "${DEST_ROOT}"

