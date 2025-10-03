#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "==> Installing Git LFS"
if command -v git >/dev/null 2>&1; then
  git lfs install --skip-repo
else
  echo "git not found; install Git before running bootstrap." >&2
  exit 1
fi

echo "==> Syncing submodules"
git submodule sync --recursive
git submodule update --init --recursive
CBMPC_SKIP_SUBMODULE_SYNC=1 scripts/check_submodule.sh

if [[ "${CBMPC_SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> Building OpenSSL"
  make openssl

  echo "==> Building cb-mpc"
  make build-cbmpc
fi

echo "==> Bootstrapping Go toolchain"
scripts/run_with_go.sh version >/dev/null

echo "==> Bootstrapping golangci-lint"
scripts/run_golangci.sh version >/dev/null 2>&1 || true

echo "Bootstrap completed."
