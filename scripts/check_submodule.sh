#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

if [[ ! -d third_party/cb-mpc ]]; then
  echo "Submodule directory third_party/cb-mpc missing." >&2
  exit 1
fi

if [[ ! -f third_party/cb-mpc/.git ]]; then
  echo "Submodule third_party/cb-mpc is not initialized. Run 'git submodule update --init --recursive'." >&2
  exit 1
fi

if git -C third_party/cb-mpc status --porcelain | grep -q .; then
  echo "Submodule cb-mpc has local changes; refusing to build." >&2
  exit 1
fi

if ! git submodule status --cached --recursive | grep "third_party/cb-mpc" >/dev/null; then
  echo "Submodule cb-mpc not pinned in index; run 'git submodule update --init --recursive'." >&2
  exit 1
fi
