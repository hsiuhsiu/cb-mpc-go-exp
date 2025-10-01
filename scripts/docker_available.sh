#!/usr/bin/env bash
set -euo pipefail

DOCKER_BIN="${CBMPC_DOCKER_BIN:-docker}"

if ! command -v "${DOCKER_BIN}" >/dev/null 2>&1; then
  exit 1
fi

if ! "${DOCKER_BIN}" info >/dev/null 2>&1; then
  exit 1
fi

