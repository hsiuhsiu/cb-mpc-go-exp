#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 1
fi

COMMAND="$1"
shift

USE_DOCKER="${CBMPC_USE_DOCKER:-0}"

if [[ "${USE_DOCKER}" == "1" ]] && scripts/docker_available.sh >/dev/null 2>&1; then
  if CBMPC_ENV_FLAVOR=docker scripts/docker_exec.sh "${COMMAND}" "$@"; then
    exit 0
  fi
  echo "Docker execution failed; retrying on host." >&2
fi

HOST_FLAVOR="${CBMPC_ENV_FLAVOR:-host}"
CBMPC_USE_DOCKER=0 CBMPC_ENV_FLAVOR="${HOST_FLAVOR}" "${COMMAND}" "$@"
