#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: run_host_or_docker.sh <command> [args...]" >&2
  exit 1
fi

COMMAND="$1"
shift

if [[ "${CBMPC_USE_DOCKER:-0}" == "1" ]]; then
  CBMPC_ENV_FLAVOR=docker scripts/docker_exec.sh "${COMMAND}" "$@"
else
  CBMPC_ENV_FLAVOR="${CBMPC_ENV_FLAVOR:-host}" \
  CBMPC_USE_DOCKER=0 \
  "${COMMAND}" "$@"
fi
