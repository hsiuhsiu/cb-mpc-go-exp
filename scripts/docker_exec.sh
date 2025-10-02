#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: docker_exec.sh <command> [args...]" >&2
  exit 1
fi

COMMAND_NAME="$1"
shift || true

DOCKER_BIN="${CBMPC_DOCKER_BIN:-docker}"

if ! command -v "${DOCKER_BIN}" >/dev/null 2>&1; then
  echo "${DOCKER_BIN} not found on PATH; install Docker or unset CBMPC_USE_DOCKER." >&2
  exit 1
fi

DOCKER_IMAGE="${CBMPC_DOCKER_IMAGE:-cb-mpc-go/dev}"
DOCKERFILE="${CBMPC_DOCKERFILE:-docker/dev.Dockerfile}"
ENV_FLAVOR="${CBMPC_ENV_FLAVOR:-docker}"

mkdir -p build/.cache/go-build-${ENV_FLAVOR} build/.cache/go-mod-${ENV_FLAVOR} \
  build/.cache/golangci-${ENV_FLAVOR} build/openssl-${ENV_FLAVOR} build/cb-mpc-${ENV_FLAVOR}

if ! "${DOCKER_BIN}" image inspect "${DOCKER_IMAGE}" >/dev/null 2>&1; then
  "${DOCKER_BIN}" build -t "${DOCKER_IMAGE}" -f "${DOCKERFILE}" .
fi

UID_VALUE="$(id -u)"
GID_VALUE="$(id -g)"

"${DOCKER_BIN}" run --rm \
  -v "${PWD}":/workspace \
  -w /workspace \
  -e CBMPC_USE_DOCKER=0 \
  -e CBMPC_ENV_FLAVOR="${ENV_FLAVOR}" \
  -e CBMPC_OPENSSL_ROOT=/workspace/build/openssl-${ENV_FLAVOR} \
  -e CBMPC_GOCACHE=/workspace/build/.cache/go-build-${ENV_FLAVOR} \
  -e CBMPC_GOMODCACHE=/workspace/build/.cache/go-mod-${ENV_FLAVOR} \
  -e CBMPC_GOLANGCI_CACHE=/workspace/build/.cache/golangci-${ENV_FLAVOR} \
  --user "${UID_VALUE}:${GID_VALUE}" \
  "${DOCKER_IMAGE}" "${COMMAND_NAME}" "$@"
