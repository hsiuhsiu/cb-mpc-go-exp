#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-apply}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PATCH_FILE="${REPO_ROOT}/patches/cb-mpc/openssl.cmake.patch"
CB_MPC_DIR="${REPO_ROOT}/third_party/cb-mpc"
TARGET_FILE="${CB_MPC_DIR}/cmake/openssl.cmake"

case "${COMMAND}" in
  apply)
    if grep -q "CBMPC_OPENSSL_ROOT" "${TARGET_FILE}"; then
      exit 0
    fi
    git -C "${CB_MPC_DIR}" apply "${PATCH_FILE}"
    ;;
  restore)
    if [[ -f "${TARGET_FILE}" ]] && grep -q "CBMPC_OPENSSL_ROOT" "${TARGET_FILE}"; then
      git -C "${CB_MPC_DIR}" checkout -- "cmake/openssl.cmake"
    fi
    ;;
  *)
    echo "Unknown command: ${COMMAND}" >&2
    exit 1
    ;;
esac
