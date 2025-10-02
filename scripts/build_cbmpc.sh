#!/usr/bin/env bash
set -euo pipefail

BUILD_TYPE="${1:-Release}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FLAVOR="${CBMPC_ENV_FLAVOR:-host}"
CB_MPC_DIR="${REPO_ROOT}/third_party/cb-mpc"
BUILD_DIR="${REPO_ROOT}/build/cb-mpc-${ENV_FLAVOR}"
OPENSSL_ROOT_DEFAULT="${REPO_ROOT}/build/openssl-${ENV_FLAVOR}"
OPENSSL_ROOT="${CBMPC_OPENSSL_ROOT:-${OPENSSL_ROOT_DEFAULT}}"

export CBMPC_OPENSSL_ROOT="${OPENSSL_ROOT}"
export CXXFLAGS="-I${OPENSSL_ROOT}/include ${CXXFLAGS:-}"

cmake -S "${CB_MPC_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" -DBUILD_TESTS=OFF -DCBMPC_OPENSSL_ROOT="${OPENSSL_ROOT}"
cmake --build "${BUILD_DIR}" --target cbmpc --config "${BUILD_TYPE}"
