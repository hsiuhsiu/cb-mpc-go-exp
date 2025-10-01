#!/bin/bash
set -e

# Build script for cb-mpc C++ library
# Usage: ./scripts/build_cpp.sh [Debug|Test|Release]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CB_MPC_DIR="$REPO_ROOT/cb-mpc"

BUILD_TYPE="${1:-Release}"

echo "Building cb-mpc C++ library (BUILD_TYPE=$BUILD_TYPE)..."

cd "$CB_MPC_DIR"

# Initialize submodules if needed
if [ ! -f "vendors/secp256k1/include/secp256k1.h" ]; then
    echo "Initializing submodules..."
    git submodule update --init --recursive
fi

# Build OpenSSL if needed (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    if [ ! -d "/usr/local/opt/openssl@3.2.0" ]; then
        echo "Building OpenSSL for macOS..."
        if [[ $(uname -m) == "arm64" ]]; then
            bash scripts/openssl/build-static-openssl-macos-m1.sh
        else
            bash scripts/openssl/build-static-openssl-macos.sh
        fi
    fi
fi

# Build cb-mpc library
echo "Building cb-mpc library..."
make clean || true
BUILD_TYPE="$BUILD_TYPE" make build

echo "cb-mpc library built successfully at $CB_MPC_DIR/lib/$BUILD_TYPE"
