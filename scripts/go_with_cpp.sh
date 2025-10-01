#!/bin/bash
set -e

# Wrapper script to run Go commands with proper CGO environment
# Usage: ./scripts/go_with_cpp.sh go test ./...

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CB_MPC_DIR="$REPO_ROOT/cb-mpc"

BUILD_TYPE="${BUILD_TYPE:-Release}"

# Auto-build C++ library if needed
if [ ! -f "$CB_MPC_DIR/lib/$BUILD_TYPE/libcbmpc.a" ]; then
    echo "C++ library not found, building..."
    bash "$SCRIPT_DIR/build_cpp.sh" "$BUILD_TYPE"
fi

# Set CGO environment variables
export CGO_ENABLED=1
export CGO_CFLAGS="-I${CB_MPC_DIR}/src"
export CGO_CXXFLAGS="-I${CB_MPC_DIR}/src"
export CGO_LDFLAGS="-L${CB_MPC_DIR}/lib/${BUILD_TYPE}"

# macOS-specific OpenSSL paths
if [[ "$OSTYPE" == "darwin"* ]]; then
    export CGO_CFLAGS="$CGO_CFLAGS -I/usr/local/opt/openssl@3.2.0/include"
    export CGO_CXXFLAGS="$CGO_CXXFLAGS -I/usr/local/opt/openssl@3.2.0/include"
    export CGO_LDFLAGS="$CGO_LDFLAGS -L/usr/local/opt/openssl@3.2.0/lib"
fi

echo "CGO_CFLAGS=$CGO_CFLAGS"
echo "CGO_CXXFLAGS=$CGO_CXXFLAGS"
echo "CGO_LDFLAGS=$CGO_LDFLAGS"

# Execute the provided command
exec "$@"
