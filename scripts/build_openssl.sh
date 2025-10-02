#!/usr/bin/env bash
set -euo pipefail

VERSION="3.2.0"
SHA256="14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FLAVOR="${CBMPC_ENV_FLAVOR:-host}"
DEFAULT_PREFIX="${REPO_ROOT}/build/openssl-${ENV_FLAVOR}"
INSTALL_ROOT="${1:-${DEFAULT_PREFIX}}"

# Skip if already built.
if [[ -f "${INSTALL_ROOT}/lib/libcrypto.a" || -f "${INSTALL_ROOT}/lib64/libcrypto.a" ]]; then
  echo "OpenSSL already present in ${INSTALL_ROOT}; skipping rebuild."
  exit 0
fi

WORK_DIR="${REPO_ROOT}/build/tmp-openssl-${ENV_FLAVOR}"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

TARBALL="openssl-${VERSION}.tar.gz"
URL="https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/${TARBALL}"

curl -L "${URL}" -o "${TARBALL}"
if command -v shasum >/dev/null 2>&1; then
  DOWNLOAD_HASH=$(shasum -a 256 "${TARBALL}" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  DOWNLOAD_HASH=$(sha256sum "${TARBALL}" | awk '{print $1}')
else
  echo "No SHA-256 checksum tool available" >&2
  exit 1
fi
if [[ "${DOWNLOAD_HASH}" != "${SHA256}" ]]; then
  echo "Checksum mismatch for ${TARBALL}" >&2
  echo "expected ${SHA256}" >&2
  echo "got      ${DOWNLOAD_HASH}" >&2
  exit 1
fi

tar -xzf "${TARBALL}"
cd "openssl-${VERSION}"

# Enable externally visible symbols for curve25519 implementation.
if [[ "$(uname)" == "Darwin" ]]; then
  sed -i '' -e 's/^static//' crypto/ec/curve25519.c
else
  sed -i -e 's/^static//' crypto/ec/curve25519.c
fi

case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      x86_64)
        CONFIG_TARGET="darwin64-x86_64-cc"
        ;;
      arm64)
        CONFIG_TARGET="darwin64-arm64-cc"
        ;;
      *)
        echo "Unsupported macOS architecture: $(uname -m)" >&2
        exit 1
        ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      x86_64)
        CONFIG_TARGET="linux-x86_64"
        ;;
      aarch64|arm64)
        CONFIG_TARGET="linux-aarch64"
        ;;
      *)
        echo "Unsupported Linux architecture: $(uname -m)" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

CONFIGURE_FLAGS=(
  -g3
  -static
  -DOPENSSL_THREADS
  no-shared
  no-afalgeng
  no-apps
  no-aria
  no-autoload-config
  no-bf
  no-camellia
  no-cast
  no-chacha
  no-cmac
  no-cms
  no-crypto-mdebug
  no-comp
  no-cmp
  no-ct
  no-des
  no-dh
  no-dgram
  no-dsa
  no-dso
  no-dtls
  no-dynamic-engine
  no-ec2m
  no-egd
  no-engine
  no-external-tests
  no-gost
  no-http
  no-idea
  no-mdc2
  no-md2
  no-md4
  no-module
  no-nextprotoneg
  no-ocb
  no-ocsp
  no-psk
  no-padlockeng
  no-poly1305
  no-quic
  no-rc2
  no-rc4
  no-rc5
  no-rfc3779
  no-scrypt
  no-sctp
  no-seed
  no-siphash
  no-sm2
  no-sm3
  no-sm4
  no-sock
  no-srtp
  no-srp
  no-ssl-trace
  no-ssl3
  no-stdio
  no-tests
  no-tls
  no-ts
  no-unit-test
  no-uplink
  no-whirlpool
  no-zlib
  --prefix="${INSTALL_ROOT}"
)

./Configure "${CONFIGURE_FLAGS[@]}" "${CONFIG_TARGET}"

if command -v nproc >/dev/null 2>&1; then
  BUILD_JOBS=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
  BUILD_JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
else
  BUILD_JOBS=1
fi

make -j"${BUILD_JOBS}"
make install_sw

cd "${REPO_ROOT}"
rm -rf "${WORK_DIR}"
