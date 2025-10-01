#!/bin/bash
# Setup script for mTLS example
# Generates certificates and prepares the environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Setting up mTLS Example ==="
echo

# Check if config.json exists
if [ ! -f "config.json" ]; then
    echo "❌ config.json not found"
    exit 1
fi

# Parse number of parties from config.json
NUM_PARTIES=$(jq '.parties | length' config.json 2>/dev/null || echo "2")
if [ -z "$NUM_PARTIES" ] || [ "$NUM_PARTIES" -lt 2 ]; then
    echo "⚠️  Could not determine number of parties from config.json, using default: 2"
    NUM_PARTIES=2
fi

echo "Detected $NUM_PARTIES parties in config.json"
echo

# Generate certificates
echo "Step 1: Generating TLS certificates..."
../../scripts/certs/generate_certs.sh "$NUM_PARTIES" "certs"
echo

# Verify certificate paths in config match generated files
echo "Step 2: Verifying certificate paths..."
for ((i=0; i<NUM_PARTIES; i++)); do
    CERT_FILE="certs/party-$i/cert.pem"
    KEY_FILE="certs/party-$i/key.pem"

    if [ ! -f "$CERT_FILE" ]; then
        echo "❌ Certificate not found: $CERT_FILE"
        exit 1
    fi

    if [ ! -f "$KEY_FILE" ]; then
        echo "❌ Private key not found: $KEY_FILE"
        exit 1
    fi

    echo "✅ Party $i: certificate and key verified"
done

CA_CERT="certs/ca.pem"
if [ ! -f "$CA_CERT" ]; then
    echo "❌ CA certificate not found: $CA_CERT"
    exit 1
fi
echo "✅ CA certificate verified"
echo

# Display instructions
echo "=== Setup Complete ==="
echo
echo "Generated certificates for $NUM_PARTIES parties"
echo
echo "To run the example:"
echo
for ((i=0; i<NUM_PARTIES; i++)); do
    PORT=$((8080 + i))
    echo "  Terminal $((i+1)): go run main.go -party $i"
done
echo
echo "Or use the convenience script:"
echo "  ./run.sh"
echo
echo "Configuration file: config.json"
echo "Certificates directory: certs/"
echo
echo "✅ Ready to run!"
