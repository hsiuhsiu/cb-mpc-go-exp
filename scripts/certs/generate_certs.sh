#!/bin/bash
# Generate TLS certificates for MPC parties
# Usage: ./generate_certs.sh <num_parties> [output_dir]

set -e

NUM_PARTIES=${1:-2}
OUTPUT_DIR=${2:-"./certs"}

echo "=== Generating TLS certificates for $NUM_PARTIES parties ==="
echo "Output directory: $OUTPUT_DIR"
echo

# Create directory structure
mkdir -p "$OUTPUT_DIR"

# Step 1: Generate CA
echo "Step 1: Generating CA certificate..."
openssl genpkey -algorithm RSA -out "$OUTPUT_DIR/ca-key.pem" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -new -x509 -key "$OUTPUT_DIR/ca-key.pem" -out "$OUTPUT_DIR/ca.pem" -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=CB-MPC/CN=CA Root Certificate" 2>/dev/null
echo "✅ CA certificate generated"
echo

# Step 2: Generate certificates for each party
for ((i=0; i<NUM_PARTIES; i++)); do
    PARTY_DIR="$OUTPUT_DIR/party-$i"
    mkdir -p "$PARTY_DIR"

    echo "Step 2.$i: Generating certificate for party $i..."

    # Create OpenSSL config for this party
    cat > "$PARTY_DIR/openssl.cnf" <<EOF
[ req ]
default_bits       = 2048
distinguished_name = party$i
req_extensions     = req_ext
x509_extensions    = v3_req
prompt             = no

[ party$i ]
countryName                = US
stateOrProvinceName        = California
localityName               = San Francisco
organizationName           = CB-MPC
commonName                 = party$i

[ req_ext ]
subjectAltName = @alt_names

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = party$i
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

    # Generate private key
    openssl genpkey -algorithm RSA -out "$PARTY_DIR/key.pem" -pkeyopt rsa_keygen_bits:2048 2>/dev/null

    # Generate certificate signing request
    openssl req -new -key "$PARTY_DIR/key.pem" -out "$PARTY_DIR/cert.csr" \
        -config "$PARTY_DIR/openssl.cnf" 2>/dev/null

    # Sign certificate with CA
    openssl x509 -req -in "$PARTY_DIR/cert.csr" -CA "$OUTPUT_DIR/ca.pem" \
        -CAkey "$OUTPUT_DIR/ca-key.pem" -CAcreateserial -out "$PARTY_DIR/cert.pem" \
        -days 365 -extensions v3_req -extfile "$PARTY_DIR/openssl.cnf" 2>/dev/null

    # Convert to DER format (for demos compatibility if needed)
    openssl x509 -in "$PARTY_DIR/cert.pem" -outform DER -out "$PARTY_DIR/cert.der" 2>/dev/null

    # Clean up CSR
    rm "$PARTY_DIR/cert.csr"

    echo "✅ Party $i certificate generated at $PARTY_DIR/"
done

echo
echo "=== Certificate generation complete ==="
echo "Files generated:"
echo "  - CA certificate: $OUTPUT_DIR/ca.pem"
echo "  - CA private key: $OUTPUT_DIR/ca-key.pem"
for ((i=0; i<NUM_PARTIES; i++)); do
    echo "  - Party $i: $OUTPUT_DIR/party-$i/{key.pem,cert.pem}"
done
echo
echo "⚠️  Keep private keys (*.pem) secure!"
echo "✅ Ready for mTLS communication"
