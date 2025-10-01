#!/bin/bash

# Generate certificates for mTLS demo
# This creates a simple CA and client certificates for demonstration purposes
# In production, use proper PKI infrastructure

set -e

CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

echo "🔐 Generating CA and certificates for mTLS demo..."

# Generate CA private key
openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096

# Generate CA certificate
openssl req -new -x509 -key "$CERT_DIR/ca-key.pem" -sha256 -subj "/C=US/ST=CA/O=CB-MPC-Go/CN=Demo CA" -days 3650 -out "$CERT_DIR/ca-cert.pem"

# Generate server private key
openssl genrsa -out "$CERT_DIR/server-key.pem" 4096

# Generate server certificate signing request
openssl req -subj "/C=US/ST=CA/O=CB-MPC-Go/CN=localhost" -new -key "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr"

# Generate server certificate
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/server-cert.pem" -days 365 -sha256 -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1")

# Generate client1 private key
openssl genrsa -out "$CERT_DIR/client1-key.pem" 4096

# Generate client1 certificate signing request
openssl req -subj "/C=US/ST=CA/O=CB-MPC-Go/CN=client1" -new -key "$CERT_DIR/client1-key.pem" -out "$CERT_DIR/client1.csr"

# Generate client1 certificate
openssl x509 -req -in "$CERT_DIR/client1.csr" -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/client1-cert.pem" -days 365 -sha256

# Generate client2 private key
openssl genrsa -out "$CERT_DIR/client2-key.pem" 4096

# Generate client2 certificate signing request
openssl req -subj "/C=US/ST=CA/O=CB-MPC-Go/CN=client2" -new -key "$CERT_DIR/client2-key.pem" -out "$CERT_DIR/client2.csr"

# Generate client2 certificate
openssl x509 -req -in "$CERT_DIR/client2.csr" -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/client2-cert.pem" -days 365 -sha256

# Clean up CSR files
rm "$CERT_DIR"/*.csr

echo "✅ Certificates generated in $CERT_DIR/"
echo "🔒 CA Certificate: $CERT_DIR/ca-cert.pem"
echo "🖥️  Server: $CERT_DIR/server-cert.pem, $CERT_DIR/server-key.pem"
echo "👤 Client1: $CERT_DIR/client1-cert.pem, $CERT_DIR/client1-key.pem"
echo "👤 Client2: $CERT_DIR/client2-cert.pem, $CERT_DIR/client2-key.pem"
echo ""
echo "⚠️  These are DEMO certificates only. Use proper PKI in production!"