#!/bin/bash

# Run ECDSA 2PC mTLS Demo
# This script demonstrates secure two-party ECDSA with mutual TLS authentication

set -e

echo "🔐 ECDSA 2PC with mTLS Demo"
echo "=========================="

# Check if certificates exist
if [ ! -d "./certs" ]; then
    echo "📋 Generating certificates..."
    ./generate_certs.sh
else
    echo "📋 Using existing certificates in ./certs/"
fi

echo ""
echo "📋 Building demo application..."
cd ../..
bash scripts/go_with_cpp.sh go build -o examples/ecdsa2pc_mtls/ecdsa2pc_mtls ./examples/ecdsa2pc_mtls/
cd examples/ecdsa2pc_mtls

echo ""
echo "📋 Starting ECDSA 2PC mTLS demonstration..."
echo "📋 This will run both parties simultaneously to demonstrate the protocol"
echo ""

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "📋 Cleaning up background processes..."
    jobs -p | xargs -r kill
    wait
    echo "✅ Cleanup completed"
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Start Party 0 in background
echo "🚀 Starting Party 0 (Server)..."
./ecdsa2pc_mtls -party=0 -server="localhost:8443" -client="localhost:8444" > party0.log 2>&1 &
PARTY0_PID=$!

# Give Party 0 time to start listening
sleep 2

# Start Party 1 in foreground
echo "🚀 Starting Party 1 (Client)..."
./ecdsa2pc_mtls -party=1 -server="localhost:8443" -client="localhost:8444" > party1.log 2>&1 &
PARTY1_PID=$!

# Wait for both parties to complete
echo "📋 Waiting for protocol completion..."

# Monitor both processes
while kill -0 $PARTY0_PID 2>/dev/null || kill -0 $PARTY1_PID 2>/dev/null; do
    sleep 1
done

# Show results
echo ""
echo "📋 Party 0 Output:"
echo "=================="
cat party0.log

echo ""
echo "📋 Party 1 Output:"
echo "=================="
cat party1.log

echo ""
echo "🎉 Demo completed!"
echo "📋 Check the logs above to see the secure ECDSA 2PC protocol execution"
echo "🔒 All communication was protected by mutual TLS authentication"

# Cleanup log files
rm -f party0.log party1.log