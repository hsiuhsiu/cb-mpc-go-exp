#!/bin/bash
# Convenience script to run all parties in background
# Useful for testing, but in production each party runs on separate machine

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Parse number of parties from config
NUM_PARTIES=$(jq '.parties | length' config.json 2>/dev/null || echo "2")

# Check if certificates exist
if [ ! -d "certs" ] || [ ! -f "certs/ca.pem" ]; then
    echo "Certificates not found. Running setup..."
    ./setup.sh
fi

echo "=== Running $NUM_PARTIES parties in background ==="
echo

# Clean up function
cleanup() {
    echo
    echo "Cleaning up background processes..."
    pkill -P $$ 2>/dev/null || true
    exit
}
trap cleanup EXIT INT TERM

# Build the program first
echo "Building..."
bash ../../scripts/go_with_cpp.sh go build -o agree_random_mtls main.go
echo "✅ Build complete"
echo

# Start each party in background
PIDS=()
for ((i=0; i<NUM_PARTIES; i++)); do
    echo "Starting party $i..."
    ./agree_random_mtls -party $i > "party-$i.log" 2>&1 &
    PID=$!
    PIDS+=($PID)
    echo "  Party $i started (PID: $PID, log: party-$i.log)"

    # Small delay between starts to ensure proper connection ordering
    sleep 1
done

echo
echo "All parties started. Waiting for completion..."
echo "Logs are being written to party-*.log"
echo

# Wait for all parties to complete
for PID in "${PIDS[@]}"; do
    wait $PID 2>/dev/null || true
done

echo
echo "=== All parties completed ==="
echo
echo "Output from each party:"
echo

# Display results from logs
for ((i=0; i<NUM_PARTIES; i++)); do
    echo "--- Party $i ---"
    if [ -f "party-$i.log" ]; then
        grep -E "(result:|✅|🎉)" "party-$i.log" || cat "party-$i.log" | tail -5
    fi
    echo
done

echo "Full logs available in party-*.log files"
