#!/bin/bash
set -e

echo "Building workspace in local mode..."
cargo build --release

echo ""
echo "Starting enclave (local mode)..."
./target/release/oprf-enclave &
ENCLAVE_PID=$!

# Wait for enclave to start
sleep 2

echo ""
echo "Running parent (local mode)..."
./target/release/oprf-parent

# Cleanup
kill $ENCLAVE_PID 2>/dev/null || true

echo ""
echo "Local test completed!"