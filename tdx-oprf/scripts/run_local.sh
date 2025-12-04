#!/bin/bash
set -e

echo "Building TDX OPRF workspace in local mode..."
cd "$(dirname "$0")/.."
cargo build --release

echo ""
echo "Starting enclave (local mode)..."
./target/release/tdx-oprf-enclave &
ENCLAVE_PID=$!

# Wait for enclave to start
sleep 2

echo ""
echo "Running parent (local mode)..."
./target/release/tdx-oprf-parent

# Cleanup
kill $ENCLAVE_PID 2>/dev/null || true

echo ""
echo "Local test completed!"
