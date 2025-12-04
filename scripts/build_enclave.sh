#!/bin/bash
set -e

echo "Building enclave Docker image..."
docker build -t oprf-enclave -f enclave.Dockerfile . 

echo "Building EIF file..."
nitro-cli build-enclave \
    --docker-uri oprf-enclave:latest \
    --output-file oprf-enclave.eif

echo "EIF file created: oprf-enclave.eif"
echo ""
echo "To run the enclave:"
echo "  nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path oprf-enclave.eif --debug-mode"
echo ""
echo "To get enclave CID:"
echo "  nitro-cli describe-enclaves"