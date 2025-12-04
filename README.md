# BN254 OPRF on AWS Nitro Enclave

This project implements an Oblivious Pseudo-Random Function (OPRF) using the BN254 elliptic curve on AWS Nitro Enclaves.  It uses the [arkworks](https://github.com/arkworks-rs) library for curve arithmetic. 

## Overview

### What is an OPRF?

An Oblivious Pseudo-Random Function (OPRF) allows a client to evaluate a PRF on their input without revealing the input to the server, while the server keeps their key secret. 

### Protocol

1. **Enclave Setup**: The enclave generates a secret key `k` and stores `(k, g^k)`
2. **Client Blinding**: The parent samples input `m` and blinding factor `b`, computes `query = g^(m*b)`
3. **Enclave Evaluation**: The enclave computes `output = query^k = g^(m*b*k)`
4. **Client Unblinding**: The parent computes `unblind = output^(1/b) = g^(m*k)`

The final result is `g^(m*k)` - a deterministic function of `m` that only the enclave can compute.

## Project Structure

```
nitro-oprf/
├── Cargo.toml           # Workspace configuration
├── README.md            # This file
├── common/              # Shared types and crypto utilities
├── enclave/             # Nitro Enclave application
├── parent/              # EC2 parent application
├── scripts/             # Build and run scripts
└── enclave.Dockerfile   # Dockerfile for enclave image
```

## Building

### Prerequisites

- Rust 1.70+
- For Nitro deployment: AWS Nitro CLI, Docker

### Local Build (for testing)

```bash
# Build all crates in local mode (default)
cargo build --release

# Or explicitly:
cargo build --release --features local
```

### Nitro Build

```bash
# Build enclave binary
cargo build --release --package oprf-enclave --features nitro

# Build parent binary
cargo build --release --package oprf-parent --features nitro

# Build enclave image (EIF)
./scripts/build_enclave.sh
```

## Running

### Local Testing

The local mode uses TCP sockets instead of vsock, allowing you to test the full protocol on your development machine:

```bash
# Option 1: Use the script
./scripts/run_local.sh

# Option 2: Manual
# Terminal 1 - Start enclave
cargo run --release --package oprf-enclave

# Terminal 2 - Run parent
cargo run --release --package oprf-parent
```

Expected output:
```
[Enclave] Starting OPRF Enclave...
[Enclave] Running in LOCAL mode
[Enclave] Generated secret key and public key
[Enclave] Public key (hex): ... 
[Enclave] Local server listening on 127.0.0.1:5000

[Parent] Starting OPRF Parent...
[Parent] Running in LOCAL mode
[Parent] Sampled random input m
[Parent] Sampled random blinding factor b
[Parent] Computed blinded query g^(m*b)
[Parent] Connected to enclave
[Parent] Received response from enclave
[Parent] Attestation verified successfully
[Parent] ================================================
[Parent] OPRF OUTPUT (g^(m*k)): <hex encoded result>
[Parent] ================================================
```

### AWS Nitro Deployment

1. **Launch a Nitro-enabled EC2 instance** (e.g., m5.xlarge, c5.xlarge)

2. **Install Nitro CLI**:
   ```bash
   sudo amazon-linux-extras install aws-nitro-enclaves-cli
   sudo yum install aws-nitro-enclaves-cli-devel -y
   sudo usermod -aG ne $USER
   sudo usermod -aG docker $USER
   ```

3.  **Configure enclave resources** in `/etc/nitro_enclaves/allocator.yaml`:
   ```yaml
   memory_mib: 512
   cpu_count: 2
   ```

4. **Start the allocator service**:
   ```bash
   sudo systemctl start nitro-enclaves-allocator. service
   sudo systemctl enable nitro-enclaves-allocator.service
   ```

5.  **Build and run the enclave**:
   ```bash
   # Build EIF
   ./scripts/build_enclave.sh
   
   # Run enclave
   nitro-cli run-enclave \
       --cpu-count 2 \
       --memory 512 \
       --eif-path oprf-enclave.eif \
       --debug-mode
   
   # Get enclave CID
   ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r '.[0]. EnclaveCID')
   echo "Enclave CID: $ENCLAVE_CID"
   ```

6. **Run the parent** (update CID if needed):
   ```bash
   cargo run --release --package oprf-parent --features nitro
   ```

7. **View enclave logs** (debug mode only):
   ```bash
   nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
   ```

## Attestation

### Local Mode
In local mode, a mock attestation document is generated for testing. It includes:
- Module ID
- Timestamp
- Hash of the public key
- Hash of the evaluated point

### Nitro Mode
In Nitro mode, real NSM (Nitro Security Module) attestation is used:
- COSE-signed attestation document
- PCR (Platform Configuration Register) values
- User data binding

**Important**: For production use, implement full attestation verification:
1. Verify COSE signature using AWS Nitro root certificate
2.  Validate PCR values match expected enclave image
3. Check attestation timestamp is recent
4.  Verify user data matches expected values

## Security Considerations

1.  **Key Generation**: The secret key `k` is generated inside the enclave using `OsRng`, which uses the OS's secure random number generator.

2. **Blinding**: The blinding factor `b` ensures the enclave never learns the actual input `m`. 

3. **Attestation**: Verify attestation documents in production to ensure you're communicating with a legitimate enclave.

4. **PCR Values**: In production, check PCR0/1/2 match your expected enclave image hash.

5. **Side Channels**: This implementation doesn't include side-channel protections.  For high-security applications, consider constant-time implementations.

## API Reference

### OprfRequest
```rust
struct OprfRequest {
    blinded_query: Vec<u8>,  // Serialized g^(m*b)
    query_hash: String,       // SHA256 hash for integrity
}
```

### OprfResponse
```rust
struct OprfResponse {
    evaluated_point: Vec<u8>,     // Serialized (blinded_query)^k
    public_key: Vec<u8>,          // Serialized g^k
    attestation: AttestationDocument,
}
```

## Dependencies

- **ark-bn254**: BN254 curve implementation
- **ark-ec/ark-ff**: Elliptic curve and field arithmetic
- **ark-serialize**: Serialization for curve elements
- **aws-nitro-enclaves-nsm-api**: NSM driver for attestation (Nitro mode)
- **nix**: Unix socket operations for vsock

## License

MIT License
