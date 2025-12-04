# BN254 OPRF on Intel TDX

This project implements an Oblivious Pseudo-Random Function (OPRF) using the BN254 elliptic curve on Intel TDX (Trust Domain Extensions). It uses the [arkworks](https://github.com/arkworks-rs) library for curve arithmetic.

## Overview

### What is an OPRF?

An Oblivious Pseudo-Random Function (OPRF) allows a client to evaluate a PRF on their input without revealing the input to the server, while the server keeps their key secret. This implementation leverages Intel TDX to provide hardware-based confidential computing guarantees.

### What is Intel TDX?

Intel Trust Domain Extensions (TDX) is a confidential computing technology that uses hardware isolation to protect virtual machines from the host and other VMs. TDX provides:
- Memory encryption and integrity protection
- Remote attestation capabilities
- Isolation from hypervisor and host OS

### Protocol

1. **Enclave Setup**: The TDX enclave generates a secret key `k` and stores `(k, g^k)`
2. **Client Blinding**: The parent samples input `m` and blinding factor `b`, computes `query = g^(m*b)`
3. **Enclave Evaluation**: The enclave computes `output = query^k = g^(m*b*k)` and sends it with attestation
4. **Client Unblinding**: The parent verifies attestation, then computes `unblind = output^(1/b) = g^(m*k)`

The final result is `g^(m*k)` - a deterministic function of `m` that only the enclave can compute.

```
┌─────────────────────────────────────────────────────────────────┐
│                         OPRF Protocol Flow                      │
└─────────────────────────────────────────────────────────────────┘

    Parent (Client)                            TDX Enclave (Server)
    ───────────────                            ────────────────────
         │                                              │
         │ 1. Setup                                     │
         │                                              │ Generate k ← Fr
         │                                              │ Compute pk = g^k
         │                                              │ Store (k, pk)
         │                                              │
         │ 2. Blinding                                  │
         │                                              │
    Sample m ← Fr                                       │
    Sample b ← Fr                                       │
    Compute query = g^(m*b)                             │
    Compute hash(query)                                 │
         │                                              │
         │ 3. Request: {query, hash}                    │
         │─────────────────────────────────────────────>│
         │                                              │
         │                                              │ Verify hash
         │                                              │ Compute output = query^k
         │                                              │               = g^(m*b*k)
         │                                              │ Generate TDX attestation
         │                                              │
         │ 4. Response: {output, pk, attestation}       │
         │<─────────────────────────────────────────────│
         │                                              │
    Verify attestation                                  │
    Compute result = output^(1/b)                       │
                   = g^(m*k)                            │
         │                                              │
         ▼                                              ▼
```

## Project Structure

```
tdx-oprf/
├── Cargo.toml           # Workspace configuration
├── README.md            # This file
├── common/              # Shared types and crypto utilities
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs       # BN254 operations, types, serialization
├── enclave/             # TDX Enclave application
│   ├── Cargo.toml
│   └── src/
│       └── main.rs      # Key generation, OPRF eval, attestation
├── parent/              # Host/parent application
│   ├── Cargo.toml
│   └── src/
│       └── main.rs      # Client blinding, unblinding, verification
└── scripts/
    ├── run_local.sh     # Script for local testing
    └── run_tdx.sh       # Instructions for TDX deployment
```

## Prerequisites

### For Local Testing
- Rust 1.70 or later
- Standard development tools (gcc, make)

### For TDX Deployment
- Azure Confidential VM with Intel TDX support:
  - DCasv5-series or ECasv5-series VMs
- Ubuntu 22.04 or later with TDX-enabled kernel (5.15+)
- Root privileges (required for TDX attestation via configfs-tsm)

## Building

The project supports three modes via feature flags:
- `local` (default): Uses TCP sockets for testing without TDX
- `tdx`: Uses vsock and TDX attestation (requires two-VM setup)
- `tdx-local`: Uses TCP sockets with real TDX attestation (hybrid mode for single Azure TDX VM)

### Local Mode (Default)

```bash
# Build all components
cargo build --release

# Or build individually
cargo build --release --package tdx-oprf-common
cargo build --release --package tdx-oprf-enclave
cargo build --release --package tdx-oprf-parent
```

### TDX Mode

```bash
# Build enclave for TDX
cargo build --release --package tdx-oprf-enclave --features tdx

# Build parent for TDX
cargo build --release --package tdx-oprf-parent --features tdx
```

### TDX-Local Hybrid Mode

This mode combines TCP communication (like local mode) with real TDX attestation (like TDX mode). It's designed for running on a single Azure TDX VM where vsock between CID 2 and CID 3 is not available, but the VM has access to real TDX attestation via `/sys/kernel/config/tsm/report/tdx0`.

```bash
# Build enclave for TDX-Local hybrid mode
cargo build --release --package tdx-oprf-enclave --features tdx-local

# Build parent for TDX-Local hybrid mode
cargo build --release --package tdx-oprf-parent --features tdx-local
```

## Running

### Local Testing

The local mode allows you to test the full OPRF protocol on your development machine without TDX hardware:

#### Option 1: Use the provided script

```bash
./scripts/run_local.sh
```

#### Option 2: Manual execution

```bash
# Terminal 1 - Start the enclave
cargo run --release --package tdx-oprf-enclave

# Terminal 2 - Run the parent
cargo run --release --package tdx-oprf-parent
```

Expected output:

```
[Enclave] Starting TDX OPRF Enclave...
[Enclave] Running in LOCAL mode
[Enclave] Generated secret key and public key
[Enclave] Public key (hex): <hex string>
[Enclave] Local server listening on 127.0.0.1:5000

[Parent] Starting TDX OPRF Parent...
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

### Azure TDX Deployment

For detailed deployment instructions on Azure TDX-enabled VMs:

```bash
./scripts/run_tdx.sh
```

#### Quick Start for TDX

1. **Launch Azure Confidential VM** with TDX support (DCasv5 or ECasv5 series)

2. **Verify TDX is available:**
   ```bash
   dmesg | grep -i tdx
   ls -l /sys/kernel/config/tsm/report/
   ```

3. **Build for TDX:**
   ```bash
   cargo build --release --package tdx-oprf-enclave --features tdx
   cargo build --release --package tdx-oprf-parent --features tdx
   ```

4. **Run the enclave (requires root for attestation):**
   ```bash
   sudo ./target/release/tdx-oprf-enclave
   ```

5. **In another terminal, run the parent:**
   ```bash
   sudo ./target/release/tdx-oprf-parent
   ```

### Single Azure TDX VM Deployment (TDX-Local Hybrid Mode with TPM)

The TDX-Local hybrid mode allows you to test the full TDX attestation flow on a single Azure Confidential VM. **On Azure TDX VMs, the configfs-tsm interface is not available.** Instead, Azure uses vTPM (`/dev/tpm0`) for attestation, where the TPM's PCR measurements are cryptographically bound to the TDX measurements.

This mode is useful when:
- You have a single Azure TDX VM with access to `/dev/tpm0`
- The configfs-tsm interface (`/sys/kernel/config/tsm/report/`) is not available
- vsock communication between CID 2 and CID 3 is not available

#### Prerequisites for TDX-Local

1. **Azure Confidential VM** with TDX support (DCasv5 or ECasv5 series)
2. **tpm2-tools** must be installed:
   ```bash
   sudo apt update
   sudo apt install tpm2-tools
   ```
3. **TPM attestation key** must be created (one-time setup):
   ```bash
   # Create a primary key in the endorsement hierarchy
   tpm2_createprimary -C e -g sha256 -G rsa -c /tmp/primary.ctx
   
   # Create an attestation key under the primary
   tpm2_create -C /tmp/primary.ctx -g sha256 -G rsa -r /tmp/ak.priv -u /tmp/ak.pub -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign"
   
   # Load the attestation key
   tpm2_load -C /tmp/primary.ctx -r /tmp/ak.priv -u /tmp/ak.pub -c /tmp/ak.ctx
   
   # Make it persistent at handle 0x81010001
   tpm2_evictcontrol -C o -c /tmp/ak.ctx 0x81010001
   
   # Verify the key is available
   tpm2_readpublic -c 0x81010001
   ```

#### Quick Start for TDX-Local

1. **Launch Azure Confidential VM** with TDX support (DCasv5 or ECasv5 series)

2. **Verify TPM is available:**
   ```bash
   # Check TPM device
   ls -l /dev/tpm0
   
   # Test TPM functionality
   sudo tpm2_getrandom 8 --hex
   
   # Read PCR values
   sudo tpm2_pcrread sha256
   ```

3. **Install dependencies and create TPM key (one-time setup):**
   ```bash
   sudo apt update
   sudo apt install tpm2-tools
   
   # Create TPM attestation key (see Prerequisites above)
   ```

4. **Build for TDX-Local hybrid mode:**
   ```bash
   cargo build --release --package tdx-oprf-enclave --features tdx-local
   cargo build --release --package tdx-oprf-parent --features tdx-local
   ```

5. **Terminal 1 - Run the enclave (requires root for TPM access):**
   ```bash
   sudo ./target/release/tdx-oprf-enclave
   ```
   
   Expected output:
   ```
   [Enclave] Starting TDX OPRF Enclave...
   [Enclave] Running in TDX-LOCAL hybrid mode (TCP + real TDX attestation)
   [Enclave] Generated secret key and public key
   [Enclave] Local server listening on 127.0.0.1:5000
   [Enclave] Connection received
   [Enclave] Generating TDX attestation (TPM-based)
   [Enclave] Reading PCR values from TPM
   [Enclave] Read PCR values (256 bytes)
   [Enclave] Generating TPM quote
   [Enclave] Generated TPM quote (XXX bytes message, YYY bytes signature)
   [Enclave] Response sent successfully
   ```

6. **Terminal 2 - Run the parent:**
   ```bash
   ./target/release/tdx-oprf-parent
   ```
   
   Expected output:
   ```
   [Parent] Starting TDX OPRF Parent...
   [Parent] Running in TDX-LOCAL hybrid mode (TCP + real TDX attestation)
   [Parent] Connecting to enclave at 127.0.0.1:5000
   [Parent] Connected to enclave
   [Parent] Verifying TPM attestation (Azure TDX)
   [Parent] PCR0: <hash value>
   [Parent] PCR1: <hash value>
   ...
   [Parent] PCR7: <hash value>
   [Parent] TPM attestation document size: XXX bytes
   [Parent] Attestation verified successfully
   [Parent] ================================================
   [Parent] OPRF OUTPUT (g^(m*k)): <hex encoded result>
   [Parent] ================================================
   ```

**Note**: The TDX-Local hybrid mode uses:
- TCP on localhost for communication (like local mode)
- TPM-based attestation via tpm2-tools (specifically for Azure TDX VMs)
- The vTPM's PCR measurements are cryptographically bound to TDX measurements, providing hardware-backed attestation

## Attestation

### Local Mode

In local mode, a mock attestation document is generated for testing purposes. It includes:
- Module ID (mock)
- Timestamp
- Hash of the public key
- Hash of the evaluated point
- Mock MRTD and RTMR values

This allows testing the full protocol flow without TDX hardware.

### TDX Mode (configfs-tsm)

TDX mode uses real TDX attestation via the Linux configfs-tsm interface:

1. **Quote Generation**: The enclave writes report data to `/sys/kernel/config/tsm/report/tdx0/inblob`
2. **Quote Retrieval**: The enclave reads the TDX quote from `/sys/kernel/config/tsm/report/tdx0/outblob`
3. **Measurements**: The quote includes:
   - **MRTD**: Measurement of the TDX module (Trust Domain)
   - **RTMR0-3**: Runtime Measurement Registers (similar to TPM PCRs)
   - **User data**: Hash of the evaluated point
4. **Communication**: Uses vsock (requires two-VM setup with host on CID 2, guest on CID 3)

### TDX-Local Hybrid Mode (TPM-based)

TDX-Local hybrid mode uses TPM-based attestation via tpm2-tools, specifically designed for Azure Confidential VMs:

1. **Quote Generation**: 
   - Reads PCR values (0-7) using `tpm2_pcrread`
   - Generates TPM quote with user data using `tpm2_quote`
   - PCR measurements are cryptographically bound to TDX measurements via vTPM
2. **Measurements**: The attestation includes:
   - **PCR0-7**: Platform Configuration Registers containing boot measurements
   - **TPM Quote**: Signed attestation of PCR values and user data
   - **User data**: Hash of the evaluated point bound to the quote
3. **Communication**: Uses TCP on localhost (works on single Azure TDX VM)

**Why TPM for Azure?** Azure TDX VMs do not expose the configfs-tsm interface. Instead, they use a virtual TPM (vTPM) at `/dev/tpm0` where the TPM's PCR measurements are cryptographically bound to the underlying TDX measurements. This provides equivalent security guarantees while working within Azure's architecture.

**Important for Production**: This implementation includes basic attestation generation but does not implement full verification. For production use, you must:

**For TDX Mode (configfs-tsm):**
1. Verify the quote signature using Intel's Attestation Service
2. Validate MRTD matches your expected TDX module measurement
3. Check RTMR values match expected initial state
4. Verify the quote timestamp is recent
5. Implement proper certificate chain verification

**For TDX-Local Mode (TPM):**
1. Verify the TPM quote signature using the TPM attestation key
2. Validate PCR values match expected boot measurements
3. Confirm user data is correctly bound to the quote
4. Verify that PCRs reflect TDX measurements (via Azure's vTPM binding)
5. Consider using Azure Attestation service for remote verification

## Security Considerations

### Key Generation
The secret key `k` is generated inside the TDX enclave using `OsRng`, which uses the OS's secure random number generator backed by hardware RNG.

### Blinding
The blinding factor `b` ensures the enclave never learns the actual input `m`. The protocol guarantees that:
- The enclave only sees `g^(m*b)` (blinded input)
- The enclave never learns `m` or `b`
- The parent never learns `k`

### TDX Protection
Intel TDX provides:
- **Memory Encryption**: All enclave memory is encrypted with keys derived from the CPU
- **Integrity Protection**: Memory tampering is detected
- **Isolation**: The hypervisor and host OS cannot access enclave memory
- **Remote Attestation**: Cryptographic proof of the code running in the enclave

### Attestation Verification
Always verify attestation in production:
1. Validate the TDX quote signature chain back to Intel's root of trust
2. Check MRTD matches your expected enclave measurement
3. Verify RTMR values to ensure proper initialization
4. Confirm the quote is recent (check timestamp)
5. Validate user data bindings match expected values

### Side Channels
This implementation does not include protection against:
- Timing attacks
- Cache-based side channels
- Speculative execution attacks

For high-security applications, consider using constant-time implementations of cryptographic operations.

## API Reference

### OprfRequest
```rust
struct OprfRequest {
    blinded_query: Vec<u8>,  // Serialized g^(m*b)
    query_hash: String,      // SHA256 hash for integrity
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

### AttestationDocument
```rust
struct AttestationDocument {
    is_mock: bool,              // true for local mode, false for TDX
    document: Vec<u8>,          // TDX quote (or mock data)
    mrtd: Option<String>,       // Measurement of TDX module
    rtmrs: Option<Vec<String>>, // Runtime Measurement Registers
    user_data: Vec<u8>,         // User data bound to attestation
}
```

## Common Library Functions

```rust
// Serialize/deserialize G1 points
pub fn serialize_g1(point: &G1Projective) -> Result<Vec<u8>, String>
pub fn deserialize_g1(bytes: &[u8]) -> Result<G1Projective, String>

// BN254 operations
pub fn g1_generator() -> G1Projective
pub fn random_scalar<R: Rng>(rng: &mut R) -> Fr
pub fn scalar_mul_generator(scalar: &Fr) -> G1Projective
pub fn scalar_mul(point: &G1Projective, scalar: &Fr) -> G1Projective
pub fn scalar_inverse(scalar: &Fr) -> Option<Fr>

// Utilities
pub fn sha256_hex(data: &[u8]) -> String
```

## Dependencies

- **ark-bn254** (0.4): BN254 curve implementation
- **ark-ec/ark-ff** (0.4): Elliptic curve and field arithmetic
- **ark-serialize** (0.4): Serialization for curve elements
- **serde/serde_json** (1.0): JSON serialization
- **nix** (0.27): Unix socket operations (vsock for TDX)
- **rand** (0.8): Random number generation
- **sha2** (0.10): SHA-256 hashing
- **hex** (0.4): Hex encoding/decoding

## Troubleshooting

### Build Errors

**Problem**: Compilation fails with missing dependencies
```bash
# Solution: Update Cargo dependencies
cargo update
cargo clean
cargo build --release
```

### Local Testing Issues

**Problem**: "Address already in use" error
```bash
# Solution: Kill existing enclave process
pkill tdx-oprf-enclave
# Or find and kill the specific process
lsof -i :5000
kill <PID>
```

**Problem**: Connection refused
```bash
# Solution: Ensure enclave is running first
# Wait a few seconds after starting enclave before running parent
```

### TDX and TDX-Local Deployment Issues

**Problem**: `/sys/kernel/config/tsm/report/` not found
```bash
# Solution: Mount configfs and check TDX support
sudo mount -t configfs none /sys/kernel/config
dmesg | grep -i tdx
# Verify TDX is enabled in BIOS
```

**Problem**: Permission denied when accessing configfs-tsm
```bash
# Solution: Run with root privileges
sudo ./target/release/tdx-oprf-enclave
```

**Problem**: vsock connection fails (TDX mode only)
```bash
# Solution: TDX mode requires a two-VM setup with vsock
# If you only have a single Azure TDX VM, use tdx-local mode instead:
cargo build --release --package tdx-oprf-enclave --features tdx-local
cargo build --release --package tdx-oprf-parent --features tdx-local
```

**Problem**: vsock connection fails (standard TDX mode)
```bash
# Solution: Check vsock module and CID assignment
sudo modprobe vsock
cat /sys/devices/virtual/vsock/*/local_cid
# Verify firewall isn't blocking vsock
```

**Problem**: Attestation quote generation fails
```bash
# Solution: Check TDX kernel support
uname -r  # Should be 5.15 or later
dmesg | grep -i tdx
# Verify TDX attestation driver is loaded
lsmod | grep tdx
```

### TPM Attestation Issues (TDX-Local Mode)

**Problem**: `tpm2_pcrread` or `tpm2_quote` command not found
```bash
# Solution: Install tpm2-tools
sudo apt update
sudo apt install tpm2-tools
```

**Problem**: TPM device `/dev/tpm0` not found
```bash
# Solution: Check if TPM is available
ls -l /dev/tpm*
# On Azure VMs, verify you're using a TDX-enabled VM (DCasv5/ECasv5 series)
# Check TPM module is loaded
lsmod | grep tpm
sudo modprobe tpm_tis
```

**Problem**: `tpm2_quote` fails with "key not found" or "handle does not exist"
```bash
# Solution: Create the TPM attestation key (see Prerequisites in TDX-Local section)
# Or verify the key exists:
sudo tpm2_readpublic -c 0x81010001
```

**Problem**: Permission denied accessing TPM
```bash
# Solution: Run with root privileges
sudo ./target/release/tdx-oprf-enclave
# Alternatively, add user to tss group (requires re-login):
sudo usermod -a -G tss $USER
```

**Problem**: `tpm2_quote` fails with "Failed to create object"
```bash
# Solution: The persistent key handle may be in use or invalid
# Clear the handle and recreate:
sudo tpm2_evictcontrol -C o -c 0x81010001  # Remove old key if exists
# Then recreate the attestation key (see Prerequisites)
```

## Comparison with AWS Nitro Implementation

This TDX implementation is structurally similar to the AWS Nitro OPRF in this repository but differs in:

| Feature | AWS Nitro | Intel TDX |
|---------|-----------|-----------|
| **Isolation** | Nitro Hypervisor | Hardware-based TDX |
| **Communication** | vsock (Nitro) | vsock (TDX) |
| **Attestation** | NSM (Nitro Security Module) | configfs-tsm interface |
| **Measurements** | PCR0-2 | MRTD + RTMR0-3 |
| **Platform** | AWS EC2 Nitro-enabled | Azure DCasv5/ECasv5 VMs |

Both implementations provide the same OPRF functionality with hardware-backed security guarantees.

## Contributing

Contributions are welcome! Please ensure:
1. Code follows Rust style guidelines (use `cargo fmt`)
2. All tests pass (`cargo test`)
3. Security considerations are documented

## License

MIT License

## References

- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [arkworks Cryptography Library](https://github.com/arkworks-rs)
- [BN254 Curve Specification](https://hackmd.io/@jpw/bn254)
- [OPRF RFC 9497](https://datatracker.ietf.org/doc/rfc9497/)
