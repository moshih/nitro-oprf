#!/bin/bash
# Script for running TDX OPRF on Azure TDX-enabled instances
# This script provides instructions and commands for TDX deployment

cat << 'EOF'
================================================================================
TDX OPRF Deployment Instructions
================================================================================

Prerequisites:
1. Azure Confidential VM with Intel TDX support (DCasv5 or ECasv5 series)
2. Ubuntu 22.04 or later with TDX kernel (5.15+)
3. Rust toolchain installed

================================================================================
Build Instructions:
================================================================================

1. Build the enclave for TDX mode:
   cargo build --release --package tdx-oprf-enclave --features tdx

2. Build the parent for TDX mode:
   cargo build --release --package tdx-oprf-parent --features tdx

================================================================================
Deployment Steps:
================================================================================

Host/Parent VM (CID 2):
-----------------------
1. Ensure the TDX kernel module is loaded:
   lsmod | grep tdx

2. Verify vsock is available:
   ls -l /dev/vsock

3. Run the parent application:
   sudo ./target/release/tdx-oprf-parent

Guest/Enclave VM (CID 3):
-------------------------
1. Verify TDX is active:
   dmesg | grep -i tdx

2. Check configfs-tsm interface is available:
   ls -l /sys/kernel/config/tsm/report/

3. Run the enclave application (requires root for attestation):
   sudo ./target/release/tdx-oprf-enclave

================================================================================
Troubleshooting:
================================================================================

If configfs-tsm is not available:
- Ensure TDX is enabled in BIOS/UEFI
- Check kernel version supports TDX (5.15+)
- Mount configfs if needed: mount -t configfs none /sys/kernel/config

If vsock connection fails:
- Check vsock module is loaded: modprobe vsock
- Verify CID assignment: cat /sys/devices/virtual/vsock/*/local_cid
- Check firewall rules are not blocking vsock

For attestation issues:
- Verify TDX attestation service is accessible
- Check configfs-tsm permissions (may need root)
- Review dmesg for TDX-related errors

================================================================================
Notes:
================================================================================

- The parent (host) typically runs on CID 2
- The enclave (guest) typically runs on CID 3
- Port 5000 is used by default for vsock communication
- TDX attestation requires root privileges for configfs-tsm access
- In production, implement full quote verification with Intel Attestation Service

================================================================================
EOF
