FROM amazonlinux:2023 as builder

# Install build dependencies
RUN yum install -y gcc gcc-c++ make openssl-devel

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy source code
WORKDIR /app
COPY . . 

# Build the enclave binary with nitro feature
RUN cargo build --release --package oprf-enclave --features nitro

# Runtime image
FROM amazonlinux:2023

COPY --from=builder /app/target/release/oprf-enclave /app/oprf-enclave

WORKDIR /app
CMD ["/app/oprf-enclave"]