use ark_bn254::Fr;
use ark_ff::UniformRand;
use tdx_oprf_common::{
    deserialize_g1, scalar_inverse, scalar_mul, scalar_mul_generator, serialize_g1, sha256_hex,
    AttestationDocument, OprfRequest, OprfResponse,
};
use rand::rngs::OsRng;
use std::io::{Read, Write};

#[cfg(feature = "tdx")]
use std::os::unix::io::AsRawFd;

#[cfg(all(feature = "local", not(feature = "tdx")))]
const LOCAL_PORT: u16 = 5000;

#[cfg(feature = "tdx")]
const VSOCK_PORT: u32 = 5000;
#[cfg(feature = "tdx")]
const VSOCK_CID_GUEST: u32 = 3; // TDX guest CID (parent is 2, guest is 3)

/// Verify attestation document
fn verify_attestation(
    attestation: &AttestationDocument,
    expected_user_data: &[u8],
) -> Result<(), String> {
    if attestation.is_mock {
        println!("[Parent] Verifying mock attestation (local mode)");

        // In local mode, just verify the user data matches
        if attestation.user_data != expected_user_data {
            return Err("User data mismatch in attestation".to_string());
        }

        // Parse and display mock attestation
        let doc: serde_json::Value = serde_json::from_slice(&attestation.document)
            .map_err(|e| format!("Failed to parse mock attestation: {}", e))?;

        println!(
            "[Parent] Mock attestation document:\n{}",
            serde_json::to_string_pretty(&doc).unwrap()
        );

        Ok(())
    } else {
        println!("[Parent] Verifying TDX attestation");

        // Verify user data matches
        if attestation.user_data != expected_user_data {
            return Err("User data mismatch in attestation".to_string());
        }

        // Display TDX measurements
        if let Some(mrtd) = &attestation.mrtd {
            println!("[Parent] MRTD: {}", mrtd);
        }

        if let Some(rtmrs) = &attestation.rtmrs {
            for (i, rtmr) in rtmrs.iter().enumerate() {
                println!("[Parent] RTMR{}: {}", i, rtmr);
            }
        }

        println!("[Parent] TDX quote size: {} bytes", attestation.document.len());

        // In production, you would:
        // 1. Verify the quote signature using Intel's attestation service
        // 2. Check MRTD matches expected TDX module measurement
        // 3. Check RTMR values match expected initial state
        // 4. Verify the quote is recent (check timestamp)

        println!("[Parent] WARNING: Full TDX quote verification not implemented");
        println!("[Parent] In production, verify quote with Intel Attestation Service");

        Ok(())
    }
}

#[cfg(all(feature = "local", not(feature = "tdx")))]
fn connect_to_enclave() -> std::io::Result<std::net::TcpStream> {
    use std::net::TcpStream;

    println!("[Parent] Connecting to enclave at 127.0.0.1:{}", LOCAL_PORT);
    TcpStream::connect(format!("127.0.0.1:{}", LOCAL_PORT))
}

#[cfg(feature = "tdx")]
fn connect_to_enclave() -> std::io::Result<std::net::TcpStream> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
    use std::os::unix::io::{FromRawFd, IntoRawFd};

    let sock_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let addr = VsockAddr::new(VSOCK_CID_GUEST, VSOCK_PORT);

    println!(
        "[Parent] Connecting to enclave via vsock (CID: {}, Port: {})",
        VSOCK_CID_GUEST, VSOCK_PORT
    );

    connect(sock_fd.as_raw_fd(), &addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(unsafe { std::net::TcpStream::from_raw_fd(sock_fd.into_raw_fd()) })
}

fn send_request<S: Read + Write>(
    stream: &mut S,
    request: &OprfRequest,
) -> std::io::Result<OprfResponse> {
    // Send length-prefixed request
    let request_bytes = serde_json::to_vec(request)?;
    let len_bytes = (request_bytes.len() as u32).to_be_bytes();

    stream.write_all(&len_bytes)?;
    stream.write_all(&request_bytes)?;
    stream.flush()?;

    // Read length-prefixed response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[Parent] Starting TDX OPRF Parent...");

    #[cfg(all(feature = "local", not(feature = "tdx")))]
    println!("[Parent] Running in LOCAL mode");

    #[cfg(feature = "tdx")]
    println!("[Parent] Running in TDX mode");

    let mut rng = OsRng;

    // Sample random input m and blinding factor b
    let m = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);

    println!("[Parent] Sampled random input m");
    println!("[Parent] Sampled random blinding factor b");

    // Compute blinded query: g^(m*b)
    let m_times_b = m * b;
    let blinded_query = scalar_mul_generator(&m_times_b);
    let blinded_query_bytes = serialize_g1(&blinded_query)?;

    println!("[Parent] Computed blinded query g^(m*b)");
    println!(
        "[Parent] Blinded query (hex): {}",
        hex::encode(&blinded_query_bytes)
    );

    // Create request with hash
    let query_hash = sha256_hex(&blinded_query_bytes);
    let request = OprfRequest {
        blinded_query: blinded_query_bytes.clone(),
        query_hash: query_hash.clone(),
    };

    println!("[Parent] Query hash: {}", query_hash);

    // Connect to enclave
    let mut stream = connect_to_enclave()?;
    println!("[Parent] Connected to enclave");

    // Send request and get response
    let response = send_request(&mut stream, &request)?;
    println!("[Parent] Received response from enclave");

    // Verify attestation
    verify_attestation(&response.attestation, &response.evaluated_point)?;
    println!("[Parent] Attestation verified successfully");

    // Deserialize the evaluated point
    let evaluated = deserialize_g1(&response.evaluated_point)?;
    println!(
        "[Parent] Evaluated point (hex): {}",
        hex::encode(&response.evaluated_point)
    );

    // Unblind: output^(1/b) = g^(m*k)
    let b_inv = scalar_inverse(&b).ok_or("Failed to compute inverse of b")?;
    let unblinded = scalar_mul(&evaluated, &b_inv);
    let unblinded_bytes = serialize_g1(&unblinded)?;

    println!("[Parent] Unblinded result computed");
    println!("[Parent] ================================================");
    println!(
        "[Parent] OPRF OUTPUT (g^(m*k)): {}",
        hex::encode(&unblinded_bytes)
    );
    println!("[Parent] ================================================");

    // Also display the public key for reference
    println!(
        "[Parent] Enclave public key (g^k): {}",
        hex::encode(&response.public_key)
    );

    println!("[Parent] OPRF completed successfully!");

    Ok(())
}
