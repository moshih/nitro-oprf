use ark_bn254::Fr;
use ark_ff::UniformRand;
use oprf_common::{
    deserialize_g1, scalar_inverse, scalar_mul, scalar_mul_generator, serialize_g1,
    sha256_hex, AttestationDocument, OprfRequest, OprfResponse,
};
use rand::rngs::OsRng;
use std::io::{Read, Write};

const VSOCK_PORT: u32 = 5000;
const VSOCK_CID_ENCLAVE: u32 = 16; // Default enclave CID
const LOCAL_PORT: u16 = 5000;

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
            .map_err(|e| format!("Failed to parse mock attestation: {}", e))? ;
        
        println!("[Parent] Mock attestation document: {}", 
            serde_json::to_string_pretty(&doc).unwrap());
        
        Ok(())
    } else {
        println!("[Parent] Verifying NSM attestation (Nitro mode)");
        
        // In production, you would:
        // 1. Verify the CBOR/COSE signature using AWS root certificate
        // 2. Check PCR values match expected enclave image
        // 3. Verify timestamp is recent
        // 4. Check user_data matches expected value
        
        if attestation.user_data != expected_user_data {
            return Err("User data mismatch in attestation".to_string());
        }

        if let Some(pcrs) = &attestation.pcrs {
            println!("[Parent] PCR0: {}", pcrs. get(0).unwrap_or(&"N/A".to_string()));
            println!("[Parent] PCR1: {}", pcrs.get(1).unwrap_or(&"N/A".to_string()));
            println!("[Parent] PCR2: {}", pcrs.get(2).unwrap_or(&"N/A".to_string()));
        }

        // For full production verification, use aws-nitro-enclaves-attestation crate
        // or implement COSE signature verification with AWS root CA
        
        println!("[Parent] WARNING: Full attestation verification not implemented");
        println!("[Parent] In production, verify COSE signature with AWS root CA");
        
        Ok(())
    }
}

#[cfg(feature = "local")]
fn connect_to_enclave() -> std::io::Result<std::net::TcpStream> {
    use std::net::TcpStream;
    
    println!("[Parent] Connecting to enclave at 127.0.0.1:{}", LOCAL_PORT);
    TcpStream::connect(format! ("127.0.0.1:{}", LOCAL_PORT))
}

#[cfg(feature = "nitro")]
fn connect_to_enclave() -> std::io::Result<std::net::TcpStream> {
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
    use std::os::unix::io::{FromRawFd, IntoRawFd};

    let sock_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))? ;

    let addr = VsockAddr::new(VSOCK_CID_ENCLAVE, VSOCK_PORT);
    
    println!("[Parent] Connecting to enclave via vsock (CID: {}, Port: {})", 
        VSOCK_CID_ENCLAVE, VSOCK_PORT);
    
    connect(sock_fd.as_raw_fd(), &addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(unsafe { std::net::TcpStream::from_raw_fd(sock_fd. into_raw_fd()) })
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
    println!("[Parent] Starting OPRF Parent...");
    
    #[cfg(feature = "local")]
    println!("[Parent] Running in LOCAL mode");
    
    #[cfg(feature = "nitro")]
    println!("[Parent] Running in NITRO mode");

    let mut rng = OsRng;

    // Sample random input m and blinding factor b
    let m = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);

    println!("[Parent] Sampled random input m");
    println!("[Parent] Sampled random blinding factor b");

    // Compute blinded query: g^(m*b)
    let m_times_b = m * b;
    let blinded_query = scalar_mul_generator(&m_times_b);
    let blinded_query_bytes = serialize_g1(&blinded_query)? ;

    println!("[Parent] Computed blinded query g^(m*b)");
    println!("[Parent] Blinded query (hex): {}", hex::encode(&blinded_query_bytes));

    // Create request with hash
    let query_hash = sha256_hex(&blinded_query_bytes);
    let request = OprfRequest {
        blinded_query: blinded_query_bytes. clone(),
        query_hash: query_hash.clone(),
    };

    println!("[Parent] Query hash: {}", query_hash);

    // Connect to enclave
    let mut stream = connect_to_enclave()?;
    println!("[Parent] Connected to enclave");

    // Send request and get response
    let response = send_request(&mut stream, &request)? ;
    println!("[Parent] Received response from enclave");

    // Verify attestation
    verify_attestation(&response. attestation, &response.evaluated_point)?;
    println!("[Parent] Attestation verified successfully");

    // Deserialize the evaluated point
    let evaluated = deserialize_g1(&response. evaluated_point)?;
    println!("[Parent] Evaluated point (hex): {}", hex::encode(&response.evaluated_point));

    // Unblind: output^(1/b) = g^(m*k)
    let b_inv = scalar_inverse(&b). ok_or("Failed to compute inverse of b")?;
    let unblinded = scalar_mul(&evaluated, &b_inv);
    let unblinded_bytes = serialize_g1(&unblinded)?;

    println!("[Parent] Unblinded result computed");
    println!("[Parent] ================================================");
    println!("[Parent] OPRF OUTPUT (g^(m*k)): {} {:?}", hex::encode(&unblinded_bytes), unblinded);
    println!("[Parent] ================================================");

    // Also display the public key for reference
    println!("[Parent] Enclave public key (g^k): {}", hex::encode(&response.public_key));

    // Verification: compute expected result if we knew k (for testing only)
    // In real usage, k is never revealed
    println!("[Parent] OPRF completed successfully!");

    Ok(())
}