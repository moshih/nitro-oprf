use ark_bn254::Fr;
use ark_ff::UniformRand;
use tdx_oprf_common::{
    deserialize_g1, scalar_mul, scalar_mul_generator, serialize_g1, sha256_hex,
    AttestationDocument, OprfRequest, OprfResponse,
};
use rand::rngs::OsRng;
use std::io::{Read, Write};

#[cfg(all(feature = "tdx", not(feature = "tdx-local")))]
use std::os::unix::io::AsRawFd;

#[cfg(any(all(feature = "local", not(feature = "tdx"), not(feature = "tdx-local")), feature = "tdx-local"))]
const LOCAL_PORT: u16 = 5000;

#[cfg(all(feature = "tdx", not(feature = "tdx-local")))]
const VSOCK_PORT: u32 = 5000;
#[cfg(all(feature = "tdx", not(feature = "tdx-local")))]
const VSOCK_CID_ANY: u32 = 0xFFFFFFFF;

// TPM constants
#[cfg(feature = "tdx-local")]
const TPM_AK_HANDLE: &str = "0x81010001"; // TPM attestation key handle
#[cfg(feature = "tdx-local")]
const SHA256_HASH_SIZE: usize = 32; // SHA256 produces 32-byte hashes
#[cfg(feature = "tdx-local")]
const NUM_PCRS: usize = 8; // Number of PCRs to read (0-7)

/// Enclave state holding the secret key and public key
struct EnclaveState {
    /// Secret key k
    secret_key: Fr,
    /// Public key g^k (serialized)
    public_key_bytes: Vec<u8>,
}

impl EnclaveState {
    fn new() -> Self {
        let mut rng = OsRng;
        let secret_key = Fr::rand(&mut rng);
        let public_key = scalar_mul_generator(&secret_key);
        let public_key_bytes = serialize_g1(&public_key).expect("Failed to serialize public key");

        println!("[Enclave] Generated secret key and public key");
        println!("[Enclave] Public key (hex): {}", hex::encode(&public_key_bytes));

        Self {
            secret_key,
            public_key_bytes,
        }
    }

    fn evaluate(&self, request: &OprfRequest) -> Result<OprfResponse, String> {
        // Verify hash
        let computed_hash = sha256_hex(&request.blinded_query);
        if computed_hash != request.query_hash {
            return Err("Query hash mismatch".to_string());
        }

        // Deserialize the blinded query point
        let blinded_query = deserialize_g1(&request.blinded_query)
            .map_err(|e| format!("Failed to deserialize query: {}", e))?;

        println!("[Enclave] Received blinded query");

        // Compute output = blinded_query^k
        let evaluated = scalar_mul(&blinded_query, &self.secret_key);
        let evaluated_bytes =
            serialize_g1(&evaluated).map_err(|e| format!("Failed to serialize result: {}", e))?;

        println!("[Enclave] Computed OPRF evaluation");

        // Generate attestation
        let attestation = self.generate_attestation(&evaluated_bytes)?;

        Ok(OprfResponse {
            evaluated_point: evaluated_bytes,
            public_key: self.public_key_bytes.clone(),
            attestation,
        })
    }

    #[cfg(all(feature = "local", not(feature = "tdx"), not(feature = "tdx-local")))]
    fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationDocument, String> {
        println!("[Enclave] Generating mock attestation (local mode)");

        // Create a mock attestation for local testing
        let mock_doc = serde_json::json!({
            "module_id": "tdx-mock-enclave",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "public_key_hash": sha256_hex(&self.public_key_bytes),
            "user_data_hash": sha256_hex(user_data),
        });

        Ok(AttestationDocument {
            is_mock: true,
            document: serde_json::to_vec(&mock_doc).unwrap(),
            mrtd: Some("0".repeat(96)), // Mock MRTD
            rtmrs: Some(vec![
                "0".repeat(96), // RTMR0 - mock
                "0".repeat(96), // RTMR1 - mock
                "0".repeat(96), // RTMR2 - mock
                "0".repeat(96), // RTMR3 - mock
            ]),
            user_data: user_data.to_vec(),
        })
    }

    #[cfg(all(feature = "tdx", not(feature = "tdx-local")))]
    fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationDocument, String> {
        println!("[Enclave] Generating TDX attestation");

        // Use configfs-tsm interface to generate TDX quote
        use std::fs;
        use std::path::Path;

        let report_path = Path::new("/sys/kernel/config/tsm/report/tdx0");
        
        // Create report directory if it doesn't exist
        if !report_path.exists() {
            fs::create_dir_all(report_path)
                .map_err(|e| format!("Failed to create report directory: {}", e))?;
        }

        let inblob_path = report_path.join("inblob");
        let outblob_path = report_path.join("outblob");

        // Hash the evaluated point to include in attestation
        let report_data = sha256_hex(user_data);
        
        // Write report data to inblob
        fs::write(&inblob_path, report_data.as_bytes())
            .map_err(|e| format!("Failed to write to inblob: {}", e))?;

        println!("[Enclave] Wrote report data to configfs-tsm");

        // Read the TDX quote from outblob
        let quote = fs::read(&outblob_path)
            .map_err(|e| format!("Failed to read quote from outblob: {}", e))?;

        println!("[Enclave] Read TDX quote ({} bytes)", quote.len());

        // Extract MRTD and RTMR values from the quote
        // TDX quote format includes these at specific offsets
        let (mrtd, rtmrs) = extract_tdx_measurements(&quote);

        Ok(AttestationDocument {
            is_mock: false,
            document: quote,
            mrtd,
            rtmrs,
            user_data: user_data.to_vec(),
        })
    }

    #[cfg(feature = "tdx-local")]
    fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationDocument, String> {
        println!("[Enclave] Generating TDX attestation (TPM-based)");

        use std::process::Command;
        use std::fs;
        use tempfile::NamedTempFile;

        // Hash the evaluated point to include as user data in TPM quote
        let user_data_hex = hex::encode(sha256_hex(user_data).as_bytes());

        // Create secure temporary files
        let pcr_file = NamedTempFile::new()
            .map_err(|e| format!("Failed to create temp file for PCRs: {}", e))?;
        let quote_msg_file = NamedTempFile::new()
            .map_err(|e| format!("Failed to create temp file for quote message: {}", e))?;
        let quote_sig_file = NamedTempFile::new()
            .map_err(|e| format!("Failed to create temp file for quote signature: {}", e))?;
        let quote_pcr_file = NamedTempFile::new()
            .map_err(|e| format!("Failed to create temp file for quote PCRs: {}", e))?;

        // Read PCR values
        println!("[Enclave] Reading PCR values from TPM");
        let pcr_output = Command::new("tpm2_pcrread")
            .args(["sha256:0,1,2,3,4,5,6,7", "-o", pcr_file.path().to_str().unwrap()])
            .output()
            .map_err(|e| format!("Failed to execute tpm2_pcrread: {}. Ensure tpm2-tools is installed.", e))?;

        if !pcr_output.status.success() {
            let stderr = String::from_utf8_lossy(&pcr_output.stderr);
            return Err(format!("tpm2_pcrread failed: {}", stderr));
        }

        // Read the PCR binary data
        let pcr_data = fs::read(pcr_file.path())
            .map_err(|e| format!("Failed to read PCR data: {}", e))?;

        println!("[Enclave] Read PCR values ({} bytes)", pcr_data.len());

        // Generate TPM quote with user data
        println!("[Enclave] Generating TPM quote");
        let quote_output = Command::new("tpm2_quote")
            .args([
                "-c", TPM_AK_HANDLE,
                "-l", "sha256:0,1,2,3,4,5,6,7",
                "-q", &user_data_hex,
                "-m", quote_msg_file.path().to_str().unwrap(),
                "-s", quote_sig_file.path().to_str().unwrap(),
                "-o", quote_pcr_file.path().to_str().unwrap(),
            ])
            .output()
            .map_err(|e| format!("Failed to execute tpm2_quote: {}", e))?;

        if !quote_output.status.success() {
            let stderr = String::from_utf8_lossy(&quote_output.stderr);
            return Err(format!("tpm2_quote failed: {}. The TPM key may need to be created first.", stderr));
        }

        // Read the quote message and signature
        let quote_msg = fs::read(quote_msg_file.path())
            .map_err(|e| format!("Failed to read quote message: {}", e))?;
        let quote_sig = fs::read(quote_sig_file.path())
            .map_err(|e| format!("Failed to read quote signature: {}", e))?;

        println!("[Enclave] Generated TPM quote ({} bytes message, {} bytes signature)", 
                 quote_msg.len(), quote_sig.len());

        // Combine quote components into document
        // Format: [quote_msg_len (4 bytes)][quote_msg][quote_sig_len (4 bytes)][quote_sig][pcr_data]
        let mut document = Vec::new();
        document.extend_from_slice(&(quote_msg.len() as u32).to_be_bytes());
        document.extend_from_slice(&quote_msg);
        document.extend_from_slice(&(quote_sig.len() as u32).to_be_bytes());
        document.extend_from_slice(&quote_sig);
        document.extend_from_slice(&pcr_data);

        // Extract PCR values for display
        let pcr_values = extract_pcr_values(&pcr_data);

        // Temporary files are automatically cleaned up when they go out of scope

        Ok(AttestationDocument {
            is_mock: false,
            document,
            mrtd: None, // TPM doesn't have MRTD
            rtmrs: Some(pcr_values), // Use rtmrs field for PCR values
            user_data: user_data.to_vec(),
        })
    }
}

#[cfg(all(feature = "tdx", not(feature = "tdx-local")))]
fn extract_tdx_measurements(quote: &[u8]) -> (Option<String>, Option<Vec<String>>) {
    // TDX quote structure (simplified):
    // The quote contains a TD Report which includes:
    // - MRTD at offset 0x20 (48 bytes)
    // - RTMR0-3 at offsets starting from 0x60 (48 bytes each)
    
    if quote.len() < 432 {
        return (None, None);
    }

    // Extract MRTD (48 bytes at offset 32)
    let mrtd = if quote.len() >= 80 {
        Some(hex::encode(&quote[32..80]))
    } else {
        None
    };

    // Extract RTMRs (4 registers, 48 bytes each, starting at offset 96)
    let rtmrs = if quote.len() >= 288 {
        Some(vec![
            hex::encode(&quote[96..144]),   // RTMR0
            hex::encode(&quote[144..192]),  // RTMR1
            hex::encode(&quote[192..240]),  // RTMR2
            hex::encode(&quote[240..288]),  // RTMR3
        ])
    } else {
        None
    };

    (mrtd, rtmrs)
}

#[cfg(feature = "tdx-local")]
fn extract_pcr_values(pcr_data: &[u8]) -> Vec<String> {
    // PCR data format: consecutive SHA256 hash values for PCRs 0-7
    let mut pcr_values = Vec::new();
    
    for i in 0..NUM_PCRS {
        let start = i * SHA256_HASH_SIZE;
        let end = start + SHA256_HASH_SIZE;
        if end <= pcr_data.len() {
            pcr_values.push(hex::encode(&pcr_data[start..end]));
        }
    }
    
    pcr_values
}

#[cfg(any(all(feature = "local", not(feature = "tdx"), not(feature = "tdx-local")), feature = "tdx-local"))]
fn run_server(state: EnclaveState) -> std::io::Result<()> {
    use std::net::TcpListener;

    let listener = TcpListener::bind(format!("127.0.0.1:{}", LOCAL_PORT))?;
    println!("[Enclave] Local server listening on 127.0.0.1:{}", LOCAL_PORT);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("[Enclave] Connection received");
                handle_connection(&mut stream, &state);
            }
            Err(e) => eprintln!("[Enclave] Connection error: {}", e),
        }
    }
    Ok(())
}

#[cfg(all(feature = "tdx", not(feature = "tdx-local")))]
fn run_server(state: EnclaveState) -> std::io::Result<()> {
    use nix::sys::socket::{
        accept, bind, listen, socket, AddressFamily, SockFlag, SockType, VsockAddr,
    };
    use std::os::unix::io::FromRawFd;

    let sock_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let addr = VsockAddr::new(VSOCK_CID_ANY, VSOCK_PORT);
    bind(sock_fd.as_raw_fd(), &addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    listen(&sock_fd, 128)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    println!("[Enclave] TDX vsock server listening on port {}", VSOCK_PORT);

    loop {
        match accept(sock_fd.as_raw_fd()) {
            Ok(client_fd) => {
                println!("[Enclave] Connection received");
                let mut stream = unsafe { std::net::TcpStream::from_raw_fd(client_fd) };
                handle_connection(&mut stream, &state);
            }
            Err(e) => eprintln!("[Enclave] Accept error: {}", e),
        }
    }
}

fn handle_connection<S: Read + Write>(stream: &mut S, state: &EnclaveState) {
    // Read length-prefixed message
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        eprintln!("[Enclave] Failed to read message length");
        return;
    }
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    if stream.read_exact(&mut buf).is_err() {
        eprintln!("[Enclave] Failed to read message body");
        return;
    }

    // Parse request
    let request: OprfRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[Enclave] Failed to parse request: {}", e);
            return;
        }
    };

    // Process request
    let response = match state.evaluate(&request) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[Enclave] Evaluation failed: {}", e);
            return;
        }
    };

    // Send response
    let response_bytes = match serde_json::to_vec(&response) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[Enclave] Failed to serialize response: {}", e);
            return;
        }
    };

    let len_bytes = (response_bytes.len() as u32).to_be_bytes();
    if stream.write_all(&len_bytes).is_err() || stream.write_all(&response_bytes).is_err() {
        eprintln!("[Enclave] Failed to send response");
        return;
    }

    if stream.flush().is_err() {
        eprintln!("[Enclave] Failed to flush stream");
        return;
    }

    println!("[Enclave] Response sent successfully");
}

fn main() -> std::io::Result<()> {
    println!("[Enclave] Starting TDX OPRF Enclave...");

    #[cfg(all(feature = "local", not(feature = "tdx"), not(feature = "tdx-local")))]
    println!("[Enclave] Running in LOCAL mode");

    #[cfg(all(feature = "tdx", not(feature = "tdx-local")))]
    println!("[Enclave] Running in TDX mode");

    #[cfg(feature = "tdx-local")]
    println!("[Enclave] Running in TDX-LOCAL hybrid mode (TCP + real TDX attestation)");

    let state = EnclaveState::new();
    run_server(state)
}
