use ark_bn254::Fr;
use ark_ff::UniformRand;
use oprf_common::{
    deserialize_g1, scalar_mul, scalar_mul_generator, serialize_g1,
    sha256_hex, AttestationDocument, OprfRequest, OprfResponse,
};
use rand::rngs::OsRng;
use std::io::{Read, Write};

#[cfg(feature = "nitro")]
use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
#[cfg(feature = "nitro")]
use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
#[cfg(feature = "nitro")]
use std::os::unix::io::AsRawFd;

const VSOCK_PORT: u32 = 5000;
const VSOCK_CID_ANY: u32 = 0xFFFFFFFF;
#[allow(dead_code)]
const VSOCK_CID_PARENT: u32 = 3;
const LOCAL_PORT: u16 = 5000;

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
        let public_key_bytes = serialize_g1(&public_key). expect("Failed to serialize public key");

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
            serialize_g1(&evaluated). map_err(|e| format!("Failed to serialize result: {}", e))?;

        println!("[Enclave] Computed OPRF evaluation");

        // Generate attestation
        let attestation = self.generate_attestation(&evaluated_bytes)?;

        Ok(OprfResponse {
            evaluated_point: evaluated_bytes,
            public_key: self. public_key_bytes.clone(),
            attestation,
        })
    }

    #[cfg(all(feature = "local", not(feature = "nitro")))]
    fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationDocument, String> {
        println!("[Enclave] Generating mock attestation (local mode)");

        // Create a mock attestation for local testing
        let mock_doc = serde_json::json!({
            "module_id": "mock-enclave",
            "timestamp": chrono_lite_timestamp(),
            "public_key_hash": sha256_hex(&self. public_key_bytes),
            "user_data_hash": sha256_hex(user_data),
        });

        Ok(AttestationDocument {
            is_mock: true,
            document: serde_json::to_vec(&mock_doc). unwrap(),
            pcrs: Some(vec![
                "0". repeat(96), // PCR0 - mock
                "0".repeat(96), // PCR1 - mock
                "0".repeat(96), // PCR2 - mock
            ]),
            user_data: user_data.to_vec(),
        })
    }

    #[cfg(feature = "nitro")]
    fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationDocument, String> {
        println!("[Enclave] Generating NSM attestation (Nitro mode)");

        let nsm_fd = nsm_driver::nsm_init();
        if nsm_fd < 0 {
            return Err("Failed to initialize NSM driver".to_string());
        }

        // Include public key and evaluated point hash in attestation
        let mut attestation_data = self.public_key_bytes.clone();
        attestation_data. extend_from_slice(sha256_hex(user_data). as_bytes());

        let request = NsmRequest::Attestation {
            user_data: Some(attestation_data. clone(). into()),
            nonce: None,
            public_key: None,
        };

        let response = nsm_driver::nsm_process_request(nsm_fd, request);

        match response {
            NsmResponse::Attestation { document } => {
                // Parse CBOR to extract PCRs
                let pcrs = extract_pcrs_from_attestation(&document);

                Ok(AttestationDocument {
                    is_mock: false,
                    document,
                    pcrs,
                    user_data: user_data.to_vec(),
                })
            }
            NsmResponse::Error(e) => Err(format!("NSM error: {:?}", e)),
            _ => Err("Unexpected NSM response".to_string()),
        }
    }
}

#[cfg(feature = "nitro")]
fn extract_pcrs_from_attestation(document: &[u8]) -> Option<Vec<String>> {
    // Parse CBOR attestation document to extract PCRs
    let value: serde_cbor::Value = serde_cbor::from_slice(document). ok()?;

    if let serde_cbor::Value::Map(map) = value {
        for (key, val) in map {
            if let serde_cbor::Value::Text(k) = key {
                if k == "pcrs" {
                    if let serde_cbor::Value::Map(pcr_map) = val {
                        let mut pcrs = Vec::new();
                        for i in 0..3 {
                            if let Some((_, serde_cbor::Value::Bytes(bytes))) =
                                pcr_map. iter().find(|(k, _)| **k == serde_cbor::Value::Integer(i))
                            {
                                pcrs.push(hex::encode(bytes));
                            }
                        }
                        return Some(pcrs);
                    }
                }
            }
        }
    }
    None
}

fn chrono_lite_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(all(feature = "local", not(feature = "nitro")))]
fn run_server(state: EnclaveState) -> std::io::Result<()> {
    use std::net::TcpListener;

    let listener = TcpListener::bind(format!("127. 0.0.1:{}", LOCAL_PORT))?;
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

#[cfg(feature = "nitro")]
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
    bind(sock_fd. as_raw_fd(), &addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))? ;

    listen(&sock_fd, 128)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))? ;

    println!("[Enclave] Nitro vsock server listening on port {}", VSOCK_PORT);

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
    if stream. read_exact(&mut len_buf).is_err() {
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
            eprintln!("[Enclave] Evaluation error: {}", e);
            return;
        }
    };

    // Send response
    let response_bytes = serde_json::to_vec(&response).unwrap();
    let len_bytes = (response_bytes.len() as u32).to_be_bytes();

    if stream.write_all(&len_bytes).is_err() || stream. write_all(&response_bytes). is_err() {
        eprintln!("[Enclave] Failed to send response");
    } else {
        println!("[Enclave] Response sent successfully");
    }
}

fn main() {
    println!("[Enclave] Starting OPRF Enclave.. .");

    #[cfg(all(feature = "local", not(feature = "nitro")))]
    println!("[Enclave] Running in LOCAL mode");

    #[cfg(feature = "nitro")]
    println!("[Enclave] Running in NITRO mode");

    let state = EnclaveState::new();

    if let Err(e) = run_server(state) {
        eprintln!("[Enclave] Server error: {}", e);
        std::process::exit(1);
    }
}