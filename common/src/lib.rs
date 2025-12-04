use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur in OPRF operations
#[derive(Error, Debug)]
pub enum OprfError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Invalid point")]
    InvalidPoint,
    #[error("Attestation verification failed: {0}")]
    AttestationFailed(String),
}

/// Request from parent to enclave
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OprfRequest {
    /// Blinded query point g^(m*b) serialized
    pub blinded_query: Vec<u8>,
    /// Hash of the query for integrity
    pub query_hash: String,
}

/// Response from enclave to parent
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OprfResponse {
    /// Evaluated point (blinded_query)^k serialized
    pub evaluated_point: Vec<u8>,
    /// Public key g^k serialized
    pub public_key: Vec<u8>,
    /// Attestation document (NSM attestation in Nitro, mock in local)
    pub attestation: AttestationDocument,
}

/// Attestation document structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationDocument {
    /// Whether this is a real Nitro attestation or mock
    pub is_mock: bool,
    /// The attestation data (CBOR encoded NSM doc in real mode)
    pub document: Vec<u8>,
    /// PCR values (Platform Configuration Registers)
    pub pcrs: Option<Vec<String>>,
    /// User data included in attestation
    pub user_data: Vec<u8>,
}

/// Serialize a G1 point to bytes
pub fn serialize_g1(point: &G1Projective) -> Result<Vec<u8>, OprfError> {
    let affine = point.into_affine();
    let mut bytes = Vec::new();
    affine
        .serialize_compressed(&mut bytes)
        .map_err(|e| OprfError::Serialization(e.to_string()))?;
    Ok(bytes)
}

/// Deserialize bytes to a G1 point
pub fn deserialize_g1(bytes: &[u8]) -> Result<G1Projective, OprfError> {
    let affine = G1Affine::deserialize_compressed(bytes)
        .map_err(|e| OprfError::Deserialization(e.to_string()))?;
    Ok(affine. into_group())
}

/// Serialize a scalar field element to bytes
pub fn serialize_fr(scalar: &Fr) -> Result<Vec<u8>, OprfError> {
    let mut bytes = Vec::new();
    scalar
        .serialize_compressed(&mut bytes)
        .map_err(|e| OprfError::Serialization(e.to_string()))?;
    Ok(bytes)
}

/// Deserialize bytes to a scalar field element
pub fn deserialize_fr(bytes: &[u8]) -> Result<Fr, OprfError> {
    Fr::deserialize_compressed(bytes). map_err(|e| OprfError::Deserialization(e.to_string()))
}

/// Compute SHA256 hash and return hex string
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Get the generator of G1
pub fn g1_generator() -> G1Projective {
    G1Projective::generator()
}

/// Sample a random scalar field element
pub fn random_scalar<R: Rng>(rng: &mut R) -> Fr {
    Fr::rand(rng)
}

/// Compute g^scalar
pub fn scalar_mul_generator(scalar: &Fr) -> G1Projective {
    g1_generator() * scalar
}

/// Compute point^scalar
pub fn scalar_mul(point: &G1Projective, scalar: &Fr) -> G1Projective {
    *point * scalar
}

/// Compute the multiplicative inverse of a scalar
pub fn scalar_inverse(scalar: &Fr) -> Option<Fr> {
    scalar.inverse()
}

/// Hash arbitrary data to a scalar field element
pub fn hash_to_scalar(data: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    Fr::from_be_bytes_mod_order(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_serialize_deserialize_g1() {
        let mut rng = test_rng();
        let scalar = random_scalar(&mut rng);
        let point = scalar_mul_generator(&scalar);
        
        let bytes = serialize_g1(&point). unwrap();
        let recovered = deserialize_g1(&bytes).unwrap();
        
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_serialize_deserialize_fr() {
        let mut rng = test_rng();
        let scalar = random_scalar(&mut rng);
        
        let bytes = serialize_fr(&scalar).unwrap();
        let recovered = deserialize_fr(&bytes).unwrap();
        
        assert_eq!(scalar, recovered);
    }

    #[test]
    fn test_oprf_correctness() {
        let mut rng = test_rng();
        
        // Enclave secret key
        let k = random_scalar(&mut rng);
        let pk = scalar_mul_generator(&k); // g^k
        
        // Parent input and blinding
        let m = random_scalar(&mut rng);
        let b = random_scalar(&mut rng);
        
        // Blinded query: g^(m*b)
        let blinded_query = scalar_mul_generator(&(m * b));
        
        // Enclave evaluation: (g^(m*b))^k = g^(m*b*k)
        let evaluated = scalar_mul(&blinded_query, &k);
        
        // Parent unblinds: g^(m*b*k) * (1/b) = g^(m*k)
        let b_inv = scalar_inverse(&b).unwrap();
        let unblinded = scalar_mul(&evaluated, &b_inv);
        
        // Expected: g^(m*k)
        let expected = scalar_mul_generator(&(m * k));
        
        assert_eq!(unblinded, expected);
    }
}