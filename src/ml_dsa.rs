//! Abir-Guard: ML-DSA Digital Signatures (NIST FIPS 204)
//!
//! Post-quantum secure digital signatures using Module-Lattice-Based Digital
//! Signature Algorithm (ML-DSA). Provides key generation, signing, and
//! verification operations for vault data integrity.
//!
//! Uses ML-DSA-65 (security category 3) for balanced security/performance.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use sha3::{Digest, Sha3_512};
use thiserror::Error;
use std::convert::TryInto;

/// ML-DSA signature errors
#[derive(Debug, Error)]
pub enum MldsaError {
    #[error("key generation failed: {0}")]
    KeyGenFailed(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("verification failed")]
    VerificationFailed,
    #[error("key deserialization failed: {0}")]
    DeserializationFailed(String),
}

/// ML-DSA keypair container
#[derive(Debug, Clone)]
pub struct MldsaKeypair {
    pub signing_key: Vec<u8>,
    pub verifying_key: Vec<u8>,
}

/// Generate a new ML-DSA-65 keypair (security category 3).
pub fn generate_keypair() -> Result<MldsaKeypair, MldsaError> {
    let (pk, sk) = ml_dsa_65::try_keygen()
        .map_err(|e| MldsaError::KeyGenFailed(e.to_string()))?;

    Ok(MldsaKeypair {
        signing_key: sk.into_bytes().to_vec(),
        verifying_key: pk.into_bytes().to_vec(),
    })
}

/// Sign data with ML-DSA-65.
pub fn sign(data: &[u8], signing_key: &[u8]) -> Result<Vec<u8>, MldsaError> {
    let sk_bytes: [u8; 4032] = signing_key
        .try_into()
        .map_err(|_| MldsaError::DeserializationFailed("Invalid signing key length".into()))?;
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
        .map_err(|e| MldsaError::DeserializationFailed(e.to_string()))?;

    let sig = sk
        .try_sign(data, &[])
        .map_err(|e| MldsaError::SigningFailed(e.to_string()))?;

    Ok(sig.to_vec())
}

/// Verify an ML-DSA-65 signature.
pub fn verify(data: &[u8], signature: &[u8], verifying_key: &[u8]) -> Result<bool, MldsaError> {
    let pk_bytes: [u8; 1952] = verifying_key
        .try_into()
        .map_err(|_| MldsaError::DeserializationFailed("Invalid verifying key length".into()))?;
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
        .map_err(|e| MldsaError::DeserializationFailed(e.to_string()))?;

    let sig_bytes: [u8; 3309] = signature
        .try_into()
        .map_err(|_| MldsaError::DeserializationFailed("Invalid signature length".into()))?;

    let valid = pk.verify(data, &sig_bytes, &[]);
    Ok(valid)
}

/// Compute SHA3-512 hash of data for fingerprinting.
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Serialize keypair to JSON string for storage.
pub fn serialize_keypair(keypair: &MldsaKeypair) -> String {
    serde_json::json!({
        "signing_key": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &keypair.signing_key,
        ),
        "verifying_key": base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &keypair.verifying_key,
        ),
    })
    .to_string()
}

/// Deserialize keypair from JSON string.
pub fn deserialize_keypair(json: &str) -> Result<MldsaKeypair, MldsaError> {
    let parsed: serde_json::Value =
        serde_json::from_str(json).map_err(|e| MldsaError::DeserializationFailed(e.to_string()))?;

    let sk_b64 = parsed["signing_key"]
        .as_str()
        .ok_or_else(|| MldsaError::DeserializationFailed("Missing signing_key".into()))?;
    let vk_b64 = parsed["verifying_key"]
        .as_str()
        .ok_or_else(|| MldsaError::DeserializationFailed("Missing verifying_key".into()))?;

    let signing_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        sk_b64,
    )
    .map_err(|e| MldsaError::DeserializationFailed(e.to_string()))?;
    let verifying_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        vk_b64,
    )
    .map_err(|e| MldsaError::DeserializationFailed(e.to_string()))?;

    Ok(MldsaKeypair {
        signing_key,
        verifying_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().unwrap();
        assert!(!keypair.signing_key.is_empty());
        assert!(!keypair.verifying_key.is_empty());
        assert_eq!(keypair.signing_key.len(), 4032);
        assert_eq!(keypair.verifying_key.len(), 1952);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = generate_keypair().unwrap();
        let data = b"test data for ML-DSA signature";

        let signature = sign(data, &keypair.signing_key).unwrap();
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 3309);

        let valid = verify(data, &signature, &keypair.verifying_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_invalid_signature_fails() {
        let keypair = generate_keypair().unwrap();
        let data = b"test data";
        let tampered = b"tampered data";

        let signature = sign(data, &keypair.signing_key).unwrap();
        let valid = verify(tampered, &signature, &keypair.verifying_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_serialize_deserialize_keypair() {
        let keypair = generate_keypair().unwrap();
        let json = serialize_keypair(&keypair);
        let restored = deserialize_keypair(&json).unwrap();

        assert_eq!(keypair.signing_key, restored.signing_key);
        assert_eq!(keypair.verifying_key, restored.verifying_key);

        let data = b"test serialization";
        let sig = sign(data, &restored.signing_key).unwrap();
        assert!(verify(data, &sig, &restored.verifying_key).unwrap());
    }

    #[test]
    fn test_different_keypairs_cant_verify() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();

        let data = b"test cross-key verification";
        let sig = sign(data, &kp1.signing_key).unwrap();
        let valid = verify(data, &sig, &kp2.verifying_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_hash_data_consistency() {
        let data = b"test data";
        let hash1 = hash_data(data);
        let hash2 = hash_data(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }
}
