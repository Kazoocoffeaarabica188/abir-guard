//! Abir-Guard Persistent Vault (Rust)
//!
//! Encrypted file-based key storage for CLI persistence.
//! Keys are encrypted with AES-256-GCM and stored in `~/.abir_guard/keys.enc`.
//! ML-DSA signing keys stored in `~/.abir_guard/mldsa_keys.enc`.
//!
//! Security:
//! - Master key derived from passphrase via Argon2id (OWASP recommended)
//! - AES-256-GCM encryption per-save
//! - Salt stored alongside encrypted blob
//! - File not created until first save

use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

use crate::quantum_kernel::{Ciphertext, Vault};
use crate::ml_dsa::MldsaKeypair;
use crate::kdf;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

const VAULT_DIR: &str = ".abir_guard";
const KEYS_FILE: &str = "keys.enc";
const MLDSA_KEYS_FILE: &str = "mldsa_keys.enc";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    key_id: String,
    public_key: String,
    secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMldsaKey {
    key_id: String,
    signing_key_b64: String,
    verifying_key_b64: String,
}

/// Encrypt data with AES-256-GCM
fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Valid key");
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).expect("Failed to get random nonce");
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ct = cipher.encrypt(nonce, data).expect("Encryption failed");
    
    // Output: nonce(12) + ciphertext
    let mut result = Vec::with_capacity(12 + ct.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ct);
    result
}

/// Decrypt data with AES-256-GCM
fn decrypt_data(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if blob.len() < 12 + 16 {
        return Err("Encrypted blob too short".to_string());
    }
    
    let nonce_bytes = &blob[..12];
    let ct = &blob[12..];
    
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);
    
    cipher.decrypt(nonce, ct).map_err(|e| format!("Decryption failed: {}", e))
}

/// Get or create a Vault with persisted keys loaded
pub fn get_vault(passphrase: &str) -> Vault {
    let vault = Vault::new();
    
    let keys_path = get_keys_path();
    if !keys_path.exists() {
        return vault;
    }
    
    let blob = match fs::read(&keys_path) {
        Ok(d) => d,
        Err(_) => return vault,
    };
    
    // Format: salt(16) + nonce(12) + ciphertext + GCM_tag(16)
    if blob.len() < kdf::SALT_LENGTH + 12 + 16 {
        return vault;
    }
    
    let salt = &blob[..kdf::SALT_LENGTH];
    let encrypted_blob = &blob[kdf::SALT_LENGTH..];
    
    let key = kdf::derive_key_with_salt(passphrase, salt);
    
    let data = match decrypt_data(encrypted_blob, &key) {
        Ok(d) => d,
        Err(_) => return vault,
    };
    
    let stored: Vec<StoredKey> = match serde_json::from_slice(&data) {
        Ok(s) => s,
        Err(_) => return vault,
    };
    
    for key in stored {
        vault.import_key(&key.key_id, &key.public_key, &key.secret_key).ok();
    }
    
    vault
}

/// Persist all keys from vault to disk (encrypted with Argon2id-derived key)
pub fn persist(vault: &Vault, passphrase: &str) {
    let keys_path = get_keys_path();
    
    if let Some(parent) = keys_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    
    let exported = vault.export_keys();
    let stored_keys: Vec<StoredKey> = exported
        .into_iter()
        .map(|(key_id, public_key, secret_key)| StoredKey {
            key_id,
            public_key,
            secret_key,
        })
        .collect();
    
    if let Ok(data) = serde_json::to_vec(&stored_keys) {
        let (key, salt) = kdf::derive_key(passphrase, None);
        let encrypted = encrypt_data(&data, &key);
        
        // Write: salt + encrypted_blob
        let mut blob = Vec::with_capacity(kdf::SALT_LENGTH + encrypted.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&encrypted);
        
        fs::write(&keys_path, blob).ok();
    }
}

fn get_keys_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(VAULT_DIR).join(KEYS_FILE)
}

fn get_mldsa_keys_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(VAULT_DIR).join(MLDSA_KEYS_FILE)
}

/// Encrypt data and persist the vault (saves new auto-generated keys)
pub fn store_encrypted(vault: &Vault, key_id: &str, plaintext: &[u8], passphrase: &str) -> Result<Ciphertext, String> {
    let ct = vault.store(key_id.as_bytes(), plaintext)?;
    persist(vault, passphrase);
    Ok(ct)
}

/// Decrypt data (ensures keys are loaded)
pub fn retrieve_decrypted(vault: &Vault, key_id: &str, ct: &Ciphertext, passphrase: &str) -> Result<Vec<u8>, String> {
    load_additional_keys(vault, passphrase);
    vault.retrieve(key_id.as_bytes(), ct)
}

fn load_additional_keys(vault: &Vault, passphrase: &str) {
    let keys_path = get_keys_path();
    if !keys_path.exists() {
        return;
    }
    
    let blob = match fs::read(&keys_path) {
        Ok(d) => d,
        Err(_) => return,
    };
    
    if blob.len() < kdf::SALT_LENGTH + 12 + 16 {
        return;
    }
    
    let salt = &blob[..kdf::SALT_LENGTH];
    let encrypted_blob = &blob[kdf::SALT_LENGTH..];
    
    let key = kdf::derive_key_with_salt(passphrase, salt);
    
    let data = match decrypt_data(encrypted_blob, &key) {
        Ok(d) => d,
        Err(_) => return,
    };
    
    let stored: Vec<StoredKey> = match serde_json::from_slice(&data) {
        Ok(s) => s,
        Err(_) => return,
    };
    
    let existing = vault.list_keypairs();
    for key in stored {
        if !existing.contains(&key.key_id) {
            vault.import_key(&key.key_id, &key.public_key, &key.secret_key).ok();
        }
    }
}

/// Persist ML-DSA keypairs to disk (encrypted with Argon2id-derived key)
pub fn persist_mldsa_keys(keypairs: &[(String, MldsaKeypair)], passphrase: &str) -> Result<(), String> {
    let keys_path = get_mldsa_keys_path();
    
    if let Some(parent) = keys_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    
    let stored: Vec<StoredMldsaKey> = keypairs
        .iter()
        .map(|(key_id, kp)| StoredMldsaKey {
            key_id: key_id.clone(),
            signing_key_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &kp.signing_key,
            ),
            verifying_key_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &kp.verifying_key,
            ),
        })
        .collect();
    
    let data = serde_json::to_vec(&stored).map_err(|e| e.to_string())?;
    let (key, salt) = kdf::derive_key(passphrase, None);
    let encrypted = encrypt_data(&data, &key);
    
    let mut blob = Vec::with_capacity(kdf::SALT_LENGTH + encrypted.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&encrypted);
    
    fs::write(&keys_path, blob).map_err(|e| e.to_string())?;
    Ok(())
}

/// Load ML-DSA keypairs from disk
pub fn load_mldsa_keys(passphrase: &str) -> Result<Vec<(String, MldsaKeypair)>, String> {
    let keys_path = get_mldsa_keys_path();
    if !keys_path.exists() {
        return Err("ML-DSA keys file not found".to_string());
    }
    
    let blob = fs::read(&keys_path).map_err(|e| e.to_string())?;
    
    if blob.len() < kdf::SALT_LENGTH + 12 + 16 {
        return Err("Encrypted blob too short".to_string());
    }
    
    let salt = &blob[..kdf::SALT_LENGTH];
    let encrypted_blob = &blob[kdf::SALT_LENGTH..];
    
    let key = kdf::derive_key_with_salt(passphrase, salt);
    let data = decrypt_data(encrypted_blob, &key)?;
    
    let stored: Vec<StoredMldsaKey> = serde_json::from_slice(&data)
        .map_err(|e| format!("Failed to deserialize: {}", e))?;
    
    let keypairs: Result<Vec<_>, _> = stored
        .into_iter()
        .map(|sk| {
            let signing_key = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &sk.signing_key_b64,
            )
            .map_err(|e| e.to_string())?;
            let verifying_key = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &sk.verifying_key_b64,
            )
            .map_err(|e| e.to_string())?;
            Ok((sk.key_id, MldsaKeypair {
                signing_key,
                verifying_key,
            }))
        })
        .collect();
    
    keypairs
}

/// Sign data with ML-DSA using vault-stored keys
pub fn sign_with_vault(key_id: &str, data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let keypairs = load_mldsa_keys(passphrase)?;
    let (_, kp) = keypairs
        .iter()
        .find(|(id, _)| id == key_id)
        .ok_or_else(|| format!("ML-DSA key '{}' not found", key_id))?;
    
    crate::ml_dsa::sign(data, &kp.signing_key)
        .map_err(|e| format!("Signing failed: {}", e))
}

/// Verify data with ML-DSA using vault-stored keys
pub fn verify_with_vault(key_id: &str, data: &[u8], signature: &[u8], passphrase: &str) -> Result<bool, String> {
    let keypairs = load_mldsa_keys(passphrase)?;
    let (_, kp) = keypairs
        .iter()
        .find(|(id, _)| id == key_id)
        .ok_or_else(|| format!("ML-DSA key '{}' not found", key_id))?;
    
    crate::ml_dsa::verify(data, signature, &kp.verifying_key)
        .map_err(|e| format!("Verification failed: {}", e))
}

/// List stored ML-DSA key IDs
pub fn list_mldsa_keys(passphrase: &str) -> Result<Vec<String>, String> {
    let keypairs = load_mldsa_keys(passphrase)?;
    Ok(keypairs.into_iter().map(|(id, _)| id).collect())
}
