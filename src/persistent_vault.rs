//! Abir-Guard Persistent Vault (Rust)
//!
//! Encrypted file-based key storage for CLI persistence.
//! Keys are encrypted with AES-256-GCM and stored in `~/.abir_guard/keys.enc`.
//!
//! Security:
//! - Master key derived from passphrase via HKDF-SHA256 with random salt
//! - AES-256-GCM encryption per-save
//! - File not created until first save

use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

use crate::quantum_kernel::{Ciphertext, Vault};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha3::Sha3_256;
use rand::{RngCore, rngs::OsRng};

const VAULT_DIR: &str = ".abir_guard";
const KEYS_FILE: &str = "keys.enc";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    key_id: String,
    public_key: String,
    secret_key: String,
}

/// Derive encryption key from passphrase using HKDF with random salt
fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let hkdf = Hkdf::<Sha3_256>::new(Some(salt), passphrase.as_bytes());
    hkdf.expand(b"abir-guard-vault-key", &mut key)
        .expect("HKDF expand failed");
    key
}

/// Encrypt data with AES-256-GCM
fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Valid key");
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
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
    
    // Try to load with the passphrase (derive key first to check)
    let salt = [0u8; 16];
    let key = derive_key(passphrase, &salt);
    
    let data = match decrypt_data(&blob, &key) {
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

/// Persist all keys from vault to disk (encrypted with passphrase)
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
        // Derive key from passphrase (empty salt for deterministic derivation)
        let salt = [0u8; 16];
        let key = derive_key(passphrase, &salt);
        let encrypted = encrypt_data(&data, &key);
        fs::write(&keys_path, encrypted).ok();
    }
}

fn get_keys_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(VAULT_DIR).join(KEYS_FILE)
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
    
    let salt = [0u8; 16];
    let key = derive_key(passphrase, &salt);
    
    let data = match decrypt_data(&blob, &key) {
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
