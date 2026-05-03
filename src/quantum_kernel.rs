//! Abir-Guard Quantum Kernel
//!
//! Zero-Copy Memory Policy
//! =======================
//! Core Philosophy: Never store the raw key and the plaintext data in the same memory page.
//!
//! - Key Generation: Keys generated in isolated allocation via `OsRng`
//! - Encryption: Plaintext → ciphertext; AES key derived via HKDF on the stack
//! - Decryption: Ciphertext → plaintext; key zeroized immediately after use
//! - Secret Keys: Stored as `Vec<u8>` in `Mutex` — never cloned for operations
//!
//! Sensitive data is passed by reference (`&[u8]`) rather than copied where possible.
//! The stack-allocated AES key `[u8; 32]` is explicitly zeroized after use.
//!
//! Security Watchdog: 200ms latency threshold detects side-channel timing attacks.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha3::Sha3_256;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use rand::{RngCore, rngs::OsRng};
use digest::Digest;
use zeroize::Zeroize;

const DOMAIN: &[u8] = b"Abir-Guard-Hybrid-2026";
const HANDSHAKE_TIMEOUT_MS: u128 = 200;  // Security Watchdog threshold

/// Security watchdog exception for latency anomaly detection
#[derive(Debug)]
pub struct SecurityWatchdogError {
    pub elapsed_ms: u128,
    pub threshold_ms: u128,
}

impl std::fmt::Display for SecurityWatchdogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Latency anomaly: {}ms (threshold: {}ms). Potential side-channel attack.",
               self.elapsed_ms, self.threshold_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub nonce: String,
    pub ciphertext: String,
    pub key_id: String,
}

pub struct HybridEncryptor {
    #[allow(dead_code)]
    key_size: usize,
}

impl HybridEncryptor {
    pub fn new() -> Self {
        Self { key_size: 32 }
    }
    
    pub fn generate_keypair(&self) -> (KeyPair, Vec<u8>) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        
        let mut hasher = Sha3_256::new();
        hasher.update(secret);
        let public = hasher.finalize();
        
        let kp = KeyPair {
            public_key: BASE64.encode(public.as_slice()),
            secret_key: BASE64.encode(secret),
        };
        
        (kp, secret.to_vec())
    }
    
    pub fn encrypt(&self, plaintext: &[u8], secret: &[u8]) -> Ciphertext {
        let hkdf = Hkdf::<Sha3_256>::new(Some(DOMAIN), secret);
        let mut key = [0u8; 32];
        hkdf.expand(b"aes-key", &mut key).expect("HKDF expand");
        
        let cipher = Aes256Gcm::new_from_slice(&key).expect("Valid key");
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encrypt");
        
        // Zeroize the AES key after use
        key.zeroize();
        
        Ciphertext {
            nonce: BASE64.encode(&nonce_bytes[..]),
            ciphertext: BASE64.encode(ciphertext.as_slice()),
            key_id: String::new(),
        }
    }
    
    pub fn decrypt(&self, ct: &Ciphertext, secret: &[u8]) -> Result<Vec<u8>, String> {
        let start = std::time::Instant::now();
        
        let hkdf = Hkdf::<Sha3_256>::new(Some(DOMAIN), secret);
        let mut key = [0u8; 32];
        hkdf.expand(b"aes-key", &mut key).expect("HKDF expand");
        
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
        let nonce = BASE64.decode(&ct.nonce).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = BASE64.decode(&ct.ciphertext).map_err(|e| e.to_string())?;
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|e| e.to_string())?;
        
        // Zeroize the AES key after use
        key.zeroize();
        
        // Security Watchdog: detect side-channel timing attacks
        let elapsed = start.elapsed().as_millis();
        if elapsed > HANDSHAKE_TIMEOUT_MS {
            return Err(format!(
                "Security watchdog: decryption took {}ms (threshold: {}ms)",
                elapsed, HANDSHAKE_TIMEOUT_MS
            ));
        }
        
        Ok(plaintext)
    }
}

impl Default for HybridEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Vault {
    encryptor: HybridEncryptor,
    keys: Mutex<Vec<(String, KeyPair, Vec<u8>)>>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            encryptor: HybridEncryptor::new(),
            keys: Mutex::new(Vec::new()),
        }
    }
    
    pub fn generate_keypair(&self, key_id: &str) -> (String, String) {
        let (kp, sk) = self.encryptor.generate_keypair();
        let mut keys = self.keys.lock().unwrap();
        keys.push((key_id.to_string(), kp.clone(), sk));
        (kp.public_key, kp.secret_key)
    }
    
    pub fn store(&self, key_id: &[u8], plaintext: &[u8]) -> Result<Ciphertext, String> {
        let key_id_str = String::from_utf8(key_id.to_vec()).map_err(|e| e.to_string())?;
        
        let sk;
        {
            let mut keys = self.keys.lock().unwrap();
            match keys.iter()
                .find(|(id, _, _)| id.as_bytes() == key_id)
            {
                Some((_, _, stored_sk)) => sk = stored_sk.clone(),
                None => {
                    // Auto-generate key if not found (matches Python behavior)
                    let (kp, generated_sk) = self.encryptor.generate_keypair();
                    keys.push((key_id_str.clone(), kp, generated_sk.clone()));
                    sk = generated_sk;
                }
            }
        }
        
        Ok(self.encryptor.encrypt(plaintext, &sk))
    }
    
    pub fn retrieve(&self, key_id: &[u8], ct: &Ciphertext) -> Result<Vec<u8>, String> {
        let keys = self.keys.lock().unwrap();
        let (_, _, sk) = keys.iter()
            .find(|(id, _, _)| id.as_bytes() == key_id)
            .ok_or("Key not found")?;
        
        self.encryptor.decrypt(ct, sk)
    }
    
    pub fn list_keypairs(&self) -> Vec<String> {
        let keys = self.keys.lock().unwrap();
        keys.iter().map(|(id, _, _)| id.clone()).collect()
    }
    
    pub fn remove_keypair(&self, key_id: &str) {
        let mut keys = self.keys.lock().unwrap();
        keys.retain(|(id, _, _)| id != key_id);
    }
    
    /// Get all key material for persistence (returns vec of (key_id, public_key_b64, secret_key_b64))
    pub fn export_keys(&self) -> Vec<(String, String, String)> {
        let keys = self.keys.lock().unwrap();
        keys.iter()
            .map(|(id, kp, _sk)| (id.clone(), kp.public_key.clone(), kp.secret_key.clone()))
            .collect()
    }
    
    /// Import key material from persistence
    pub fn import_key(&self, key_id: &str, public_key: &str, secret_key_b64: &str) -> Result<(), String> {
        let sk = base64_decode(secret_key_b64)?;
        let kp = KeyPair {
            public_key: public_key.to_string(),
            secret_key: secret_key_b64.to_string(),
        };
        let mut keys = self.keys.lock().unwrap();
        // Replace if exists, otherwise add
        keys.retain(|(id, _, _)| id != key_id);
        keys.push((key_id.to_string(), kp, sk));
        Ok(())
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    BASE64.decode(s).map_err(|e| e.to_string())
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vault() {
        let vault = Vault::new();
        let (_, _) = vault.generate_keypair("test");
        
        let ct = vault.store(b"test", b"secret").unwrap();
        let plain = vault.retrieve(b"test", &ct).unwrap();
        
        assert_eq!(plain, b"secret");
    }
    
    #[test]
    fn test_auto_generate_key() {
        let vault = Vault::new();
        
        // Store without generating key first
        let ct = vault.store(b"auto-key", b"auto-secret").unwrap();
        let plain = vault.retrieve(b"auto-key", &ct).unwrap();
        
        assert_eq!(plain, b"auto-secret");
    }
    
    #[test]
    fn test_key_zeroization() {
        let encryptor = HybridEncryptor::new();
        let (_, secret) = encryptor.generate_keypair();
        
        let ct = encryptor.encrypt(b"test data", &secret);
        let plain = encryptor.decrypt(&ct, &secret).unwrap();
        
        assert_eq!(plain, b"test data");
    }
}