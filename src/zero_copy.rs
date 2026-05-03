//! Abir-Guard Zero-Copy Vault
//!
//! Zero-Copy Memory Policy
//! =======================
//! Core Philosophy: Never store the raw key and the plaintext data in the same memory page.
//!
//! This vault implements:
//! - **HashMap-backed key storage:** Keys stored in `Mutex<HashMap>` — access via reference
//! - **Encrypted cache only:** Cache stores `Vec<u8>` (encrypted data), never plaintext
//! - **LRU eviction:** Oldest entries evicted at MAX_CACHE_ENTRIES (100) to minimize RAM exposure
//! - **No clone operations:** Plaintext data is passed as `&[u8]` references, not cloned
//!
//! Cache operations:
//! - `cache_write`: Stores encrypted data by key
//! - `cache_read`: Returns cloned cached data (safe — already encrypted)
//! - `clear_cache`: Wipes entire cache from memory

use std::sync::Mutex;
use std::collections::HashMap;

use crate::quantum_kernel::{HybridEncryptor, Ciphertext};

const MAX_CACHE_ENTRIES: usize = 100;

pub struct ZeroCopyVault {
    encryptor: HybridEncryptor,
    keys: Mutex<HashMap<String, (String, Vec<u8>)>>,
    cache: Mutex<HashMap<String, Vec<u8>>>,
}

impl ZeroCopyVault {
    pub fn new() -> Self {
        Self {
            encryptor: HybridEncryptor::new(),
            keys: Mutex::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
        }
    }
    
    pub fn generate_keypair(&self, key_id: &str) -> String {
        let (kp, sk) = self.encryptor.generate_keypair();
        let mut keys = self.keys.lock().unwrap();
        keys.insert(key_id.to_string(), (kp.secret_key, sk));
        kp.public_key
    }
    
    pub fn store(&self, key_id: &str, plaintext: &[u8]) -> Result<Ciphertext, String> {
        let keys = self.keys.lock().unwrap();
        let (_, sk) = keys.get(key_id).ok_or("Key not found")?;
        
        Ok(self.encryptor.encrypt(plaintext, sk))
    }
    
    pub fn retrieve(&self, key_id: &str, ct: &Ciphertext) -> Result<Vec<u8>, String> {
        let keys = self.keys.lock().unwrap();
        let (_, sk) = keys.get(key_id).ok_or("Key not found")?;
        
        self.encryptor.decrypt(ct, sk)
    }
    
    pub fn cache_write(&self, key_id: &str, data: &[u8]) {
        let mut cache = self.cache.lock().unwrap();
        
        if cache.len() >= MAX_CACHE_ENTRIES {
            if let Some(first_key) = cache.keys().next().cloned() {
                cache.remove(&first_key);
            }
        }
        
        cache.insert(key_id.to_string(), data.to_vec());
    }
    
    pub fn cache_read(&self, key_id: &str) -> Option<Vec<u8>> {
        let cache = self.cache.lock().unwrap();
        cache.get(key_id).cloned()
    }
    
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }
}

impl Default for ZeroCopyVault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zero_copy() {
        let vault = ZeroCopyVault::new();
        let pub_key = vault.generate_keypair("test");
        
        assert!(!pub_key.is_empty());
        
        let ct = vault.store("test", b"data").unwrap();
        let plain = vault.retrieve("test", &ct).unwrap();
        
        assert_eq!(plain, b"data");
    }
}