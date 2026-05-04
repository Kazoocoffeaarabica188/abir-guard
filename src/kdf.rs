//! Abir-Guard Key Derivation
//!
//! Argon2id key derivation (OWASP recommended parameters)
//! for deriving encryption keys from passphrases.

use argon2::{Argon2, Params, Version};

pub const ARGON2_TIME_COST: u32 = 3;
pub const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MB
pub const ARGON2_PARALLELISM: u32 = 4;
pub const ARGON2_KEY_LENGTH: usize = 32;
pub const SALT_LENGTH: usize = 16;

/// Derive a 32-byte encryption key from a passphrase using Argon2id.
/// If salt is None, a random salt is generated.
/// Returns (key, salt).
pub fn derive_key(passphrase: &str, salt: Option<&[u8]>) -> ([u8; ARGON2_KEY_LENGTH], Vec<u8>) {
    let salt_bytes: Vec<u8> = match salt {
        Some(s) => s.to_vec(),
        None => {
            let mut s = vec![0u8; SALT_LENGTH];
            getrandom::fill(&mut s).expect("Failed to get random salt");
            s
        }
    };
    
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(ARGON2_KEY_LENGTH),
    ).expect("Valid Argon2 params");
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    );
    
    let mut key = [0u8; ARGON2_KEY_LENGTH];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut key)
        .expect("Argon2id derivation failed");
    
    (key, salt_bytes)
}

/// Derive key with a known salt (for decrypting existing data)
pub fn derive_key_with_salt(passphrase: &str, salt: &[u8]) -> [u8; ARGON2_KEY_LENGTH] {
    let (key, _) = derive_key(passphrase, Some(salt));
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_argon2id_derivation() {
        let (key1, salt) = derive_key("test-passphrase", None);
        assert!(!key1.iter().all(|&b| b == 0));
        assert_eq!(salt.len(), SALT_LENGTH);
        
        // Same passphrase + same salt = same key
        let key2 = derive_key_with_salt("test-passphrase", &salt);
        assert_eq!(key1, key2);
        
        // Different passphrase = different key
        let (key3, _) = derive_key("different-passphrase", Some(&salt));
        assert_ne!(key1, key3);
        
        // Different salt = different key
        let mut different_salt = salt.clone();
        different_salt[0] ^= 0xFF;
        let key4 = derive_key_with_salt("test-passphrase", &different_salt);
        assert_ne!(key1, key4);
    }
    
    #[test]
    fn test_key_length() {
        let (key, _) = derive_key("any-pass", None);
        assert_eq!(key.len(), ARGON2_KEY_LENGTH);
    }
}
