//! Abir-Guard: Automatic Key Rotation
//!
//! Manages key rotation policies and tracks key lifecycle.
//! Keys are flagged for rotation when age or usage exceeds thresholds.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Metadata for a key tracked by the rotation manager
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_id: String,
    pub created_at: u64,
    pub last_used_at: u64,
    pub encrypt_count: u64,
    pub decrypt_count: u64,
    pub max_lifetime_seconds: u64,
    pub max_operations: u64,
    pub is_expired: bool,
    pub rotated_to: String,
}

impl KeyMetadata {
    pub fn total_operations(&self) -> u64 {
        self.encrypt_count + self.decrypt_count
    }

    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.created_at)
    }

    pub fn should_expire(&self) -> bool {
        if self.max_lifetime_seconds > 0 && self.age_seconds() > self.max_lifetime_seconds {
            return true;
        }
        if self.max_operations > 0 && self.total_operations() >= self.max_operations {
            return true;
        }
        false
    }

    pub fn record_encrypt(&mut self) {
        self.encrypt_count += 1;
        self.last_used_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    pub fn record_decrypt(&mut self) {
        self.decrypt_count += 1;
        self.last_used_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

/// Manages key rotation policies
pub struct KeyRotationManager {
    metadata: HashMap<String, KeyMetadata>,
    default_max_lifetime: u64,
    default_max_operations: u64,
}

impl KeyRotationManager {
    pub fn new(default_max_lifetime: u64, default_max_operations: u64) -> Self {
        Self {
            metadata: HashMap::new(),
            default_max_lifetime,
            default_max_operations,
        }
    }

    pub fn register_key(
        &mut self,
        key_id: &str,
        max_lifetime: Option<u64>,
        max_operations: Option<u64>,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.metadata.insert(
            key_id.to_string(),
            KeyMetadata {
                key_id: key_id.to_string(),
                created_at: now,
                last_used_at: now,
                encrypt_count: 0,
                decrypt_count: 0,
                max_lifetime_seconds: max_lifetime.unwrap_or(self.default_max_lifetime),
                max_operations: max_operations.unwrap_or(self.default_max_operations),
                is_expired: false,
                rotated_to: String::new(),
            },
        );
    }

    pub fn record_usage(&mut self, key_id: &str, is_encrypt: bool) {
        if let Some(meta) = self.metadata.get_mut(key_id) {
            if is_encrypt {
                meta.record_encrypt();
            } else {
                meta.record_decrypt();
            }
        }
    }

    pub fn needs_rotation(&self, key_id: &str) -> bool {
        self.metadata
            .get(key_id)
            .map(|m| m.should_expire())
            .unwrap_or(false)
    }

    pub fn expire_key(&mut self, key_id: &str, rotated_to: &str) {
        if let Some(meta) = self.metadata.get_mut(key_id) {
            meta.is_expired = true;
            meta.rotated_to = rotated_to.to_string();
        }
    }

    pub fn get_metadata(&self, key_id: &str) -> Option<&KeyMetadata> {
        self.metadata.get(key_id)
    }

    pub fn key_count(&self) -> usize {
        self.metadata.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usage_based_rotation() {
        let mut manager = KeyRotationManager::new(0, 5);
        manager.register_key("test-key", None, Some(5));

        for _ in 0..5 {
            manager.record_usage("test-key", true);
        }

        assert!(manager.needs_rotation("test-key"));
    }

    #[test]
    fn test_no_rotation_under_limit() {
        let mut manager = KeyRotationManager::new(0, 10);
        manager.register_key("test-key", None, Some(10));

        for _ in 0..3 {
            manager.record_usage("test-key", true);
        }

        assert!(!manager.needs_rotation("test-key"));
    }
}
