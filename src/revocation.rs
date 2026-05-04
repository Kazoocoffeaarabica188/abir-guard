//! Abir-Guard: Key Revocation / Blacklist (CRL-style mechanism)
//!
//! Implements a Certificate Revocation List for agent keys.
//! Allows marking keys as compromised/revoked, preventing their use.

use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Revocation reason
#[derive(Debug, Clone)]
pub enum RevocationReason {
    Compromised,
    Rotated,
    Retired,
    Policy,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compromised => write!(f, "compromised"),
            Self::Rotated => write!(f, "rotated"),
            Self::Retired => write!(f, "retired"),
            Self::Policy => write!(f, "policy"),
        }
    }
}

/// A single revocation entry
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    pub key_id: String,
    pub reason: String,
    pub timestamp: u64,
    pub revoked_by: String,
    pub details: String,
}

/// Tamper-evident Certificate Revocation List
pub struct RevocationList {
    revocation_key: Vec<u8>,
    entries: Vec<RevocationEntry>,
    revoked_ids: HashMap<String, usize>,
    signature: Vec<u8>,
}

impl RevocationList {
    /// Create a new revocation list with a random key
    pub fn new() -> Self {
        let mut key = vec![0u8; 32];
        getrandom::fill(&mut key).expect("Failed to get random key");
        Self {
            revocation_key: key,
            entries: Vec::new(),
            revoked_ids: HashMap::new(),
            signature: Vec::new(),
        }
    }

    /// Create from a specific revocation key
    pub fn with_key(key: Vec<u8>) -> Self {
        Self {
            revocation_key: key,
            entries: Vec::new(),
            revoked_ids: HashMap::new(),
            signature: Vec::new(),
        }
    }

    fn compute_signature(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(&self.revocation_key);
        for entry in &self.entries {
            h.update(entry.key_id.as_bytes());
            h.update(entry.reason.as_bytes());
            h.update(entry.timestamp.to_le_bytes());
        }
        h.finalize().to_vec()
    }

    /// Revoke a key
    pub fn revoke(
        &mut self,
        key_id: &str,
        reason: RevocationReason,
        revoked_by: &str,
        details: &str,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let idx = self.entries.len();
        self.entries.push(RevocationEntry {
            key_id: key_id.to_string(),
            reason: reason.to_string(),
            timestamp,
            revoked_by: revoked_by.to_string(),
            details: details.to_string(),
        });
        self.revoked_ids.insert(key_id.to_string(), idx);
        self.signature = self.compute_signature();
    }

    /// Check if a key is revoked
    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked_ids.contains_key(key_id)
    }

    /// Get revocation entry for a key
    pub fn get_entry(&self, key_id: &str) -> Option<&RevocationEntry> {
        self.revoked_ids
            .get(key_id)
            .and_then(|&idx| self.entries.get(idx))
    }

    /// List all revoked keys
    pub fn list_revoked(&self) -> &[RevocationEntry] {
        &self.entries
    }

    /// Verify CRL integrity
    pub fn verify_integrity(&self) -> bool {
        if self.signature.is_empty() {
            return true;
        }
        self.compute_signature() == self.signature
    }

    /// Export CRL as JSON
    pub fn export_json(&self) -> String {
        let entries_json: Vec<String> = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    r#"{{"key_id":"{}","reason":"{}","timestamp":{},"revoked_by":"{}","details":"{}"}}"#,
                    e.key_id, e.reason, e.timestamp, e.revoked_by, e.details
                )
            })
            .collect();
        format!(
            r#"{{"version":1,"entries":[{}],"signature":"{}"}}"#,
            entries_json.join(","),
            hex::encode(&self.signature)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revoke_and_check() {
        let mut crl = RevocationList::new();
        assert!(!crl.is_revoked("agent-1"));

        crl.revoke("agent-1", RevocationReason::Compromised, "admin", "Key leaked");
        assert!(crl.is_revoked("agent-1"));
        assert!(!crl.is_revoked("agent-2"));
    }

    #[test]
    fn test_integrity() {
        let mut crl = RevocationList::new();
        crl.revoke("key-1", RevocationReason::Rotated, "system", "routine");
        assert!(crl.verify_integrity());
    }
}
