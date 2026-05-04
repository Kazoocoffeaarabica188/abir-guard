//! Abir-Guard: Quantum-Resilient Agentic Vault (v3.0.0)
//!
//! A lightweight, quantum-resistant vault for AI Agent memory.
//! Uses ML-KEM-1024 (FIPS 203), ML-DSA-65 (FIPS 204), SHAMIR, and Argon2id for post-quantum security.
//!
//! # Zero-Copy Memory Policy
//!
//! Core Philosophy: *Never store the raw key and the plaintext data in the same memory page.*
//!
//! - Sensitive data passed by reference (`&[u8]`), not cloned
//! - Stack-allocated AES keys naturally zeroized on function return
//! - Secret keys stored in `Mutex` — accessed via guard, not copied
//! - Cache stores encrypted data only, never plaintext
//!
//! # Modules
//!
//! ## Core (Phase 1)
//! - `quantum_kernel` — ML-KEM-1024 Key Encapsulation + AES-256-GCM encryption
//! - `entropy_inject` — CPU jitter-based entropy collection
//! - `zero_copy` — Zero-copy vault with LRU-encrypted cache
//! - `mcp_gateway` — MCP JSON-RPC server for AI agent tools
//!
//! ## Hardware & Security (Phase 2)
//! - `persistent_vault` — Encrypted file-based key persistence (Argon2id)
//! - `kdf` — Argon2id key derivation (OWASP recommended)
//! - `shamir` — SHAMIR Secret Sharing (t, n) threshold scheme
//! - `ml_dsa` — ML-DSA signatures (NIST FIPS 204)
//!
//! ## Ecosystem & Hardening (Phase 3)
//! - `revocation` — Key revocation/blacklist (CRL-style mechanism)
//! - `rotation` — Automatic key rotation (time/usage-based)
//! - `differential_privacy` — Differential privacy for entropy collection

pub mod quantum_kernel;
pub mod entropy_inject;
pub mod zero_copy;
pub mod mcp_gateway;
pub mod persistent_vault;
pub mod kdf;
pub mod shamir;
pub mod ml_dsa;
pub mod revocation;
pub mod rotation;
pub mod differential_privacy;

pub use quantum_kernel::{HybridEncryptor, KeyPair, Ciphertext, Vault};
pub use entropy_inject::EntropyCollector;
pub use zero_copy::ZeroCopyVault;
pub use mcp_gateway::{McpServer, McpRequest, McpResponse};
pub use kdf::{derive_key, derive_key_with_salt};
pub use shamir::{split as shamir_split, reconstruct as shamir_reconstruct, Share};
pub use ml_dsa::{MldsaKeypair, generate_keypair as mldsa_generate_keypair, sign as mldsa_sign, verify as mldsa_verify};
pub use revocation::{RevocationList, RevocationReason};
pub use rotation::{KeyRotationManager, KeyMetadata};
pub use differential_privacy::{DifferentialEntropyCollector, SpectreMeltdownDefender};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

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
}
