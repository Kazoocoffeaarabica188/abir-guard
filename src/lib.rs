//! Abir-Guard: Quantum-Resilient Agentic Vault
//!
//! A lightweight, quantum-resistant vault for AI Agent memory.
//! Uses ML-KEM-1024 (Post-Quantum Cryptography) to encrypt sensitive agent data.
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
//! - `quantum_kernel` — Hybrid KEM encryption (X25519 + AES-256-GCM)
//! - `entropy_inject` — CPU jitter-based entropy collection
//! - `zero_copy` — Zero-copy vault with LRU-encrypted cache
//! - `mcp_gateway` — MCP JSON-RPC server for AI agent tools

pub mod quantum_kernel;
pub mod entropy_inject;
pub mod zero_copy;
pub mod mcp_gateway;
pub mod persistent_vault;

pub use quantum_kernel::{HybridEncryptor, KeyPair, Ciphertext, Vault};
pub use entropy_inject::EntropyCollector;
pub use zero_copy::ZeroCopyVault;
pub use mcp_gateway::{McpServer, McpRequest, McpResponse};

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