# Abir-Guard Threat Model

**Version:** 1.0.0  
**Date:** 2026-05-03  
**Author:** Abir Maheshwari  
**Classification:** Public

---

## 1. System Overview

Abir-Guard is a quantum-resistant encryption vault for AI agent memory. It provides post-quantum cryptography (PQC) at the application layer to protect sensitive agent data — API keys, credentials, banking data, and proprietary IP — from Harvest Now, Decrypt Later (HNDL) attacks.

### 1.1 Components

| Component | Trust Level | Location |
|-----------|-------------|----------|
| Local OS Kernel | Trusted | Host machine |
| Abir-Guard Vault | Trusted | User-space application |
| AI Agent (LangChain/CrewAI) | Partially Trusted | User-space |
| LLM Provider (OpenAI/Anthropic) | **Untrusted** | External API |
| Network (MCP transport) | **Untrusted** | Local/External |
| Filesystem (encrypted data) | **Untrusted** | Disk storage |

---

## 2. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE (Local OS)                   │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  OS Kernel   │────│ Abir-Guard   │────│ AI Agent      │  │
│  │  (RAM, RNG)  │    │   Vault      │    │ (LangChain)   │  │
│  └──────────────┘    └──────────────┘    └───────────────┘  │
│         │                    │                    │          │
│         │              ┌─────┴──────┐             │          │
│         │              │ Encryption │             │          │
│         │              │ Engine     │             │          │
│         │              └────────────┘             │          │
└─────────┼──────────────────┼──────────────────────┼──────────┘
          │                  │                      │
          ▼                  ▼                      ▼
    ┌──────────┐    ┌──────────────────┐    ┌──────────────┐
    │ Hardware │    │  Disk Storage    │    │ LLM Provider │
    │ (TPM)    │    │  (ciphertext)    │    │ (UNTRUSTED)  │
    └──────────┘    └──────────────────┘    └──────────────┘
```

### 2.1 Trusted Components

- **Local OS Kernel:** Provides entropy (via `/dev/urandom`), process isolation, and memory protection.
- **Abir-Guard Vault:** The sole component that handles plaintext keys and performs cryptographic operations.

### 2.2 Untrusted Components

- **LLM Provider:** Treated as adversarial. No plaintext secrets are ever transmitted. Only encrypted ciphertext or references are passed.
- **Network:** MCP transport (stdio or HTTP) is considered observable. All secrets are encrypted before transmission.
- **Filesystem:** Encrypted data at rest is assumed to be accessible to attackers. Without the vault's in-memory keys, ciphertext is computationally infeasible to decrypt.

---

## 3. Threat Actors

| Actor | Capability | Goal | Mitigation |
|-------|-----------|------|------------|
| **Passive Eavesdropper** | Monitor network/disk logs | Harvest encrypted agent logs for future decryption | ML-KEM-1024 (quantum-resistant) |
| **Active MITM** | Intercept/modify MCP traffic | Inject malicious commands or replace ciphertext | AES-256-GCM authenticated encryption |
| **Compromised LLM** | Access agent conversation history | Extract API keys from plaintext memory | Zero-token exposure design |
| **Side-Channel Attacker** | Measure timing/power consumption | Derive private keys from encryption latency | 200ms Security Watchdog |
| **Insider Threat** | Access to development environment | Introduce backdoors or weaken cryptography | Code review, GPG-signed commits |
| **Rootkit/Malware** | Full OS-level compromise | Extract keys from RAM | **Not mitigated** (see assumptions) |

---

## 4. Security Assumptions

### 4.1 In-Scope Assumptions

1. **Local RAM is clean:** The user's machine is not already compromised by a kernel-level rootkit that can read arbitrary memory pages.
2. **Entropy sources are honest:** OS-level random number generators (`/dev/urandom`, `CryptGenRandom`) are not backdoored.
3. **Correct implementation:** Cryptographic primitives (AES-GCM, SHA-256, X25519) are correctly implemented by the underlying libraries (`cryptography`, `ring`).
4. **User controls the vault:** The vault process runs with appropriate user-level permissions and is not accessible by other users on a multi-tenant system.

### 4.2 Out-of-Scope (Not Protected)

1. **Physical access attacks:** An attacker with physical access to running hardware may extract keys via cold-boot attacks or DMA.
2. **Compromised OS:** A kernel rootkit or hypervisor-level malware can read any user-space memory.
3. **Social engineering:** Phishing, keyloggers, or credential theft outside the vault's scope.
4. **Supply chain attacks:** Compromised upstream dependencies (mitigated by Dependabot and lock files).

---

## 5. Cryptographic Design

### 5.1 Hybrid KEM Architecture

```
┌──────────────────────────────────────────────────────┐
│              Hybrid Key Encapsulation                 │
│                                                      │
│  ML-KEM-1024 (NIST FIPS 203)  +  X25519 (Classical) │
│                                                      │
│  Security: Both must be broken to compromise          │
│  - If ML-KEM weakened → X25519 holds                │
│  - If X25519 broken (quantum) → ML-KEM holds        │
└──────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────┐
│              Key Derivation (HKDF-SHA256)            │
│                                                      │
│  Input: Combined shared secret + domain separator   │
│  Output: 256-bit AES key                            │
└──────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────┐
│              Envelope Encryption                     │
│                                                      │
│  Algorithm: AES-256-GCM (NIST FIPS 197)             │
│  Nonce: 96-bit random (per-message unique)          │
│  Auth Tag: 128-bit (integrity + authenticity)       │
└──────────────────────────────────────────────────────┘
```

### 5.2 Zero-Copy Memory Policy

**Core Philosophy:** *Never store the raw key and the plaintext data in the same memory page.*

| Operation | Memory Behavior |
|-----------|----------------|
| Key Generation | Keys generated in isolated heap allocation |
| Encryption | Plaintext → ciphertext in-place where possible; key zeroized after use |
| Decryption | Ciphertext → plaintext in isolated buffer; key zeroized after use |
| Key Rotation | Old keys wiped from memory before new keys generated |
| Cache | Encrypted data only; never plaintext in cache |

### 5.3 Memory Zeroization

All sensitive material (AES keys, shared secrets, KEM secrets) is explicitly zeroized after use using:
- **Python:** `cryptography` library handles internal zeroization; we minimize key lifetime
- **Rust:** `zeroize` crate with `Zeroize` and `ZeroizeOnDrop` traits

---

## 6. Security Watchdog

### 6.1 200ms Latency Threshold

The Python ML-KEM implementation includes a **Security Watchdog** that monitors handshake latency:

```python
if elapsed > HANDSHAKE_TIMEOUT:  # 200ms
    raise SecurityException("Latency anomaly detected")
```

**Purpose:** Detect side-channel timing attacks where an adversary intentionally slows CPU execution to measure power consumption or cache behavior, potentially leaking private key bits.

**Threshold Rationale:** On an i9-class processor, ML-KEM encapsulation should complete in <50ms. A 200ms threshold provides 4x margin for system load while still catching deliberate slowdowns.

**Limitations:** 
- Does not protect against passive timing analysis on the same execution
- Threshold may trigger false positives on heavily loaded systems
- Rust implementation does not yet include watchdog (planned v1.1.0)

---

## 7. MCP Security Model

### 7.1 Transport Security

| Transport | Encryption | Threat Model |
|-----------|-----------|--------------|
| stdio | Process isolation | Same-machine only; OS enforces boundaries |
| HTTP (local) | None (plaintext) | Loopback only; network sniffer can observe |
| HTTP (remote) | **Not supported** | Would require TLS |

### 7.2 Data Flow

```
Agent Request → [Plaintext data] → Abir-Guard → [Encrypt locally] → [Ciphertext only] → Agent Memory
                                                                                              │
                                                                                              ▼
                                                                                         LLM Provider
                                                                                      (Never sees plaintext)
```

**Critical Property:** The LLM provider never receives plaintext secrets. Only encrypted ciphertext or key references traverse the network.

---

## 8. Dependency Security

| Layer | Dependency | Update Mechanism | Risk if Outdated |
|-------|-----------|------------------|------------------|
| Python | `cryptography` | Dependabot | CVE in AES/SHA implementations |
| Rust | `aes-gcm`, `sha3`, `hkdf` | `cargo update` | Cryptographic vulnerabilities |
| Rust | `zeroize` | `cargo update` | Sensitive data not properly wiped |
| Build | Rust toolchain | rustup | Compiler-level vulnerabilities |

### 8.1 Supply Chain Protections

- **`Cargo.lock`** pinned for reproducible Rust builds
- **Dependabot** configured for automated dependency updates
- **Secret scanning** enabled to prevent credential leakage
- **GPG-signed commits** verify author authenticity

---

## 9. Known Limitations

| Limitation | Impact | Planned Fix |
|-----------|--------|-------------|
| ML-KEM-1024 uses X25519 fallback (liboqs not installed) | Not quantum-resistant until liboqs deployed | v1.1.0 with liboqs integration |
| No Rust-side watchdog | Side-channel timing attacks possible in Rust | v1.1.0 |
| No hardware TPM seal/unseal | Keys not hardware-bound | v1.1.0 |
| No SHAMIR secret sharing | Single point of failure for key material | v1.2.0 |
| HSM file backend uses XOR (not real encryption) | Weak protection for stored keys | v1.1.0 with proper key wrapping |

---

## 10. Audit Trail

| Date | Change | Author |
|------|--------|--------|
| 2026-05-03 | Initial threat model | Abir Maheshwari |
| | | |

---

**This document should be reviewed and updated whenever the architecture, dependencies, or threat landscape changes.**
