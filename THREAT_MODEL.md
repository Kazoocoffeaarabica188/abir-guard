# Abir-Guard Threat Model

**Version:** 3.0.0  
**Date:** 2026-05-04  
**Author:** Abir Maheshwari (abhirsxn@gmail.com)  
**Classification:** Public

---

## 1. System Overview

Abir-Guard is a quantum-resistant encryption vault for AI agent memory. It implements NIST-standard Post-Quantum Cryptography (PQC) to protect sensitive agent data — API keys, credentials, banking data, and proprietary IP — from Harvest Now, Decrypt Later (HNDL) attacks.

### 1.1 Components

| Component | Trust Level | Location |
|-----------|-------------|----------|
| Local OS Kernel | Trusted | Host machine |
| Abir-Guard Vault | Trusted | User-space application |
| AI Agent (LangChain/CrewAI) | Partially Trusted | User-space |
| LLM Provider (OpenAI/Anthropic) | **Untrusted** | External API |
| Network (MCP transport) | **Untrusted** | Local/External |
| Filesystem (encrypted data) | **Untrusted** | Disk storage |
| Remote Attestation Verifier | Partially Trusted | External/internal service |

### 1.2 v3.0.0 Phase 3 Additions

| Component | Trust Level | Purpose |
|-----------|-------------|---------|
| CRL (Revocation List) | Trusted | Tamper-evident key revocation via HMAC signatures |
| Key Rotation Manager | Trusted | Automated key lifecycle management |
| FIPS 140-3 Validator | Trusted | Strict algorithm enforcement gate |
| Differential Privacy Collector | Trusted | Noise-injected entropy for side-channel defense |
| Attestation Verifier | Partially Trusted | Runtime integrity verification |

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
│         │              └─────┬──────┘             │          │
│         │              ┌─────┴──────┐             │          │
│         │              │ Phase 3    │             │          │
│         │              │ Security   │             │          │
│         │              │ CRL/Attest │             │          │
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

- **Local OS Kernel:** Provides entropy (`/dev/urandom`, `CryptGenRandom`), process isolation, and memory protection.
- **Abir-Guard Vault:** The sole component that handles plaintext keys and performs cryptographic operations.
- **CRL / Key Rotation / FIPS Validator:** Internal security gates that operate on trusted key state.

### 2.2 Untrusted Components

- **LLM Provider:** Treated as adversarial. No plaintext secrets are ever transmitted.
- **Network:** MCP transport (stdio or HTTP) is considered observable. All secrets are encrypted before transmission.
- **Filesystem:** Encrypted data at rest is assumed accessible. Without the vault's in-memory keys, ciphertext is computationally infeasible to decrypt.

---

## 3. Threat Actors

| Actor | Capability | Goal | Mitigation |
|-------|-----------|------|------------|
| **Passive Eavesdropper** | Monitor network/disk logs | Harvest encrypted data for future quantum decryption | ML-KEM-1024 (quantum-resistant) |
| **Active MITM** | Intercept/modify MCP traffic | Inject commands or replace ciphertext | AES-256-GCM authenticated encryption |
| **Compromised LLM** | Access agent conversation history | Extract API keys from plaintext memory | Zero-token exposure design |
| **Side-Channel Attacker** | Measure timing/power/cache | Derive keys from encryption latency | 200ms Watchdog + Differential Privacy noise |
| **Insider Threat** | Access development environment | Introduce backdoors or weaken crypto | Code review, GPG-signed commits, audit chain |
| **Key Compromise** | Stolen or leaked key material | Decrypt historical ciphertext | CRL revocation + auto key rotation |
| **Runtime Tampering** | Modify vault binary or environment | Bypass encryption or extract keys | Remote attestation + environment sanity checks |
| **FIPS Compliance Attack** | Force non-approved algorithms | Weaken cryptographic strength | FIPS 140-3 strict mode blocks all non-NIST algorithms |
| **Rootkit/Malware** | Full OS-level compromise | Extract keys from RAM | **Not mitigated** (see assumptions) |

---

## 4. Security Assumptions

### 4.1 In-Scope Assumptions

1. **Local RAM is clean:** The user's machine is not compromised by a kernel-level rootkit that reads arbitrary memory pages.
2. **Entropy sources are honest:** OS-level RNGs (`/dev/urandom`, `CryptGenRandom`) are not backdoored.
3. **Correct implementation:** Cryptographic primitives (AES-GCM, SHA-256, X25519, ML-DSA-65) are correctly implemented by underlying libraries.
4. **User controls the vault:** The vault runs with appropriate user-level permissions.
5. **Differential privacy parameters are set correctly:** Epsilon values are within the recommended range (0.1–1.0) for cryptographic applications.
6. **Attestation verifier has known-good baselines:** Binary hashes and environment profiles are registered before verification begins.

### 4.2 Out-of-Scope (Not Protected)

1. **Physical access attacks:** Cold-boot attacks, DMA extraction from running hardware.
2. **Compromised OS:** Kernel rootkits or hypervisor-level malware can read any user-space memory.
3. **Social engineering:** Phishing, keyloggers, credential theft outside the vault's scope.
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
│              Key Derivation (Argon2id)               │
│                                                      │
│  Input: Passphrase + random salt                     │
│  Params: 64MB memory, 3 iterations, 4 parallelism   │
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

### 5.2 ML-DSA-65 Digital Signatures (NIST FIPS 204)

- **Security Category 3** (equivalent to AES-192)
- **Constant-time signing** to prevent timing side-channels
- **Key sizes**: 4032 bytes (signing), 1952 bytes (verifying), 3309 bytes (signature)
- **Vault storage**: Signing keys encrypted with Argon2id + AES-256-GCM

### 5.3 Zero-Copy Memory Policy

**Core Philosophy:** *Never store the raw key and the plaintext data in the same memory page.*

| Operation | Memory Behavior |
|-----------|----------------|
| Key Generation | Keys generated in isolated heap allocation |
| Encryption | Plaintext → ciphertext; key zeroized after use |
| Decryption | Ciphertext → plaintext in isolated buffer; key zeroized after use |
| Key Rotation | Old keys wiped from memory before new keys generated |
| Cache | Encrypted data only; never plaintext in cache |

### 5.4 Memory Zeroization

- **Python:** `cryptography` library handles internal zeroization; key lifetime minimized
- **Rust:** `zeroize` crate with `Zeroize` and `ZeroizeOnDrop` traits

---

## 6. Phase 3 Security Controls

### 6.1 Key Revocation (CRL)

**Threat:** A compromised key remains valid indefinitely, allowing an attacker to decrypt historical data.

**Mitigation:**
- HMAC-SHA256 signed revocation list
- Tamper detection: any modification to entries invalidates the signature
- Revocation reasons tracked: compromised, rotated, retired, policy
- Revoked keys are rejected by encryption and decryption operations

**Residual Risk:** If the revocation key itself is compromised, an attacker could create fake CRL entries or remove legitimate revocations. Mitigation: store revocation key in HSM or protected memory.

### 6.2 Automatic Key Rotation

**Threat:** Long-lived keys accumulate usage, increasing the attack surface for statistical cryptanalysis and key compromise.

**Mitigation:**
- Time-based expiry: keys automatically expire after configurable lifetime
- Usage-based expiry: keys expire after N operations (encrypt + decrypt)
- Expired keys are marked, new keys generated, and old keys wiped from memory
- Metadata tracks created_at, last_used_at, operation counts

**Residual Risk:** Rotation does not re-encrypt historical ciphertext. If a pre-rotation key is compromised, data encrypted before rotation is still readable.

### 6.3 FIPS 140-3 Compliance Mode

**Threat:** Non-approved or weak algorithms reduce cryptographic strength.

**Mitigation:**
- Blocks all non-NIST-approved algorithms (e.g., X25519 fallback disabled)
- Enforces minimum AES key length (256 bits)
- Enforces correct nonce length (96 bits)
- Only allows approved hash algorithms: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- Requires minimum password length (8 characters) for key derivation
- All operations logged for audit trail

**Approved Algorithms (FIPS 140-3):**
- Encryption: AES-256-GCM (FIPS 197)
- Key Derivation: HKDF-SHA256 (SP 800-56C) or Argon2id
- Hashing: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- Digital Signatures: ML-DSA-65 (FIPS 204)
- RNG: OS CSPRNG (`/dev/urandom`, `CryptGenRandom`)

### 6.4 Differential Privacy Entropy Collection

**Threat:** Spectre/Meltdown side-channel attacks infer private key bits through precise timing analysis of entropy collection.

**Mitigation:**
- Laplace noise injection calibrated by epsilon parameter
- Individual timing measurements obfuscated, aggregate entropy preserved
- OS CSPRNG mixed in via SHA-256 post-processing
- Epsilon recommended range: 0.1–1.0 for cryptographic applications
- Constant-time comparison functions prevent timing leaks
- Random delay injection defeats timing analysis

**Residual Risk:** If epsilon is set too high (>10.0), noise becomes insufficient to defeat sophisticated side-channel analysis. If set too low (<0.01), entropy quality degrades.

### 6.5 Remote Attestation

**Threat:** An attacker modifies the vault binary, injects malicious libraries (LD_PRELOAD), or tampers with the runtime environment to extract keys.

**Mitigation:**
- Binary integrity check: SHA-256 hash of running binary verified against known-good baseline
- Environment sanity: LD_PRELOAD, PYTHONPATH, PYTHONINSPECT checked for suspicious values
- Memory canaries: Random values verified to detect memory tampering
- Challenge-response: Fresh attestation challenges prevent replay attacks
- Freshness window: Challenges expire after 5 minutes

**Residual Risk:** If the known-good binary hash is never registered (first-run scenario), attestation defaults to accepting any binary. Attacker with physical access can modify the binary before the initial hash is captured.

---

## 7. Security Watchdog

### 7.1 200ms Latency Threshold

The Python ML-KEM implementation includes a **Security Watchdog** that monitors handshake latency:

```python
if elapsed > HANDSHAKE_TIMEOUT:  # 200ms
    raise SecurityException("Latency anomaly detected")
```

**Purpose:** Detect side-channel timing attacks where an adversary intentionally slows CPU execution to measure power consumption or cache behavior.

**Threshold Rationale:** On an i9-class processor, ML-KEM encapsulation should complete in <50ms. A 200ms threshold provides 4x margin for system load while catching deliberate slowdowns.

**Limitations:** Does not protect against passive timing analysis on the same execution; may trigger false positives on heavily loaded systems.

---

## 8. MCP Security Model

### 8.1 Transport Security

| Transport | Encryption | Threat Model |
|-----------|-----------|--------------|
| stdio | Process isolation | Same-machine only; OS enforces boundaries |
| HTTP (local) | None (plaintext) | Loopback only; network sniffer can observe |
| HTTP (remote) | TLS optional | Remote transport requires TLS certificate |

### 8.2 HTTP Hardening

| Protection | Implementation |
|---|---|
| Authentication | Bearer token (HMAC constant-time comparison) |
| Rate Limiting | 100 requests/minute per IP, token bucket |
| Body Size Limit | 1MB max, 413 on overflow |
| Default Binding | `127.0.0.1` (require `--public` for `0.0.0.0`) |
| TLS Support | Optional SSL cert/key, TLSv1.2+ minimum |
| Security Headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` |

### 8.3 Data Flow

```
Agent Request → [Plaintext data] → Abir-Guard → [Encrypt locally] → [Ciphertext only] → Agent Memory
                                                                                               │
                                                                                               ▼
                                                                                          LLM Provider
                                                                                       (Never sees plaintext)
```

**Critical Property:** The LLM provider never receives plaintext secrets.

---

## 9. Dependency Security

| Layer | Dependency | Update Mechanism | Risk if Outdated |
|-------|-----------|------------------|------------------|
| Python | `cryptography` | Dependabot | CVE in AES/SHA implementations |
| Python | `argon2-cffi` | Dependabot | KDF vulnerabilities |
| Rust | `aes-gcm`, `sha3`, `hkdf`, `fips204` | `cargo update` | Cryptographic vulnerabilities |
| Rust | `zeroize` | `cargo update` | Sensitive data not properly wiped |
| Build | Rust toolchain | rustup | Compiler-level vulnerabilities |
| Go | Standard library (`crypto/*`) | `go mod tidy` | Stdlib CVEs |

### 9.1 Supply Chain Protections

- **`Cargo.lock`** pinned for reproducible Rust builds
- **`go.sum`** pinned for reproducible Go builds
- **Dependabot** configured for automated dependency updates
- **Secret scanning** enabled to prevent credential leakage
- **GPG-signed commits** verify author authenticity

---

## 10. Known Limitations

| Limitation | Impact | Status |
|-----------|--------|--------|
| ML-KEM-1024 uses X25519 fallback (liboqs not installed) | Classical KEM until liboqs deployed | Code ready, needs `liboqs` |
| HSM file backend uses XOR (not real encryption) | Weak protection for stored keys on Linux without desktop | Mitigated by Argon2id vault encryption |
| Attestation requires pre-registered binary hash | First-run attestation is permissive | Documented in deployment guide |
| Differential privacy degrades with very low epsilon | Entropy quality affected if misconfigured | Recommended range: 0.1–1.0 |
| Rotation does not re-encrypt historical data | Pre-rotation ciphertext readable if old key compromised | Documented limitation |

---

## 11. Audit Trail

| Date | Change | Author |
|------|--------|--------|
| 2026-05-03 | Initial threat model (v1.0.0) | Abir Maheshwari |
| 2026-05-04 | v2.0.0: ML-DSA-65, SHAMIR, Argon2id added | Abir Maheshwari |
| 2026-05-04 | v3.0.0: CRL, rotation, FIPS mode, differential privacy, remote attestation, Go SDK | Abir Maheshwari |

---

**This document should be reviewed and updated whenever the architecture, dependencies, or threat landscape changes.**
