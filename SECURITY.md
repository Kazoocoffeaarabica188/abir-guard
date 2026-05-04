# Security Policy

## Supported Versions

| Version | Supported | PQC Level |
|--------|----------|-----------|
| 1.0.x | ✅ | Classical (AES-256 + X25519) |
| 2.0.x | ✅ | Post-quantum (ML-DSA-65 + Argon2id + SHAMIR) |

## Reporting Vulnerabilities

**DO NOT report security vulnerabilities in public issues.**

Email: abhirsxn@gmail.com

Response time: 24-48 hours

## Threat Model

### What I Protect Against

1. **Harvest Now, Decrypt Later**
   - Attackers record encrypted data today
   - Quantum computers break it tomorrow
   - **Mitigation**: ML-KEM-1024 post-quantum KEM

2. **Memory Exposure**
   - Agent logs plaintext sensitive data
   - **Mitigation**: Encrypt before storage

3. **Token Leakage**
   - LLM sees sensitive data in context
   - **Mitigation**: Zero-copy, LLM never sees plaintext

4. **Data Tampering**
   - Attacker modifies encrypted data
   - **Mitigation**: ML-DSA-65 post-quantum signatures

### What I Don't Protect Against

- Physical access (use HSM)
- Compromised host (use TPM)
- Side-channel attacks (use secure hardware)

## Security Properties

### Encryption

| Property | Implementation |
|----------|---------------|
| Confidentiality | AES-256-GCM |
| Integrity | AEAD authentication tag |
| Key Encapsulation | ML-KEM-1024 (or X25519) |
| Key Derivation | Argon2id (OWASP recommended) |
| Digital Signatures | ML-DSA-65 (NIST FIPS 204) |
| Entropy | OS CSPRNG + timing jitter |

### Key Management

- **At Rest**: Keys stored in encrypted vault (Argon2id + AES-256-GCM)
- **In Transit**: MCP over stdio (local) or TLS (future)
- **Ephemeral**: New keypair per agent session
- **Threshold Recovery**: SHAMIR (t, n) secret sharing for key backup

## Cryptography Standards

- NIST FIPS 203: ML-KEM (when available)
- NIST FIPS 204: ML-DSA (implemented)
- NIST FIPS 197: AES-GCM
- NIST FIPS 202: SHA-3
- OWASP: Argon2id key derivation

## Audit

This is alpha software. Audit before production use.

## QNu Labs Comparison

| QNu Labs Product | Abir-Guard | Innovation |
| :--- | :--- | :--- |
| **Tropos** (QRNG) | **Noise-Harvesting** | Software-only, no hardware |
| **Armos** (QKD) | **PQC Tunnel** | Application-layer quantum safety |
| **Hodos** (PQC) | **Agent Vault** | Designed for AI agents |

While QNu Labs focuses on hardware-level QKD, I bring Quantum-Resilience to the Application Layer for Autonomous Agents.

## Incident Response

1. Identify compromised key ID
2. Delete keypair: `vault.remove_keypair(id)`
3. Rotate all secrets
4. Update agent code
5. Report to users

---

For security questions: abhirsxn@gmail.com