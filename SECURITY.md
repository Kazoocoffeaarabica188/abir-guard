# Security Policy

## Supported Versions

| Version | Supported | PQC Level |
|--------|----------|-----------|
| 0.1.x | ✅ | Classical (AES-256) |
| 0.2.0 | Coming | ML-KEM-1024 |

## Reporting Vulnerabilities

**DO NOT report security vulnerabilities in public issues.**

Email: security@abir-guard.dev

Response time: 24-48 hours

## Threat Model

### What We Protect Against

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

### What We Don't Protect Against

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
| Key Derivation | HKDF-SHA256 |
| Entropy | OS CSPRNG + timing jitter |

### Key Management

- **At Rest**: Keys stored in memory only
- **In Transit**: MCP over stdio (local) or TLS (future)
- **Ephemeral**: New keypair per agent session

## Cryptography Standards

- NIST FIPS 203: ML-KEM (when available)
- NIST FIPS 197: AES-GCM
- NIST SP 800-56C: HKDF
- NIST FIPS 202: SHA-3

## Audit

This is alpha software. Audit before production use.

## QNu Labs Comparison

| QNu Labs Product | Abir-Guard | Innovation |
| :--- | :--- | :--- |
| **Tropos** (QRNG) | **Noise-Harvesting** | Software-only, no hardware |
| **Armos** (QKD) | **PQC Tunnel** | Application-layer quantum safety |
| **Hodos** (PQC) | **Agent Vault** | Designed for AI agents |

While QNu Labs focuses on hardware-level QKD, Abir-Guard brings Quantum-Resilience to the Application Layer for Autonomous Agents.

## Incident Response

1. Identify compromised key ID
2. Delete keypair: `vault.remove_keypair(id)`
3. Rotate all secrets
4. Update agent code
5. Report to users

---

For security questions: security@abir-guard.dev