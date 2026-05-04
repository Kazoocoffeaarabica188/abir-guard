# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 3.0.x | Yes |
| 2.0.x | Security patches only |
| < 2.0 | No |

## Reporting a Vulnerability

We take the security of Abir-Guard seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Reporting Process

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Email your findings to **abhirsxn@gmail.com** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. We will acknowledge receipt within **48 hours**.
4. We will provide a detailed response within **7 days** with:
   - Confirmation of the issue
   - Our assessment of severity
   - Timeline for a fix
5. We will keep you informed of progress toward a fix and announcement.

### Disclosure Policy

- We will coordinate disclosure with the reporter
- We aim to provide a patch within **30 days** of confirmation
- Public disclosure will occur after the patch is released
- Credit will be given to the reporter (unless anonymity is requested)

### Scope

**In-scope:**
- Cryptographic implementation flaws
- Key management vulnerabilities
- Memory safety issues (Rust)
- Side-channel attack vectors
- MCP protocol vulnerabilities
- Dependency CVEs
- FIPS 140-3 compliance bypasses
- Remote attestation bypasses
- Differential privacy parameter manipulation
- CRL tampering or bypass

**Out-of-scope:**
- Social engineering attacks
- Physical access attacks
- Compromised host OS (rootkits)
- Issues in third-party libraries (report to upstream)

### Security Best Practices for Contributors

- **GPG-sign all commits**
- **Never commit secrets, keys, or credentials**
- **Run `cargo audit` before submitting PRs**
- **Review dependency changes carefully**
- **Follow zero-copy principles for sensitive data**
- **Ensure FIPS 140-3 compliance in all new code paths**

## Security Features (v3.0.0)

Abir-Guard implements the following security measures:

### Cryptography
- **Post-Quantum Cryptography:** ML-KEM-1024 (NIST FIPS 203) + X25519 hybrid
- **Authenticated Encryption:** AES-256-GCM (NIST FIPS 197)
- **Digital Signatures:** ML-DSA-65 (NIST FIPS 204)
- **Key Derivation:** Argon2id (OWASP: 64MB, 3 iterations)
- **Secret Sharing:** SHAMIR (t, n) threshold scheme over GF(251)

### Runtime Security
- **Security Watchdog:** 200ms latency anomaly detection
- **Zero-Copy Memory:** Minimal plaintext exposure in RAM
- **Memory Zeroization:** Explicit wiping of sensitive material (Rust `zeroize`)
- **Differential Privacy:** Laplace noise on entropy collection (Spectre/Meltdown defense)
- **Remote Attestation:** Runtime integrity verification before decryption
- **Constant-Time Comparison:** Timing-attack-resistant equality checks

### Key Lifecycle
- **Key Revocation (CRL):** HMAC-signed revocation list with tamper detection
- **Automatic Rotation:** Time-based and usage-based key expiry
- **FIPS 140-3 Mode:** Strict NIST algorithm enforcement, blocks non-compliant fallbacks
- **Canary Keys:** Honeypot keys for breach detection

### Infrastructure
- **Hardware Support:** TPM 2.0 detection, HSM integration (macOS Keychain, Windows Credential Manager)
- **Network Security:** Bearer token auth, rate limiting, TLS support, localhost default
- **Audit Trail:** Tamper-evident SHA-256 hash chain of all operations
- **Input Validation:** Regex, length, path traversal, reserved prefix rejection

See [THREAT_MODEL.md](THREAT_MODEL.md) for our complete threat model.
