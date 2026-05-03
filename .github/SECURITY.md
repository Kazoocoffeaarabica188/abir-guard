# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Abir-Guard seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Reporting Process

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Email your findings to **abir@aquilldriver.com** with:
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

## Security Features

Abir-Guard implements the following security measures:

- **Post-Quantum Cryptography:** ML-KEM-1024 (NIST FIPS 203) + X25519 hybrid
- **Authenticated Encryption:** AES-256-GCM (NIST FIPS 197)
- **Security Watchdog:** 200ms latency anomaly detection
- **Zero-Copy Memory:** Minimal plaintext exposure in RAM
- **Memory Zeroization:** Explicit wiping of sensitive material
- **Entropy Injection:** CPU jitter-based randomness collection
- **Hardware Support:** TPM 2.0 detection, HSM integration

See [THREAT_MODEL.md](THREAT_MODEL.md) for our complete threat model.
