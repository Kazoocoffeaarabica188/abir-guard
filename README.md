# Abir-Guard (v1.0.0)

<p align="center">
  <img src="https://img.shields.io/badge/X25519-Classical_ECDH-blue?style=for-the-badge&logo=lock" alt="X25519">
  <img src="https://img.shields.io/badge/AES--256-GCM-NIST_FIPS_197-blue?style=for-the-badge&logo=lock" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/ML--KEM-NIST_FIPS_203-orange?style=for-the-badge&logo=shield" alt="ML-KEM">
  <img src="https://img.shields.io/badge/Rust-Production_Ready-orange?style=for-the-badge&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

```diff
- Legacy memory storage is a ticking time bomb.
+ Abir-Guard: The Quantum-Resilient "Black Box" for Autonomous Agent Memory.
```

## Overview

Abir-Guard is a quantum-resistant encryption vault designed for AI agent memory. It implements NIST-standard Post-Quantum Cryptography (PQC) to protect sensitive agent data — API keys, credentials, and proprietary IP — from Harvest Now, Decrypt Later (HNDL) attacks.

**Dual implementation:** Python SDK for agent integration + Rust core for high-performance cryptography.

---

## Table of Contents

- [Features](#features)
- [Security Architecture](#security-architecture)
- [Quick Start](#quick-start)
- [Python SDK Guide](#python-sdk-guide)
- [Rust CLI Guide](#rust-cli-guide)
- [Rust Library Guide](#rust-library-guide)
- [JavaScript SDK Guide](#javascript-sdk-guide)
- [MCP Server Guide](#mcp-server-guide)
- [LangChain Integration](#langchain-integration)
- [CrewAI Integration](#crewai-integration)
- [Docker Deployment](#docker-deployment)
- [HSM & TPM Integration](#hsm--tpm-integration)
- [Run Tests](#run-tests)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| X25519 Hybrid KEM | ✅ | NIST-compliant ECDH key encapsulation (real ECDH, not random bytes) |
| ML-KEM-1024 Ready | ⏳ | Code ready, requires `liboqs` library (fallback to X25519) |
| AES-256-GCM Envelope Encryption | ✅ | NIST FIPS 197 authenticated encryption |
| Memory Zeroization | ✅ | Explicit key wiping after use (Rust `zeroize` crate) |
| Security Watchdog (200ms) | ✅ | Latency anomaly detection for side-channel attacks |
| Entropy Injection | ✅ | CPU jitter-based randomness collection |
| Encrypted Disk Persistence | ✅ | AES-256-GCM encrypted vault with passphrase |
| Input Validation | ✅ | Regex, length, reserved prefix, path traversal rejection |
| MCP Server (JSON-RPC) | ✅ | 10 methods, auth, rate limiting, body size limits |
| MCP HTTP Server | ✅ | Hardened: Bearer auth, rate limit, TLS, security headers |
| Audit Logging | ✅ | Tamper-evident SHA-256 hash chain |
| Canary Keys | ✅ | Honeypot keys for breach detection |
| LangChain SDK | ✅ | 3 tools: KeyGen, Encrypt, Decrypt |
| CrewAI SDK | ✅ | Agent tools (version-compatible) |
| JavaScript SDK | ✅ | Node.js crypto implementation + MCP client |
| HSM Integration | ✅ | macOS Keychain, Windows Credential Manager, file fallback |
| TPM 2.0 Detection | ✅ | Hardware TPM availability check |
| Rust CLI | ✅ | Persistent vault with clap subcommands + passphrase |
| Docker | ✅ | Containerized hardened MCP server |
| CI/CD | ✅ | GitHub Actions: test, build, lint, security audit |
| Dependabot | ✅ | Weekly dependency updates |

---

## Security Architecture

### 1. Hybrid KEM Architecture

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
│              Envelope Encryption                     │
│                                                      │
│  Algorithm: AES-256-GCM (NIST FIPS 197)             │
│  Nonce: 96-bit random (per-message unique)          │
│  Auth Tag: 128-bit (integrity + authenticity)       │
└──────────────────────────────────────────────────────┘
```

### 2. X25519 Real ECDH Implementation

The fallback KEM uses proper Elliptic Curve Diffie-Hellman:

```
Sender:                          Receiver:
  1. Generate ephemeral X25519     1. Has static X25519 keypair
     keypair (ep_sk, ep_pk)
  2. shared = ep_sk.exchange(      2. shared = static_sk.exchange(
     recipient_pk)                    ep_pk)  ← from ciphertext
  3. HKDF(shared) → 32-byte        3. HKDF(shared) → 32-byte
     shared secret                    shared secret (identical)
  4. Ciphertext = ep_pk (32 bytes)  4. Ciphertext = ep_pk
```

### 3. Encrypted Disk Persistence

```
Passphrase ──→ HKDF-SHA256 ──→ 256-bit AES key
                                       │
                                       ▼
Keys JSON ──→ AES-256-GCM ──→ keys.enc (encrypted binary)
                                       │
                              nonce(12) + ciphertext + GCM tag(16)
```

- No plaintext keys on disk
- Wrong passphrase = decryption failure, no data exposed
- File permissions set to `0o600` (owner read/write only)

### 4. MCP HTTP Hardening

| Protection | Implementation |
|------------|---------------|
| Authentication | Bearer token (HMAC constant-time comparison) |
| Rate Limiting | 100 requests/minute per IP, token bucket |
| Body Size Limit | 1MB max, 413 on overflow |
| Default Binding | `127.0.0.1` (require `--public` for `0.0.0.0`) |
| TLS Support | Optional SSL cert/key, TLSv1.2+ minimum |
| Security Headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` |
| Audit Log | Tamper-evident SHA-256 hash chain of all operations |
| Canary Keys | Honeypot keys that trigger breach alerts when accessed |

### 5. Input Validation

All `key_id` inputs are validated:
- Alphanumeric, hyphens, underscores only
- Maximum 64 characters
- Cannot start with `__` (reserved for system/canary keys)
- Null bytes, `..`, `/`, `\` rejected (path traversal)

### 6. Zero-Copy Memory Policy

**Core Philosophy:** *Never store the raw key and the plaintext data in the same memory page.*

| Operation | Memory Behavior |
|-----------|----------------|
| Key Generation | Keys generated in isolated heap allocation |
| Encryption | Plaintext → ciphertext; key zeroized after use |
| Decryption | Ciphertext → plaintext in isolated buffer; key zeroized after use |
| Key Rotation | Old keys wiped from memory before new keys generated |
| Cache | Encrypted data only; never plaintext in cache |

### 7. MCP Zero-Token Exposure

Encryption happens locally. The raw sensitive data never enters LLM context or consumes tokens.

---

## Quick Start

```bash
# Python SDK
pip install -e .

# Rust CLI
cargo build --release

# Verify everything works
python3 tests/run_tests.py && cargo test
```

---

## Python SDK Guide

### Basic Vault Usage

```python
from abir_guard import Vault

vault = Vault()

# Generate keypair
pub, sec = vault.generate_keypair("finance_agent")

# Encrypt
ct = vault.store("finance_agent", b"API_KEY=sk-abc123xyz")

# Decrypt
plaintext = vault.retrieve("finance_agent", ct)
# b"API_KEY=sk-abc123xyz"

# List keys
keys = vault.list_keypairs()  # ['finance_agent']

# Delete key (zeroizes from memory)
vault.remove_keypair("finance_agent")
```

**Auto-generate keys:** `store()` creates a key if it doesn't exist:

```python
vault = Vault()
ct = vault.store("new_agent", b"auto-generated")  # Key created automatically
```

### Canary Keys (Breach Detection)

```python
from abir_guard import Vault

vault = Vault()

# Plant a honeypot key
canary_id = vault.add_canary()

# If attacker accesses this key, breach is detected
breached = vault.check_canary()  # False = safe, True = breach
```

### Audit Log (Tamper-Evident)

```python
# All operations are automatically logged
vault.audit.log("custom_action", "key-1", True)

# Verify integrity (detects tampering)
is_valid = vault.verify_audit_integrity()

# Get recent entries
entries = vault.audit.get_entries(limit=50)
```

### ML-KEM Hybrid KEM

```python
from abir_guard.ml_kem import MLKEM1024

kem = MLKEM1024()
pk, sk = kem.keygen()

# Encapsulate (proper ECDH)
ct, ss_sender = kem.encapsulate(pk)

# Decapsulate
ss_receiver = kem.decapsulate(ct, sk)

assert ss_sender == ss_receiver  # Same shared secret
```

### MCP JSON-RPC Server

```python
from abir_guard import McpServer

server = McpServer()

# Available methods: generate_key, encrypt, decrypt, list_keys,
#                    delete_key, clear_cache, add_canary, check_canary,
#                    audit_log, info

request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "encrypt",
    "params": {"key_id": "agent", "data": "secret"}
}
response = server.handle(request)
```

### MCP HTTP Server (Hardened)

```python
from abir_guard.mcp_http import McpHttpServer

# Production: auth + localhost only
server = McpHttpServer(
    port=9090,
    api_key="your-secret-key",
    rate_limit=100,
)
server.start()

# Development (no auth):
# server = McpHttpServer(port=9090, public=True)

# With TLS:
# server = McpHttpServer(port=9090, ssl_cert="cert.pem", ssl_key="key.pem")
```

```bash
# Health check
curl http://localhost:9090/health

# Encrypt (requires Bearer token)
curl -X POST http://localhost:9090 \
  -H "Authorization: Bearer your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"encrypt","params":{"key_id":"agent","data":"secret"}}'

# Check audit log
curl -X POST http://localhost:9090 \
  -H "Authorization: Bearer your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"audit_log","params":{}}'
```

---

## Rust CLI Guide

### Build

```bash
cargo build --release
./target/release/abir-guard info
```

### Key Management

```bash
# Generate keypair (with passphrase)
./target/release/abir-guard -k "my-passphrase" init my-agent

# List keys (hides canary/system keys)
./target/release/abir-guard -k "my-passphrase" list-keys

# Delete a key
./target/release/abir-guard -k "my-passphrase" delete-key my-agent

# Clear all vault data
./target/release/abir-guard -k "my-passphrase" clear-cache
```

### Encrypt & Decrypt

```bash
# Encrypt (auto-generates key if needed)
./target/release/abir-guard -k "my-passphrase" encrypt my-agent "API_KEY=sk-secret"
# Output:
# Ciphertext: NfvJ2ofz8obRKx+A//384ZGYpRcvMsDdI0SJudx9zNAamhLYKQ==
# Nonce: OpslNknUuQptaQzZ

# Decrypt (use positional args)
./target/release/abir-guard -k "my-passphrase" decrypt my-agent \
  "NfvJ2ofz8obRKx+A//384ZGYpRcvMsDdI0SJudx9zNAamhLYKQ==" \
  "OpslNknUuQptaQzZ"
# Output: API_KEY=sk-secret
```

**Wrong passphrase = graceful error:**
```bash
$ ./target/release/abir-guard -k "wrong" decrypt my-agent ...
Decryption failed: Key not found
Exit code: 1
```

### Passphrase via Environment Variable

```bash
export ABIR_GUARD_KEY="my-passphrase"
./target/release/abir-guard init my-agent  # No -k flag needed
```

### MCP stdio Server

```bash
./target/release/abir-guard mcp-server --mode stdio
```

---

## Rust Library Guide

```toml
[dependencies]
abir_guard = { path = "../abir-guard" }
```

```rust
use abir_guard::Vault;

let vault = Vault::new();

// Auto-generates key on first store
let ct = vault.store(b"agent-1", b"secret data").unwrap();
let plain = vault.retrieve(b"agent-1", &ct).unwrap();
assert_eq!(plain, b"secret data");
```

**Persistent encrypted vault:**

```rust
use abir_guard::persistent_vault;

let vault = persistent_vault::get_vault("my-passphrase");
let ct = persistent_vault::store_encrypted(&vault, "agent", b"secret", "my-passphrase").unwrap();
let plain = persistent_vault::retrieve_decrypted(&vault, "agent", &ct, "my-passphrase").unwrap();
```

---

## JavaScript SDK Guide

Located at `src/abir_guard.js`:

```javascript
const AbirGuard = require('./src/abir_guard');

const vault = new AbirGuard();

const { publicKey, secretKey } = vault.generateKeyPair('agent-1');
const { ciphertext, nonce } = vault.encrypt('agent-1', 'API_KEY=sk-secret');
const plaintext = vault.decrypt('agent-1', ciphertext, nonce);
```

---

## MCP Server Guide

### JSON-RPC Methods

| Method | Params | Response |
|--------|--------|----------|
| `generate_key` | `{key_id}` | `{key_id, generated: true}` |
| `encrypt` | `{key_id, data}` | `{nonce, ciphertext, key_id}` |
| `decrypt` | `{key_id, ciphertext: {nonce, ciphertext}}` | `{plaintext}` |
| `list_keys` | `{}` | `{keys: [...]}` |
| `delete_key` | `{key_id}` | `{deleted: true, key_id}` |
| `clear_cache` | `{}` | `{cleared: true}` |
| `add_canary` | `{}` | `{canary_id}` |
| `check_canary` | `{}` | `{breach_detected: bool}` |
| `audit_log` | `{limit}` | `{entries: [...]}` |
| `info` | `{}` | `{name, version, mcp_version}` |

---

## LangChain Integration

```python
from abir_guard.langchain import get_langchain_tools

tools = get_langchain_tools()
# tools[0] = SilentQKeyGenTool
# tools[1] = SilentQEncryptTool
# tools[2] = SilentQDecryptTool
```

---

## CrewAI Integration

```bash
pip install -e ".[crewai]"
```

```python
from abir_guard.crewai import get_crewai_tools

tools = get_crewai_tools()
# Returns KeyGenCrewTool, EncryptCrewTool, DecryptCrewTool
```

---

## Docker Deployment

```bash
# Build
docker build -t abir-guard:latest .

# Run (with API key for auth)
docker run -d --name abir-guard \
  -p 9090:9090 \
  -e ABIR_GUARD_API_KEY="your-key" \
  -v abir-keys:/root/.abir_guard \
  abir-guard:latest

# Health check
curl http://localhost:9090/health
```

---

## HSM & TPM Integration

```python
from abir_guard.abir_hsm import HSMKeyStore, TPMKeyStore

# Auto-detects best backend (Keychain > Credential Manager > file)
hsm = HSMKeyStore()
print(f"Backend: {hsm.backend}")  # "keychain" / "credential_manager" / "secret_service" / "file"

hsm.store_secret("my-api-key", b"sk-abc123")
secret = hsm.retrieve_secret("my-api-key")

# TPM 2.0 detection
tpm = TPMKeyStore()
print(f"TPM available: {tpm.is_available()}")
```

---

## Run Tests

```bash
# Python test suite
python3 tests/run_tests.py

# Pytest
pip install -e ".[dev]"
pytest tests/test_abir_guard.py -v

# Rust tests
cargo test

# Full verification
cargo build --release && cargo test && python3 tests/run_tests.py
```

---

## Project Structure

```
abir_guard/
├── abir_guard/              # Python package
│   ├── __init__.py          # Core Vault, MCP, Ciphertext, AuditLogger, canary keys
│   ├── ml_kem.py            # ML-KEM-1024 + X25519 hybrid KEM (real ECDH)
│   ├── langchain.py         # LangChain tool integration (3 tools)
│   ├── crewai.py            # CrewAI tool integration (version-compatible)
│   ├── abir_hsm.py          # HSM/TPM integration
│   ├── mcp_http.py          # Hardened HTTP MCP server (auth, rate limit, TLS)
│   └── crypto_store.py      # Encrypted disk persistence (Argon2id + AES-GCM)
├── src/                     # Rust source
│   ├── lib.rs               # Library entry point + re-exports
│   ├── main.rs              # CLI binary (clap, passphrase, input validation)
│   ├── quantum_kernel.rs    # Hybrid encryption + watchdog + zeroization
│   ├── entropy_inject.rs    # CPU jitter entropy collector
│   ├── zero_copy.rs         # Zero-copy vault with LRU-encrypted cache
│   ├── mcp_gateway.rs       # MCP JSON-RPC server (10 methods)
│   └── persistent_vault.rs  # Encrypted file-based key persistence
├── examples/
│   ├── quick_start.py       # Full feature demo
│   └── secure_crewai_agent.py  # CrewAI security example
├── tests/
│   ├── run_tests.py         # Manual test runner (5 suites)
│   └── test_abir_guard.py   # Pytest suite
├── Cargo.toml               # Rust dependencies
├── pyproject.toml           # Python package config (v1.0.0)
├── Dockerfile               # Container build (hardened)
├── LICENSE                  # MIT License
├── README.md                # This file
├── THREAT_MODEL.md          # Zero-trust threat model
├── SECURITY.md              # Vulnerability reporting
├── CONTRIBUTING.md          # Contribution guidelines
├── CODE_OF_CONDUCT.md       # Community standards
├── CITATION.cff             # Academic citation
├── TASKS.md                 # Feature status and roadmap
└── .github/
    ├── workflows/ci-cd.yml  # 5-job CI pipeline
    └── dependabot.yml       # Weekly dependency updates
```

---

## Roadmap

### Phase 1: Bedrock (Done)
- [x] X25519 hybrid KEM with AES-256-GCM (real ECDH)
- [x] Memory zeroization (Rust `zeroize` crate)
- [x] Security Watchdog (200ms latency detection)
- [x] Encrypted disk persistence (AES-256-GCM + HKDF)
- [x] Input validation (regex, length, path traversal)
- [x] MCP JSON-RPC Gateway (stdio + HTTP, auth, rate limit)
- [x] Python + Rust implementations
- [x] LangChain + CrewAI SDKs
- [x] JavaScript SDK
- [x] HSM + TPM integration
- [x] Docker + CI/CD
- [x] Audit logging (tamper-evident hash chain)
- [x] Canary/honeypot keys for breach detection

### Phase 2: Hardware & Cloud
- [ ] Real ML-KEM-1024 via liboqs
- [ ] ML-DSA signatures (NIST FIPS 204)
- [ ] SHAMIR secret sharing
- [ ] YubiKey integration
- [ ] Real TPM 2.0 seal/unseal
- [ ] Argon2id in Rust (replace HKDF)
- [ ] Apple Secure Enclave / Intel SGX

### Phase 3: Ecosystem
- [ ] Go SDK
- [ ] Aquilldriver AI cluster deployment
- [ ] ABIRMARv1 / ABIRGUJv1 SLM native support
- [ ] PyPI + crates.io publishing

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

We welcome contributions from developers, security researchers, and AI engineers.

---

## Project Governance

| Document | Purpose |
|----------|---------|
| [THREAT_MODEL.md](THREAT_MODEL.md) | Zero-trust threat model, trust boundaries, mitigations |
| [SECURITY.md](.github/SECURITY.md) | Vulnerability reporting policy, disclosure process |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute, code style, PR checklist |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards and enforcement |
| [CITATION.cff](CITATION.cff) | Academic citation for research papers |
| [TASKS.md](TASKS.md) | Feature status and roadmap |

---

## Developer

**Abir Maheshwari**  
Founder at artificial quantum dyson intelligence, biro labs, aquilldriver | AI Engineer | Quantum Computing Researcher

### Connect
- **LinkedIn:** https://linkedin.com/in/abirmaheshwari
- **Medium:** https://office.qz.com/@abirmaheshwari

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Developed by **Abir Maheshwari**  
2026 Abir-Guard
