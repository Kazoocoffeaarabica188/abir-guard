# Contributing to Abir-Guard

Thank you for your interest in contributing to Abir-Guard — the quantum-resilient vault I built for AI agent memory.

I welcome contributions from developers, security researchers, and AI engineers who believe that agent memory should be a private vault, not an open book.

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## How to Contribute

### 1. Reporting Bugs

- Check [existing issues](https://github.com/abir-guard/abir-guard/issues) first
- Use the bug report template
- Include: Rust version, Python version, OS, and reproduction steps
- **Security vulnerabilities:** Follow our [Security Policy](.github/SECURITY.md) — do NOT open public issues

### 2. Suggesting Features

- Open a feature request issue with:
  - Use case description
  - Why it matters for agent security
  - Proposed implementation approach

### 3. Submitting Code

1. **Fork** the repository
2. **Create a branch:** `git checkout -b feature/your-feature`
3. **Write tests** for new functionality
4. **Run tests locally:**
   ```bash
   # Python
   pytest tests/test_abir_guard.py -v
   
   # Rust
   cargo test
   
   # Lint
   cargo clippy -- -D warnings
   ```
5. **GPG-sign your commits:** `git commit -S -m "feat: add feature"`
6. **Push** and open a Pull Request

### 4. Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ML-DSA signature support
fix: resolve nonce collision in encrypt
docs: update threat model with new assumptions
test: add HMAC verification tests
ci: add Rust audit to CI pipeline
deps: update aes-gcm to 0.11
```

---

## Priority Contribution Areas

I especially welcome contributions in these areas:

### High Priority
- [ ] **Real ML-KEM-1024 via liboqs** — Replace X25519 fallback with actual PQC
- [ ] **Rust Security Watchdog** — Port 200ms latency detection to Rust
- [ ] **Go SDK** — Native Go implementation for Kubernetes workloads

### Medium Priority
- [ ] **YubiKey Integration** — PKCS#11 HSM support
- [ ] **Real TPM 2.0 Seal/Unseal** — Hardware-backed key storage
- [ ] **Mojo SDK** — Modular language support

### Lower Priority
- [ ] **Elixir SDK** — For Phoenix-based agent frameworks
- [ ] **Ruby SDK** — For Rails agent integrations
- [ ] **WASM Build** — Browser-based encryption demo
- [ ] **Benchmarks** — Performance comparison suite

---

## Development Setup

### Prerequisites

- **Rust 1.70+** (via rustup)
- **Python 3.10+**
- **Git with GPG** (recommended)

### Quick Setup

```bash
# Clone
git clone https://github.com/abir-guard/abir-guard.git
cd abir-guard

# Python
pip install -e ".[dev]"

# Rust
cargo build --release

# Run all tests
cargo test && pytest tests/test_abir_guard.py -v
```

---

## Code Style

### Rust
- Follow `rustfmt` defaults
- No `unwrap()` in library code — use `?` or `expect()` with context
- Zero-copy for sensitive data: pass references, don't clone
- Always zeroize: implement `Zeroize` and `ZeroizeOnDrop`
- Run `cargo clippy -- -D warnings` before submitting

### Python
- Follow PEP 8 (enforced by ruff)
- Type hints required for all public functions
- Docstrings for all public classes and methods
- Run `ruff check src/` before submitting

---

## Pull Request Checklist

- [ ] Tests pass (`cargo test` + `pytest`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] No ruff violations (`ruff check`)
- [ ] Commit is GPG-signed
- [ ] Documentation updated (if API changed)
- [ ] Threat model updated (if security boundary changed)
- [ ] CHANGELOG entry added (if applicable)

---

## Questions?

- Open a [discussion](https://github.com/abir-guard/abir-guard/discussions)
- Email: abhirsxn@gmail.com

---

By contributing, you agree that your contributions will be licensed under the MIT License.
