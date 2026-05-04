# Abir-Guard Publishing Guide

## Prerequisites

### PyPI Publishing

1. Create a PyPI account at https://pypi.org
2. Create an API token at https://pypi.org/manage/account/token/
3. Install required tools:
   ```bash
   pip install --upgrade build twine
   ```

### crates.io Publishing

1. Create a crates.io account at https://crates.io
2. Generate an API token at https://crates.io/settings/tokens
3. Login with cargo:
   ```bash
   cargo login <your-token>
   ```

## Publishing Steps

### 1. Update Version Numbers

Update version in both files:

**pyproject.toml:**
```toml
[project]
version = "3.1.0"  # Update this
```

**Cargo.toml:**
```toml
[package]
version = "3.1.0"  # Update this
```

### 2. Run Full Test Suite

```bash
# Python tests
python3 -m pytest tests/ -v

# Rust tests
cargo test

# Go tests
cd sdk/go && go test -v
```

### 3. Build Packages

**Python (PyPI):**
```bash
# Clean old builds
rm -rf dist/ build/ *.egg-info

# Build
python3 -m build

# Verify
twine check dist/*
```

**Rust (crates.io):**
```bash
# Verify package
cargo verify-package  # Optional

# Dry run
cargo publish --dry-run
```

### 4. Publish to Test Servers (Optional but Recommended)

**TestPyPI:**
```bash
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ abir-guard
```

**Crates.io (no test environment)**

### 5. Publish to Production

**PyPI:**
```bash
twine upload dist/*
```

**crates.io:**
```bash
cargo publish
```

### 6. Create GitHub Release

```bash
# Tag the release
git tag -a v3.1.0 -m "Release v3.1.0"
git push origin v3.1.0
```

## Automated Publishing (GitHub Actions)

The repository includes a GitHub Actions workflow that automatically publishes:

1. **On Release:** When you create a GitHub Release, it publishes to both PyPI and crates.io
2. **Manual Trigger:** You can manually trigger the workflow from the Actions tab

### Setup Required

1. **PyPI:** Configure trusted publishing in your PyPI project settings
2. **crates.io:** Add `CRATES_IO_TOKEN` secret to your GitHub repository

## Version Bumping Checklist

- [ ] Update `pyproject.toml` version
- [ ] Update `Cargo.toml` version
- [ ] Update `README.md` version badge
- [ ] Update `TASKS.md` roadmap
- [ ] Run full test suite (all must pass)
- [ ] Build and verify packages
- [ ] Create git tag
- [ ] Push to GitHub
- [ ] Create GitHub Release
- [ ] Verify PyPI listing
- [ ] Verify crates.io listing

## Troubleshooting

### PyPI Issues

**Package already exists:**
```bash
# You cannot overwrite versions
# Bump version and rebuild
```

**Missing classifiers:**
```bash
twine check dist/*  # Will show warnings
```

### crates.io Issues

**Dependency not published:**
```bash
# Ensure all dependencies are on crates.io first
cargo tree  # Check dependency tree
```

**Version already exists:**
```bash
# crates.io does not allow republishing
# Bump version and republish
```

**Missing README:**
```bash
# Ensure README.md is in the package root
# and included in Cargo.toml
```

## Post-Publishing Verification

```bash
# PyPI
pip install abir-guard
python -c "import abir_guard; print(abir_guard.VERSION)"

# crates.io
cargo add abir_guard
cargo run --example basic  # If examples exist

# Go
go get github.com/Abiress/abir-guard/sdk/go
go test github.com/Abiress/abir-guard/sdk/go
```

## Support

For publishing issues:
- PyPI: https://pypi.org/help/
- crates.io: https://crates.io/policies
- GitHub Issues: https://github.com/Abiress/abir-guard/issues
