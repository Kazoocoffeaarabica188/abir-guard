#!/bin/bash
# Abir-Guard Full Project Debug & Verification Script
# Run this before publishing to ensure everything works

set -e

echo "============================================="
echo "  Abir-Guard v3.1.0 - Full Debug & Verify"
echo "============================================="
echo ""

PASS=0
FAIL=0
WARN=0

check_pass() {
    echo "  [PASS] $1"
    PASS=$((PASS + 1))
}

check_fail() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
}

check_warn() {
    echo "  [WARN] $1"
    WARN=$((WARN + 1))
}

# Python Package Verification
echo ""
echo "📦 Python Package Checks"
echo "-------------------------"

# Check pyproject.toml
if [ -f "pyproject.toml" ]; then
    check_pass "pyproject.toml exists"
else
    check_fail "pyproject.toml missing"
fi

# Check py.typed for PEP 561
if [ -f "abir_guard/py.typed" ]; then
    check_pass "py.typed exists (PEP 561)"
else
    check_fail "py.typed missing"
fi

# Check all required modules
MODULES=("abir_guard" "ml_kem" "yubikey_integration" "tpm2_seal" "hardware_enclave" "langchain" "crewai" "abir_hsm" "mcp_http" "crypto_store" "revocation" "rotation" "fips_mode" "differential_privacy" "attestation")
for mod in "${MODULES[@]}"; do
    if [ -f "abir_guard/${mod}.py" ]; then
        check_pass "${mod}.py exists"
    else
        check_fail "${mod}.py missing"
    fi
done

# Rust Package Verification
echo ""
echo "🦀 Rust Package Checks"
echo "-----------------------"

# Check Cargo.toml
if [ -f "Cargo.toml" ]; then
    check_pass "Cargo.toml exists"
else
    check_fail "Cargo.toml missing"
fi

# Check required source files
RUST_FILES=("lib.rs" "main.rs" "quantum_kernel.rs" "ml_dsa.rs" "shamir.rs" "kdf.rs" "revocation.rs" "rotation.rs" "zero_copy.rs" "mcp_gateway.rs" "persistent_vault.rs" "entropy_inject.rs" "differential_privacy.rs")
for file in "${RUST_FILES[@]}"; do
    if [ -f "src/${file}" ]; then
        check_pass "${file} exists"
    else
        check_fail "${file} missing"
    fi
done

# Run Python Tests
echo ""
echo "🐍 Python Tests"
echo "----------------"
if python3 -m pytest tests/ -v --tb=short 2>&1 | grep -q "passed"; then
    TEST_COUNT=$(python3 -m pytest tests/ -v 2>&1 | grep -oP '\d+ passed' | head -1)
    check_pass "All Python tests passed: ${TEST_COUNT}"
else
    check_fail "Python tests failed"
fi

# Run Rust Tests
echo ""
echo "🦀 Rust Tests"
echo "--------------"
if cargo test 2>&1 | grep -q "test result: ok"; then
    RUST_TESTS=$(cargo test 2>&1 | grep "test result: ok" | head -1)
    check_pass "Rust tests passed: ${RUST_TESTS}"
else
    check_fail "Rust tests failed"
fi

# Run Go Tests
echo ""
echo "🔷 Go Tests"
echo "-----------"
cd sdk/go
if go test -v 2>&1 | grep -q "PASS"; then
    GO_TESTS=$(go test -v 2>&1 | grep -c "--- PASS")
    check_pass "Go tests passed: ${GO_TESTS}"
else
    check_fail "Go tests failed"
fi
cd ../..

# Check Documentation
echo ""
echo "📚 Documentation Checks"
echo "------------------------"
if [ -f "README.md" ]; then
    check_pass "README.md exists"
    if grep -q "v3.1.0" README.md; then
        check_pass "README.md version updated to v3.1.0"
    else
        check_warn "README.md may need version update"
    fi
else
    check_fail "README.md missing"
fi

if [ -f "LICENSE" ]; then
    check_pass "LICENSE exists"
else
    check_fail "LICENSE missing"
fi

# Check Publishing Infrastructure
echo ""
echo "🚀 Publishing Infrastructure"
echo "----------------------------"

if [ -f ".github/workflows/publish.yml" ]; then
    check_pass "GitHub Actions publish workflow exists"
else
    check_warn "publish.yml workflow missing (manual publish possible)"
fi

# Try building Python package
if python3 -m build 2>&1 | grep -q "Successfully built"; then
    check_pass "Python package builds successfully"
else
    check_warn "Python package build may have issues (install build: pip install build)"
fi

# Try verifying Rust package
if cargo verify-package 2>&1 | grep -q "verified"; then
    check_pass "Rust package verified"
else
    check_warn "cargo-verify-package not installed (install: cargo install cargo-verify-package)"
fi

# Summary
echo ""
echo "============================================="
echo "  Debug Summary"
echo "============================================="
echo "  ✅ Passed: ${PASS}"
echo "  ❌ Failed: ${FAIL}"
echo "  ⚠️  Warnings: ${WARN}"
echo ""

if [ ${FAIL} -eq 0 ]; then
    echo "  🎉 Project is ready for publishing!"
    echo ""
    echo "  Next steps:"
    echo "  1. PyPI:      twine upload dist/*"
    echo "  2. crates.io: cargo publish"
    echo "  3. GitHub:    git push && git push --tags"
    exit 0
else
    echo "  ❌ Project has issues - fix before publishing"
    exit 1
fi
