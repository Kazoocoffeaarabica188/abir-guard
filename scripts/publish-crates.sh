#!/bin/bash
# crates.io Publishing Script for Abir-Guard
# Usage: ./scripts/publish-crates.sh

set -e

echo "============================================="
echo "  Abir-Guard - crates.io Publishing"
echo "============================================="
echo ""

# Login to crates.io
echo "Logging into crates.io..."
echo "Note: You'll need to run 'cargo login <your-token>' first"
echo "Get token at: https://crates.io/settings/tokens"
echo ""

# Verify package
echo "Verifying package..."
cargo verify-package 2>&1 || echo "Note: cargo-verify-package not installed (optional)"

# Dry run publish
echo "Running dry publish..."
cargo publish --dry-run

# Actual publish
echo ""
echo "Publishing to crates.io..."
cargo publish

echo ""
echo "✅ Package published to crates.io!"
echo "View at: https://crates.io/crates/abir_guard"
echo ""
echo "Install with: cargo add abir_guard"
