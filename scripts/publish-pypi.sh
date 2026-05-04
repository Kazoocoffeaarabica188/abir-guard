#!/bin/bash
# PyPI Publishing Script for Abir-Guard
# Usage: ./scripts/publish-pypi.sh

set -e

echo "============================================="
echo "  Abir-Guard - PyPI Publishing"
echo "============================================="
echo ""

# Install build tools
echo "Installing build tools..."
pip install --break-system-packages build twine

# Clean old builds
echo "Cleaning old builds..."
rm -rf dist/ build/ *.egg-info abir_guard.egg-info

# Build package
echo "Building package..."
python3 -m build

# Verify package
echo "Verifying package..."
twine check dist/*

# Upload to TestPyPI first (optional)
echo ""
echo "Uploading to TestPyPI (safe test)..."
twine upload --repository testpypi dist/*

# Upload to PyPI
echo ""
echo "Uploading to PyPI..."
twine upload dist/*

echo ""
echo "✅ Package published successfully!"
echo "View at: https://pypi.org/project/abir-guard/"
echo ""
echo "Install with: pip install abir-guard"
