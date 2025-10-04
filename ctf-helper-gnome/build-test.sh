#!/bin/bash
# Quick build script to test Cryptea compilation
# This does NOT install, just builds to verify everything works

set -e

echo "=== Cryptea Build Test ==="
echo ""

echo "Step 1: Cleaning previous build..."
if [ -d "builddir-test" ]; then
    rm -rf builddir-test
fi

echo ""
echo "Step 2: Configuring with Meson..."
meson setup builddir-test --prefix=/tmp/cryptea-test

echo ""
echo "Step 3: Compiling..."
meson compile -C builddir-test

echo ""
echo "=== Build Successful! ==="
echo ""
echo "The build completed without errors."
echo "To install, use one of the installation scripts:"
echo "  - sudo ./install.sh (system-wide)"
echo "  - ./install-user.sh (user directory, no sudo)"
echo ""
