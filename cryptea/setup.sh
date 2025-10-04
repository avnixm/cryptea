#!/bin/bash
# Cryptea Quick Setup for Fedora
# This script will guide you through the entire process

set -e

echo "╔════════════════════════════════════════╗"
echo "║   Cryptea Setup for Fedora             ║"
echo "║   Offline CTF Helper Application       ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Step 1: Check dependencies
echo "Step 1: Checking dependencies..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
./check-deps.sh

# Check if meson is available
if ! command -v meson >/dev/null 2>&1; then
    echo ""
    echo "⚠ Build dependencies are missing."
    echo ""
    echo "Would you like to install them now? This requires sudo. (y/n)"
    read -r response
    if [ "$response" = "y" ]; then
        echo ""
        echo "Installing build dependencies..."
        sudo dnf install -y meson ninja-build python3-devel \
            gtk4-devel libadwaita-devel python3-gobject \
            desktop-file-utils appstream
        
        echo ""
        echo "Installing Python dependencies..."
        pip3 install --user markdown2 PyNaCl cryptography pycryptodome || {
            sudo dnf install -y python3-cryptography python3-pycryptodome \
                python3-markdown2 python3-pynacl 2>/dev/null || true
        }
    else
        echo "Please install dependencies manually and run this script again."
        exit 1
    fi
fi

# Step 2: Choose installation method
echo ""
echo "Step 2: Choose installation method"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1) User installation (~/.local) - No sudo required, only for your user"
echo "2) System-wide (/usr/local) - Requires sudo, available to all users"
echo "3) Just test the build - Don't install, only verify compilation"
echo "4) Cancel"
echo ""
echo -n "Enter your choice (1-4): "
read -r choice

case $choice in
    1)
        echo ""
        echo "Starting user installation..."
        ./install-user.sh
        ;;
    2)
        echo ""
        echo "Starting system-wide installation..."
        sudo ./install.sh
        ;;
    3)
        echo ""
        echo "Testing build..."
        ./build-test.sh
        echo ""
        echo "Build test completed successfully!"
        echo "Run this script again and choose option 1 or 2 to install."
        ;;
    4)
        echo "Setup cancelled."
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "╔════════════════════════════════════════╗"
echo "║   Setup Complete!                      ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "You can now launch Cryptea by:"
echo "  • Searching for 'Cryptea' in Activities"
echo "  • Running 'ctf-helper' in a terminal"
echo ""
echo "For user installation, you may need to reload your PATH:"
echo "  source ~/.bashrc"
echo ""
echo "Enjoy using Cryptea! 🛡️"
echo ""
