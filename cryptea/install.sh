#!/bin/bash
# Cryptea Installation Script for Fedora
# This script will build and install Cryptea system-wide

set -e

echo "=== Cryptea Installation Script ==="
echo ""

# Run dependency checker first
if [ -f "check_dependencies.py" ]; then
    echo "Checking system dependencies..."
    python3 check_dependencies.py
    check_result=$?
    if [ $check_result -ne 0 ]; then
        echo ""
        echo "Please install missing required dependencies before proceeding."
        exit 1
    fi
    echo ""
    read -p "Press Enter to continue with installation..."
    echo ""
fi

# Check if running on Fedora
if [ ! -f /etc/fedora-release ]; then
    echo "Warning: This script is designed for Fedora. Continue anyway? (y/n)"
    read -r response
    if [ "$response" != "y" ]; then
        exit 1
    fi
fi

# Check for sudo
if [ "$EUID" -ne 0 ]; then 
    echo "This script requires sudo privileges for system-wide installation."
    echo "Please run with: sudo ./install.sh"
    exit 1
fi

echo "Step 1: Installing system dependencies..."
dnf install -y \
    meson \
    ninja-build \
    python3-devel \
    python3-pip \
    gtk4-devel \
    libadwaita-devel \
    python3-gobject \
    gobject-introspection-devel \
    desktop-file-utils \
    appstream

echo ""
echo "Step 2: Installing Python dependencies..."
dnf install -y \
    python3-cryptography \
    python3-pycryptodome \
    python3-markdown2 \
    python3-pynacl || {
    echo "Some Python packages not available in DNF, installing via pip..."
    pip3 install markdown2 PyNaCl cryptography
}

echo ""
echo "Step 3: Configuring build with Meson..."
if [ -d "builddir" ]; then
    echo "Removing existing build directory..."
    rm -rf builddir
fi
meson setup builddir --prefix=/usr/local

echo ""
echo "Step 4: Compiling..."
meson compile -C builddir

echo ""
echo "Step 5: Installing..."
meson install -C builddir

echo ""
echo "Step 6: Updating desktop database and icon cache..."
update-desktop-database /usr/local/share/applications 2>/dev/null || true
gtk4-update-icon-cache /usr/local/share/icons/hicolor 2>/dev/null || true

echo ""
echo "=== Installation Complete! ==="
echo ""
echo "You can now launch Cryptea by:"
echo "  1. Searching for 'Cryptea' in your application menu"
echo "  2. Running 'ctf-helper' in a terminal"
echo ""
echo "To uninstall, run: sudo ninja -C builddir uninstall"
echo ""
