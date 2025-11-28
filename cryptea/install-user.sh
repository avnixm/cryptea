#!/bin/bash
# Cryptea User Installation Script for Fedora
# This script will build and install Cryptea to your home directory (no sudo required)

set -e

echo "=== Cryptea User Installation Script ==="
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

echo "Step 1: Checking system dependencies..."
echo "The following packages should be installed (you may need sudo for this):"
echo "  - meson, ninja-build, python3-devel, gtk4-devel, libadwaita-devel"
echo ""
echo "Install them? This requires sudo. (y/n)"
read -r response
if [ "$response" = "y" ]; then
    sudo dnf install -y \
        meson \
        ninja-build \
        python3-devel \
        gtk4-devel \
        libadwaita-devel \
        python3-gobject \
        desktop-file-utils
fi

echo ""
echo "Step 2: Installing Python dependencies to user directory..."
# Install core dependencies first
pip3 install --user markdown2 PyNaCl cryptography pycryptodome psutil pwntools

# Install angr separately (optional, requires build tools)
echo ""
echo "Installing angr (optional, may require build tools)..."
echo "This will require cmake, gcc, gcc-c++, and make if not already installed."
echo "Install angr? This may take 5-10 minutes due to unicorn compilation. (y/n)"
read -r install_angr
if [ "$install_angr" = "y" ]; then
    echo "Installing build dependencies (requires sudo)..."
    sudo dnf install -y cmake gcc gcc-c++ python3-devel make 2>/dev/null || {
        echo "⚠ Could not install all build dependencies. angr installation may fail."
    }
    echo "Installing unicorn-engine (dependency of angr)..."
    pip3 install --user unicorn-engine 2>/dev/null || {
        echo "⚠ Warning: unicorn-engine installation failed"
        echo "  This is required for angr. You may need to install more build dependencies."
    }
    echo "Installing angr..."
    pip3 install --user angr 2>/dev/null || {
        echo "⚠ Warning: angr installation failed (requires unicorn compilation)"
        echo "  The application will work without angr, but the Angr Helper tool won't be available."
        echo "  To install later, run:"
        echo "    sudo dnf install cmake gcc gcc-c++ python3-devel make"
        echo "    pip3 install --user unicorn-engine angr"
    }
else
    echo "Skipping angr installation. You can install it later with:"
    echo "  sudo dnf install cmake gcc gcc-c++ python3-devel make"
    echo "  pip3 install --user unicorn-engine angr"
fi

echo ""
echo "Step 2b: Optional network tooling"
echo "The following command-line tools power many automation modules:"
echo "  nmap sqlmap hydra medusa wfuzz commix arjun sublist3r crackmapexec"
echo "Install them with your package manager (e.g., sudo dnf install …) if you plan to use the related tools."

echo ""
echo "Step 3: Configuring build with Meson..."
if [ -d "builddir-user" ]; then
    echo "Removing existing build directory..."
    rm -rf builddir-user
fi
meson setup builddir-user --prefix="$HOME/.local"

echo ""
echo "Step 4: Compiling..."
meson compile -C builddir-user

echo ""
echo "Step 5: Installing to $HOME/.local..."
meson install -C builddir-user

echo ""
echo "Step 6: Updating desktop database and icon cache..."
update-desktop-database ~/.local/share/applications 2>/dev/null || true
gtk4-update-icon-cache ~/.local/share/icons/hicolor 2>/dev/null || true

echo ""
echo "Step 7: Checking PATH..."
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "Adding ~/.local/bin to PATH..."
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    echo "Please run: source ~/.bashrc"
    echo "Or restart your terminal."
fi

echo ""
echo "=== Installation Complete! ==="
echo ""
echo "You can now launch Cryptea by:"
echo "  1. Searching for 'Cryptea' in your application menu"
echo "  2. Running 'ctf-helper' in a terminal (after reloading PATH)"
echo ""
echo "To uninstall, run: ninja -C builddir-user uninstall"
echo ""
