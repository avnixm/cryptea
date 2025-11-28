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
DEP_CHECK_RESULT=0
if [ -f "check_dependencies.py" ]; then
    python3 check_dependencies.py || DEP_CHECK_RESULT=$?
fi

# Function to check if Python package is installed
check_python_package() {
    python3 -c "import $1" 2>/dev/null
}

# Check for required Python packages
echo ""
echo "Checking Python dependencies..."
# Map display names to import names
declare -A PYTHON_PACKAGES=(
    ["markdown2"]="markdown2"
    ["PyNaCl"]="nacl"
    ["cryptography"]="cryptography"
    ["pycryptodome"]="Crypto"
    ["psutil"]="psutil"
    ["angr"]="angr"
    ["pwntools"]="pwn"
)

MISSING_PYTHON_PACKAGES=()

for display_name in "${!PYTHON_PACKAGES[@]}"; do
    import_name="${PYTHON_PACKAGES[$display_name]}"
    if ! check_python_package "$import_name"; then
        MISSING_PYTHON_PACKAGES+=("$display_name")
    fi
done

# Check for CLI-based network tools
NETWORK_TOOLS=(nmap sqlmap hydra medusa wfuzz commix arjun sublist3r crackmapexec)
MISSING_NETWORK_TOOLS=()

for tool in "${NETWORK_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        MISSING_NETWORK_TOOLS+=("$tool")
    fi
done

# Check if meson is available or Python packages are missing
if ! command -v meson >/dev/null 2>&1 || [ ${#MISSING_PYTHON_PACKAGES[@]} -ne 0 ] || [ ${#MISSING_NETWORK_TOOLS[@]} -ne 0 ]; then
    echo ""
    if ! command -v meson >/dev/null 2>&1; then
        echo "⚠ Build dependencies are missing (meson, ninja, etc.)"
    fi
    if [ ${#MISSING_PYTHON_PACKAGES[@]} -ne 0 ]; then
        echo "⚠ Missing Python packages: ${MISSING_PYTHON_PACKAGES[*]}"
    fi
    if [ ${#MISSING_NETWORK_TOOLS[@]} -ne 0 ]; then
        echo "⚠ Missing command-line tools: ${MISSING_NETWORK_TOOLS[*]}"
    fi
    echo ""
    echo "Would you like to install all missing dependencies now? This requires sudo. (y/n)"
    read -r response
    if [ "$response" = "y" ]; then
        if ! command -v meson >/dev/null 2>&1; then
            echo ""
            echo "Installing build dependencies..."
            sudo dnf install -y meson ninja-build python3-devel \
                gtk4-devel libadwaita-devel python3-gobject \
                desktop-file-utils appstream
        fi
        
        if [ ${#MISSING_PYTHON_PACKAGES[@]} -ne 0 ]; then
            echo ""
            echo "Installing Python dependencies..."
            # Install core dependencies first (required)
            pip3 install --user markdown2 PyNaCl cryptography pycryptodome psutil pwntools 2>/dev/null || {
                sudo dnf install -y python3-cryptography python3-pycryptodome \
                    python3-markdown2 python3-pynacl python3-psutil python3-pwntools 2>/dev/null || true
            }
            
            # Install angr separately with build dependencies (optional)
            if [[ " ${MISSING_PYTHON_PACKAGES[@]} " =~ " angr " ]]; then
                echo ""
                echo "Installing angr (optional, this requires build tools and may take 5-10 minutes)..."
                echo "Installing unicorn build dependencies..."
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
            fi
        fi
        if [ ${#MISSING_NETWORK_TOOLS[@]} -ne 0 ]; then
            echo ""
            echo "Installing network tooling (may skip unavailable packages)..."
            if ! sudo dnf install -y "${MISSING_NETWORK_TOOLS[@]}"; then
                echo "Some tools could not be installed automatically. Please install manually: ${MISSING_NETWORK_TOOLS[*]}"
            fi
        fi
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
