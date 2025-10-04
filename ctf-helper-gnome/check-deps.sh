#!/bin/bash
# Dependency checker for Cryptea build

echo "=== Cryptea Dependency Checker ==="
echo ""

missing=()

# Check for build tools
echo "Checking build tools..."
command -v meson >/dev/null 2>&1 || missing+=("meson")
command -v ninja >/dev/null 2>&1 || missing+=("ninja-build")
command -v python3 >/dev/null 2>&1 || missing+=("python3-devel")
command -v pkg-config >/dev/null 2>&1 || missing+=("pkg-config")

# Check for GTK4/Libadwaita
echo "Checking GTK4 libraries..."
pkg-config --exists gtk4 2>/dev/null || missing+=("gtk4-devel")
pkg-config --exists libadwaita-1 2>/dev/null || missing+=("libadwaita-devel")

# Check for Python GObject
echo "Checking Python bindings..."
python3 -c "import gi" 2>/dev/null || missing+=("python3-gobject")

# Check for Python packages
echo "Checking Python dependencies..."
python3 -c "import cryptography" 2>/dev/null || echo "  ⚠ python3-cryptography missing (can install via pip)"
python3 -c "import markdown2" 2>/dev/null || echo "  ⚠ markdown2 missing (can install via pip)"
python3 -c "import nacl" 2>/dev/null || echo "  ⚠ PyNaCl missing (can install via pip)"
python3 -c "import Crypto" 2>/dev/null || echo "  ⚠ pycryptodome missing (can install via pip)"

echo ""
if [ ${#missing[@]} -eq 0 ]; then
    echo "✓ All required build dependencies are installed!"
    echo ""
    echo "You can now build with:"
    echo "  ./build-test.sh        # Test build only"
    echo "  ./install-user.sh      # Install to ~/.local"
    echo "  sudo ./install.sh      # Install system-wide"
else
    echo "✗ Missing required packages:"
    for pkg in "${missing[@]}"; do
        echo "  - $pkg"
    done
    echo ""
    echo "To install missing packages, run:"
    echo "  sudo dnf install -y ${missing[*]}"
fi
echo ""
