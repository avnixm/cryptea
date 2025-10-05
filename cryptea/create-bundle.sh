#!/bin/bash
# Create a distributable Flatpak bundle for Cryptea
# This creates a single .flatpak file that can be shared with users

set -e

echo "=== Cryptea Flatpak Bundle Creator ==="
echo ""

# Check if flatpak-builder is installed
if ! command -v flatpak-builder &> /dev/null; then
    echo "Error: flatpak-builder is not installed."
    echo ""
    echo "Install it with:"
    echo "  Fedora: sudo dnf install flatpak-builder"
    echo "  Ubuntu: sudo apt install flatpak-builder"
    echo "  Arch:   sudo pacman -S flatpak-builder"
    exit 1
fi

# Check if GNOME runtime is installed
if ! flatpak info org.gnome.Platform//47 &> /dev/null; then
    echo "Installing GNOME 47 runtime and SDK..."
    flatpak install -y flathub org.gnome.Platform//47 org.gnome.Sdk//47
fi

# Output filename with version
VERSION=$(grep -E '^version\s*=' pyproject.toml | sed 's/.*=\s*"\(.*\)".*/\1/' || echo "1.0.0")
OUTPUT="cryptea-${VERSION}-$(date +%Y%m%d).flatpak"

echo "Creating distributable bundle..."
echo "Version: $VERSION"
echo "Output file: $OUTPUT"
echo ""

# Clean previous builds
if [ -d "repo" ]; then
    echo "Cleaning previous repository..."
    rm -rf repo
fi

if [ -d "flatpak-build" ]; then
    echo "Cleaning previous build..."
    rm -rf flatpak-build
fi

if [ -d ".flatpak-builder" ]; then
    echo "Cleaning builder cache..."
    rm -rf .flatpak-builder
fi

# Step 1: Build and export to repository
echo ""
echo "Step 1: Building Flatpak and exporting to repository..."
echo "This may take several minutes..."
echo ""
flatpak-builder --repo=repo --force-clean flatpak-build org.avnixm.Cryptea.yaml

# Step 2: Create bundle
echo ""
echo "Step 2: Creating distributable bundle..."
flatpak build-bundle repo "$OUTPUT" org.avnixm.Cryptea

# Get bundle info
BUNDLE_SIZE=$(du -h "$OUTPUT" | cut -f1)
BUNDLE_SIZE_MB=$(du -m "$OUTPUT" | cut -f1)

echo ""
echo "=========================================="
echo "=== Bundle Created Successfully! ==="
echo "=========================================="
echo ""
echo "📦 File: $OUTPUT"
echo "📊 Size: $BUNDLE_SIZE (${BUNDLE_SIZE_MB}MB)"
echo "🆔 App ID: org.avnixm.Cryptea"
echo "📌 Version: $VERSION"
echo ""
echo "✅ This bundle includes:"
echo "   • Cryptea application"
echo "   • radare2, binwalk, exiftool, zbar, ffmpeg"
echo "   • Python dependencies"
echo "   • GNOME runtime (referenced, not bundled)"
echo ""
echo "📤 To distribute:"
echo "   1. Upload to GitHub releases"
echo "   2. Share on your website"
echo "   3. Distribute via download link"
echo ""
echo "👥 Users can install with ONE command:"
echo "   flatpak install $OUTPUT"
echo ""
echo "   Or simply double-click the file!"
echo ""
echo "🧪 To test installation locally:"
echo "   flatpak install --user $OUTPUT"
echo ""
