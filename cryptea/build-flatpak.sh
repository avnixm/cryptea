#!/bin/bash
# Flatpak Build Script for Cryptea
# This script builds and installs Cryptea as a Flatpak package

set -e

echo "=== Cryptea Flatpak Builder ==="
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

# Clean previous builds
if [ -d "flatpak-build" ]; then
    echo "Cleaning previous build..."
    rm -rf flatpak-build
fi

if [ -d ".flatpak-builder" ]; then
    echo "Cleaning flatpak-builder cache..."
    rm -rf .flatpak-builder
fi

# Build the Flatpak
echo ""
echo "Building Flatpak package..."
flatpak-builder --force-clean --install --user flatpak-build org.avnixm.Cryptea.yaml

echo ""
echo "=== Build Complete! ==="
echo ""
echo "Cryptea has been installed as a Flatpak!"
echo ""
echo "To run it:"
echo "  flatpak run org.avnixm.Cryptea"
echo ""
echo "To uninstall:"
echo "  flatpak uninstall org.avnixm.Cryptea"
echo ""
echo "To create a bundle for distribution:"
echo "  flatpak build-bundle ~/.local/share/flatpak/repo cryptea.flatpak org.avnixm.Cryptea"
echo ""
