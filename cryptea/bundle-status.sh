#!/bin/bash
# Flatpak Bundle Information Script
# Shows status of build and bundle files

echo "=== Cryptea Flatpak Bundle Status ==="
echo ""

# Check if flatpak-builder exists
if command -v flatpak-builder &> /dev/null; then
    echo "✅ flatpak-builder: $(flatpak-builder --version | head -1)"
else
    echo "❌ flatpak-builder: Not installed"
fi

# Check if flatpak exists
if command -v flatpak &> /dev/null; then
    echo "✅ flatpak: $(flatpak --version)"
else
    echo "❌ flatpak: Not installed"
fi

# Check for GNOME runtime
if flatpak info org.gnome.Platform//47 &> /dev/null 2>&1; then
    echo "✅ GNOME Platform 47: Installed"
else
    echo "❌ GNOME Platform 47: Not installed"
fi

if flatpak info org.gnome.Sdk//47 &> /dev/null 2>&1; then
    echo "✅ GNOME SDK 47: Installed"
else
    echo "❌ GNOME SDK 47: Not installed"
fi

echo ""
echo "=== Build Status ==="
echo ""

# Check for build directories
if [ -d ".flatpak-builder" ]; then
    BUILD_SIZE=$(du -sh .flatpak-builder 2>/dev/null | cut -f1)
    echo "📦 Build cache: $BUILD_SIZE (.flatpak-builder/)"
else
    echo "📦 Build cache: Not present"
fi

if [ -d "flatpak-build" ]; then
    BUILD_SIZE=$(du -sh flatpak-build 2>/dev/null | cut -f1)
    echo "🔨 Build directory: $BUILD_SIZE (flatpak-build/)"
else
    echo "🔨 Build directory: Not present"
fi

if [ -d "repo" ]; then
    REPO_SIZE=$(du -sh repo 2>/dev/null | cut -f1)
    echo "📚 Repository: $REPO_SIZE (repo/)"
else
    echo "📚 Repository: Not present"
fi

echo ""
echo "=== Existing Bundles ==="
echo ""

# Find all .flatpak files
BUNDLES=$(find . -maxdepth 1 -name "*.flatpak" -type f 2>/dev/null)

if [ -z "$BUNDLES" ]; then
    echo "📦 No .flatpak bundles found"
    echo ""
    echo "To create a bundle, run:"
    echo "  ./create-bundle.sh"
else
    while IFS= read -r bundle; do
        BUNDLE_NAME=$(basename "$bundle")
        BUNDLE_SIZE=$(du -h "$bundle" | cut -f1)
        BUNDLE_DATE=$(stat -c %y "$bundle" 2>/dev/null || stat -f %Sm "$bundle" 2>/dev/null)
        echo "📦 $BUNDLE_NAME"
        echo "   Size: $BUNDLE_SIZE"
        echo "   Created: ${BUNDLE_DATE%.*}"
        echo ""
    done <<< "$BUNDLES"
fi

# Check if Cryptea is installed
echo "=== Installation Status ==="
echo ""

if flatpak info org.avnixm.Cryptea &> /dev/null 2>&1; then
    INSTALLED_VERSION=$(flatpak info org.avnixm.Cryptea | grep "Version:" | awk '{print $2}')
    INSTALLED_SIZE=$(flatpak info org.avnixm.Cryptea | grep "Installed size:" | cut -d: -f2 | xargs)
    echo "✅ Cryptea is installed"
    echo "   Version: $INSTALLED_VERSION"
    echo "   Size: $INSTALLED_SIZE"
    echo ""
    echo "To run: flatpak run org.avnixm.Cryptea"
else
    echo "❌ Cryptea is not installed"
    echo ""
    echo "To install:"
    echo "  • From source: ./build-flatpak.sh"
    echo "  • From bundle: flatpak install <bundle.flatpak>"
fi

echo ""
echo "=== Quick Actions ==="
echo ""
echo "Build Flatpak locally:    ./build-flatpak.sh"
echo "Create bundle for users:  ./create-bundle.sh"
echo "Check bundle status:      ./bundle-status.sh"
echo "View full docs:           cat FLATPAK_BUNDLE.md"
echo ""
