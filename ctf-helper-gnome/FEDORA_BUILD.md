# Cryptea - Fedora Build Summary

## What's Been Set Up

Your Cryptea application now has complete Fedora build and packaging support:

### Installation Scripts
1. **`check-deps.sh`** - Checks if all build dependencies are installed
2. **`install-user.sh`** - Installs to `~/.local` (no sudo required)
3. **`install.sh`** - Installs system-wide to `/usr/local` (requires sudo)
4. **`build-test.sh`** - Tests compilation without installing

### Documentation
1. **`BUILD.md`** - Comprehensive build instructions
2. **`INSTALL.md`** - Installation guide with troubleshooting
3. **`LICENSE`** - GPL-3.0-or-later license file

### Packaging
1. **`cryptea.spec`** - RPM spec file for creating Fedora packages

## Quick Start

### Step 1: Check Dependencies
```bash
./check-deps.sh
```

### Step 2: Install Missing Packages
If the checker shows missing packages, install them:
```bash
sudo dnf install -y meson ninja-build libadwaita-devel
```

### Step 3: Install Cryptea

**Option A: User Installation (Recommended)**
```bash
./install-user.sh
```
- Installs to `~/.local`
- No sudo required
- Only affects your user account

**Option B: System-wide Installation**
```bash
sudo ./install.sh
```
- Installs to `/usr/local`
- Requires sudo
- Available to all users

### Step 4: Launch
After installation:
- Open GNOME Activities and search for "Cryptea"
- Or run `ctf-helper` in terminal

## Current Status

**What's Working:**
- ✓ GTK4/Libadwaita application
- ✓ 40+ CTF tools across 6 categories
- ✓ Challenge management with favorites
- ✓ PCAP/PCAPNG viewer
- ✓ Custom black app icon
- ✓ Meson build system configured
- ✓ Installation scripts ready
- ✓ RPM packaging support

**Next Steps:**
1. Run `./check-deps.sh` to see what needs to be installed
2. Install missing dependencies with `dnf`
3. Run `./install-user.sh` to build and install
4. Launch and test the application

## File Structure

```
ctf-helper-gnome/
├── check-deps.sh          # Dependency checker
├── install-user.sh        # User installation script
├── install.sh             # System installation script
├── build-test.sh          # Build test script
├── BUILD.md               # Build documentation
├── INSTALL.md             # Installation guide
├── LICENSE                # GPL license
├── cryptea.spec           # RPM spec file
├── meson.build            # Main build configuration
├── pyproject.toml         # Python project metadata
├── src/                   # Source code
├── data/                  # Data files, icons, desktop entry
└── tests/                 # Test suite
```

## RPM Package Creation

For distribution:

```bash
# Install RPM tools
sudo dnf install -y rpm-build rpmdevtools
rpmdev-setuptree

# Create source tarball
cd /home/avnixm/Documents/cryptea
tar czf ~/rpmbuild/SOURCES/cryptea-0.1.0.tar.gz \
    --transform 's,^ctf-helper-gnome,ctf-helper-gnome,' \
    ctf-helper-gnome/

# Build RPM
rpmbuild -ba ~/rpmbuild/SPECS/cryptea.spec

# Install
sudo dnf install ~/rpmbuild/RPMS/noarch/cryptea-0.1.0-1.fc*.noarch.rpm
```

## Troubleshooting

### Meson Not Found
```bash
sudo dnf install -y meson ninja-build
```

### GTK4/Libadwaita Not Found
```bash
sudo dnf install -y gtk4-devel libadwaita-devel
```

### Python Dependencies Missing
```bash
pip3 install --user markdown2 PyNaCl cryptography pycryptodome
```

### Icon Not Showing After Install
```bash
# Update icon cache
gtk4-update-icon-cache -f ~/.local/share/icons/hicolor
# Or for system-wide:
sudo gtk4-update-icon-cache -f /usr/local/share/icons/hicolor
```

### Desktop Entry Not Appearing
```bash
# Update desktop database
update-desktop-database ~/.local/share/applications
# Or for system-wide:
sudo update-desktop-database /usr/local/share/applications
```

## Development Mode

To run without installing (for development):
```bash
python run.py
```

This runs directly from source and is faster for testing changes.

## Support

For detailed information, see:
- `BUILD.md` - Complete build instructions
- `INSTALL.md` - Installation guide
- `README.md` - Application features and tools
