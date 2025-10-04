# Building Cryptea for Fedora

This guide covers building and packaging Cryptea as a native Fedora application.

## Quick Start

### Option 1: User Installation (Recommended for Testing)
```bash
./install-user.sh
```
This installs to `~/.local` without requiring root privileges.

### Option 2: System-wide Installation
```bash
sudo ./install.sh
```
This installs to `/usr/local` and makes the app available for all users.

### Option 3: Just Test the Build
```bash
./build-test.sh
```
This only compiles without installing, useful for testing.

## Manual Build Steps

If you prefer to build manually:

### 1. Install Dependencies

```bash
sudo dnf install -y \
    meson ninja-build python3-devel \
    gtk4-devel libadwaita-devel python3-gobject \
    python3-cryptography python3-pycryptodome \
    python3-markdown2 python3-pynacl
```

### 2. Configure Build

**System-wide:**
```bash
meson setup builddir --prefix=/usr/local
```

**User installation:**
```bash
meson setup builddir --prefix=$HOME/.local
```

### 3. Compile

```bash
meson compile -C builddir
```

### 4. Install

**System-wide:**
```bash
sudo meson install -C builddir
```

**User installation:**
```bash
meson install -C builddir
```

### 5. Update Caches

**System-wide:**
```bash
sudo update-desktop-database /usr/local/share/applications
sudo gtk4-update-icon-cache /usr/local/share/icons/hicolor
```

**User installation:**
```bash
update-desktop-database ~/.local/share/applications
gtk4-update-icon-cache ~/.local/share/icons/hicolor
```

## Creating an RPM Package

For distribution or deployment to multiple systems:

### 1. Install RPM Build Tools

```bash
sudo dnf install -y rpm-build rpmdevtools
rpmdev-setuptree
```

### 2. Prepare Source Tarball

```bash
cd /home/avnixm/Documents/cryptea
tar czf ~/rpmbuild/SOURCES/cryptea-0.1.0.tar.gz \
    --transform 's,^ctf-helper-gnome,ctf-helper-gnome,' \
    ctf-helper-gnome/
```

### 3. Copy Spec File

```bash
cp ctf-helper-gnome/cryptea.spec ~/rpmbuild/SPECS/
```

### 4. Build RPM

```bash
rpmbuild -ba ~/rpmbuild/SPECS/cryptea.spec
```

### 5. Install RPM

```bash
sudo dnf install ~/rpmbuild/RPMS/noarch/cryptea-0.1.0-1.fc*.noarch.rpm
```

## Build Options

Cryptea supports several build-time options:

### Development Profile
Enable debug features and additional logging:
```bash
meson setup builddir --prefix=/usr/local -Ddev-profile=true
```

### Offline Build
Build without network access (uses bundled dependencies):
```bash
meson setup builddir --prefix=/usr/local -Doffline-build=true
```

## Uninstalling

### From Meson Build

**System-wide:**
```bash
cd /path/to/source
sudo ninja -C builddir uninstall
```

**User installation:**
```bash
cd /path/to/source
ninja -C builddir uninstall
```

### From RPM
```bash
sudo dnf remove cryptea
```

## Troubleshooting

### Icon Not Showing
```bash
# System-wide
sudo gtk4-update-icon-cache -f /usr/local/share/icons/hicolor
# User
gtk4-update-icon-cache -f ~/.local/share/icons/hicolor
```

### Desktop Entry Not Found
```bash
# System-wide
sudo update-desktop-database /usr/local/share/applications
# User
update-desktop-database ~/.local/share/applications
```

### Command Not Found (ctf-helper)
For user installations, ensure `~/.local/bin` is in PATH:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Python Module Import Errors
Verify Python site-packages is accessible:
```bash
python3 -c "import ctf_helper; print(ctf_helper.__file__)"
```

### Missing Dependencies
Install all Python dependencies:
```bash
pip3 install --user markdown2 PyNaCl cryptography pycryptodome
```

## Development Build

For active development, you can run from source without installing:

```bash
python run.py
```

This is faster for iteration but won't update the system icon cache or desktop entries.

## File Locations After Installation

### System-wide (`/usr/local`):
- Binary: `/usr/local/bin/ctf-helper`
- Python modules: `/usr/local/lib/python3.*/site-packages/ctf_helper/`
- Desktop file: `/usr/local/share/applications/org.example.CTFHelper.desktop`
- Icon: `/usr/local/share/icons/hicolor/scalable/apps/org.example.CTFHelper.svg`
- Data files: `/usr/local/share/ctf-helper-gnome/`

### User installation (`~/.local`):
- Binary: `~/.local/bin/ctf-helper`
- Python modules: `~/.local/lib/python3.*/site-packages/ctf_helper/`
- Desktop file: `~/.local/share/applications/org.example.CTFHelper.desktop`
- Icon: `~/.local/share/icons/hicolor/scalable/apps/org.example.CTFHelper.svg`
- Data files: `~/.local/share/ctf-helper-gnome/`

## Clean Build

To start fresh:

```bash
rm -rf builddir builddir-user builddir-test
```

Then reconfigure and rebuild.
