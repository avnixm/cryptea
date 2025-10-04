# Installation Guide for Cryptea on Fedora

## Prerequisites

Install required system dependencies:

```bash
# Install build tools and dependencies
sudo dnf install -y \
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

# Install Python dependencies
sudo dnf install -y \
    python3-cryptography \
    python3-pycryptodome \
    python3-markdown2 \
    python3-pynacl
```

## Building and Installing

### Option 1: System-wide Installation (Recommended)

```bash
# Navigate to the project directory
cd /home/avnixm/Documents/cryptea/ctf-helper-gnome

# Configure the build
meson setup builddir --prefix=/usr/local

# Build the project
meson compile -C builddir

# Install (requires sudo)
sudo meson install -C builddir

# Update desktop database
sudo update-desktop-database /usr/local/share/applications

# Update icon cache
sudo gtk4-update-icon-cache /usr/local/share/icons/hicolor
```

After installation, you can launch Cryptea from:
- Application menu (search for "Cryptea")
- Terminal: `ctf-helper`

### Option 2: User Installation (No sudo required)

```bash
# Navigate to the project directory
cd /home/avnixm/Documents/cryptea/ctf-helper-gnome

# Configure for user installation
meson setup builddir --prefix=$HOME/.local

# Build the project
meson compile -C builddir

# Install to user directory
meson install -C builddir

# Update user desktop database
update-desktop-database ~/.local/share/applications

# Update user icon cache
gtk4-update-icon-cache ~/.local/share/icons/hicolor
```

Make sure `~/.local/bin` is in your PATH:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Launch with: `ctf-helper`

### Option 3: Development Mode (Running from source)

If you just want to run without installing:

```bash
cd /home/avnixm/Documents/cryptea/ctf-helper-gnome
python run.py
```

## Uninstalling

### System-wide:
```bash
cd /home/avnixm/Documents/cryptea/ctf-helper-gnome
sudo ninja -C builddir uninstall
```

### User installation:
```bash
cd /home/avnixm/Documents/cryptea/ctf-helper-gnome
ninja -C builddir uninstall
```

## Creating an RPM Package (Advanced)

To create a distributable RPM package:

```bash
# Install RPM build tools
sudo dnf install -y rpm-build rpmdevtools

# Create RPM build directory
rpmdev-setuptree

# Copy the spec file (once created)
cp cryptea.spec ~/rpmbuild/SPECS/

# Create source tarball
cd /home/avnixm/Documents/cryptea
tar czf ~/rpmbuild/SOURCES/cryptea-0.1.0.tar.gz ctf-helper-gnome/

# Build the RPM
rpmbuild -ba ~/rpmbuild/SPECS/cryptea.spec

# Install the RPM
sudo dnf install ~/rpmbuild/RPMS/noarch/cryptea-0.1.0-1.fc*.noarch.rpm
```

## Troubleshooting

### Icon not showing
If the icon doesn't appear after installation:
```bash
# Update icon cache
sudo gtk4-update-icon-cache -f /usr/local/share/icons/hicolor
# Or for user installation:
gtk4-update-icon-cache -f ~/.local/share/icons/hicolor
```

### Desktop file not appearing
```bash
# Update desktop database
sudo update-desktop-database /usr/local/share/applications
# Or for user installation:
update-desktop-database ~/.local/share/applications
```

### Python module not found
Make sure the Python site-packages directory is in your PYTHONPATH:
```bash
export PYTHONPATH="/usr/local/lib/python3.13/site-packages:$PYTHONPATH"
```

### Permission denied
If you get permission errors, either:
- Use `sudo` for system-wide installation
- Use user installation (Option 2) instead
