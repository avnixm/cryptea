# CRYPTEA

<div align="center">

![Cryptea Logo](data/icons/org.avnixm.Cryptea.svg)

**100% Offline CTF Challenge Manager & Security Toolkit**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv### Quick Install (Fedora)

```bash
# Clone ### Ubuntu/Debian

```bash
# Clone re### Arch Linux

```bash
# Clone repository first
git clone https://github.com/avnixm/cryptea.git
cd cryptea

# Check dependencies (recommended - shows what's missing)
python3 check_dependencies.py

# Install system dependencies
sudo pacman -S python python-pip python-gobject gtk4 libadwaita meson

# Install optional tools (for full functionality)
sudo pacman -S hashcat john-jumbo radare2 gdb binutils binwalk \
               perl-image-exiftool zbar ffmpeg sox nmap

# Build and installt
git clone https://github.com/avnixm/cryptea.git
cd cryptea

# Check dependencies (recommended - shows what's missing)
python3 check_dependencies.py

# Install system dependencies
sudo apt install python3 python3-pip python3-gi gir1.2-gtk-4.0 \
                 gir1.2-adw-1 meson ninja-build

# Install optional tools (for full functionality)
sudo apt install hashcat john radare2 gdb binutils binwalk exiftool \
                 zbar-tools ffmpeg sox nmap

# Build and installst
git clone https://github.com/avnixm/cryptea.git
cd cryptea

# Check dependencies (recommended - shows what's missing)
python3 check_dependencies.py

# Install system dependencies
sudo dnf install python3 python3-pip python3-gobject gtk4 libadwaita meson

# Install optional tools (for full functionality)
sudo dnf install hashcat john ghidra radare2 gdb binutils binwalk \
                 exiftool zbar ffmpeg sox nmap

# Build and installCENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![GTK 4](https://img.shields.io/badge/GTK-4-green.svg)](https://www.gtk.org/)
[![Libadwaita](https://img.shields.io/badge/Libadwaita-1.2+-purple.svg)](https://gnome.pages.gitlab.gnome.org/libadwaita/)

[Features](#-features) • [Installation](#-installation) • [Tools](#-available-tools) • [Usage](#-usage) • [Development](#-development)

</div>

---

## 📖 Overview

**Cryptea** is a 100% offline desktop application for Capture The Flag (CTF) challenge management and security tool integration. Built with GTK4 and Libadwaita, it provides a modern, native Linux experience for CTF players and security researchers who need a secure, air-gapped environment.

### Why Cryptea?

- 🔒 **100% Offline** - No network access, no telemetry, no external dependencies
- 🛡️ **Air-Gap Safe** - Perfect for sensitive security research and exam environments
- 🎯 **CTF Focused** - Built specifically for capture-the-flag workflows
- 🧰 **40+ Tools** - Comprehensive offline security toolkit
- 📝 **Note Taking** - Integrated Markdown editor with live preview
- 💾 **Local Storage** - SQLite database, no cloud dependencies

---

## 🌟 Features

### 🔒 Offline Operation
- **No network access** - Works completely air-gapped
- **No telemetry** - Your data stays local  
- **No external dependencies** at runtime
- Perfect for sensitive environments and exam scenarios

### �� Challenge Management
- Create and organize CTF challenges by project, category, and difficulty
- Track status: Not Started → In Progress → Completed
- Store flags securely in local SQLite database
- Rich metadata: title, description, tags, difficulty levels
- Search and filter challenges instantly
- Mark favorites for quick access

### 📝 Integrated Note Taking
- Built-in Markdown editor with live preview
- Auto-save functionality (no data loss)
- Syntax highlighting support
- Quick access to challenge-specific notes
- Export notes as part of challenge packs

### 📎 Screenshot & Attachment Manager
- **Take screenshots** directly from challenge view
- **Attach files** (PCAPs, screenshots, logs, exploits)
- **Image previews** with inline thumbnails
- **Organize by challenge** - all files automatically categorized
- **Offline storage** in `~/.local/share/cryptea/attachments/`
- **File management** - view, delete, rename, export
- **Security validated** - file type and size restrictions
- **Multi-tool support** - grim (Wayland), gnome-screenshot (X11), scrot (fallback)

### 📦 Import/Export
- Export challenges as \`.ctfpack\` files
- Import challenge packs from other installations
- Air-gap compatible file format
- Share writeups or backup work safely

### 🎨 Modern UI
- Built with GTK4 and Libadwaita
- Native GNOME experience
- Dark mode support (follows system theme)
- Responsive design
- Keyboard shortcuts for power users

---

## 🛠️ Available Tools

Cryptea includes **40+ offline security tools** organized by category:

<details>
<summary><b>🔐 Crypto & Encoding (10 tools)</b></summary>

| Tool | Description |
|------|-------------|
| **Caesar Cipher** | Encrypt, decrypt, or brute force Caesar shifts |
| **Vigenère Cipher** | Classical polyalphabetic cipher with autokey support |
| **Morse Decoder** | Text and audio Morse code decoding |
| **XOR Analyzer** | Keystream recovery from known-plaintext attacks |
| **RSA Toolkit** | Modulus analysis, small-e attacks, and key recovery |
| **Decoder Workbench** | Chain multiple encodings (Base64, Hex, ROT13, URL, Gzip, XOR) |
| **Hash Suite** | Complete hash management workspace with identification and cracking |
| **Hash Digest** | Compute message digests using Python's hashlib |
| **Hash Identifier** | Quick hash type identification |
| **htpasswd Generator** | Generate Apache htpasswd entries |

</details>

<details>
<summary><b>🔍 Forensics (6 tools)</b></summary>

| Tool | Description |
|------|-------------|
| **PCAP Viewer** | Summarize PCAP/PCAPNG captures and conversations |
| **Timeline Builder** | Generate file timestamp timelines (CSV/JSON) |
| **Disk Image Tools** | Parse partition tables and layouts |
| **Memory Analyzer** | Scan memory dumps for suspicious strings |
| **File Inspector** | Analyze file metadata, hashes, and magic bytes |
| **Binwalk** | Firmware analysis and extraction |

</details>

<details>
<summary><b>🔧 Reverse Engineering (10 tools)</b></summary>

| Tool | Description |
|------|-------------|
| **PE/ELF Inspector** | Inspect headers, sections, and security flags |
| **Quick Disassembly** | Disassemble code using objdump/radare2/rizin |
| **EXE Decompiler** | Decompile executables to C-like pseudocode (Ghidra/Rizin) |
| **Disassembler Launcher** | Launch Ghidra, IDA, Cutter, or rizin |
| **ROP Gadget Finder** | Find ROP gadgets in binaries |
| **Binary Diff** | Compare binaries via radiff2 or hash |
| **Extract Strings** | Run strings utility on binaries |
| **GDB Runner** | Execute scripted GDB sessions |
| **Radare/Rizin Console** | Run scripted rizin/radare2 commands |
| **objdump Viewer** | View disassembly and sections |

</details>

<details>
<summary><b>🖼️ Media Analysis (5 tools)</b></summary>

| Tool | Description |
|------|-------------|
| **EXIF Metadata Viewer** | Inspect photo metadata and GPS data |
| **Image Stego Toolkit** | Run zsteg, steghide, stegsolve |
| **QR/Barcode Scanner** | Scan for QR codes and barcodes |
| **Audio Analyzer** | Detect DTMF tones and Morse beeps |
| **Video Frame Exporter** | Export video frames at intervals |

</details>

<details>
<summary><b>🌐 Web Exploitation (7 tools)</b></summary>

| Tool | Description |
|------|-------------|
| **Directory Discovery** | Directory bruteforcing with SecLists |
| **JWT Tool** | Decode, verify, and tamper with JWTs |
| **XSS Tester** | Test for reflected XSS payloads |
| **SQLi Tester** | Test SQL injection vulnerabilities |
| **File Upload Tester** | Generate upload bypass payloads |
| **Payload Library** | Browse curated payload examples |
| **OWASP ZAP** | Launch and manage ZAP proxy |

</details>

<details>
<summary><b>🌐 Network (2 tools)</b></summary>

| Tool | Description |
|------|-------------|
| **Nmap** | Run local network scans (opt-in) |
| **nping** | Send crafted packets (opt-in) |

</details>

<details>
<summary><b>🔑 Password Tools (2 tools)</b></summary>

| Tool | Description |
|------|-------------|
| **Wordlist Generator** | Generate custom wordlists and permutations |
| **Hash Cracker** | Multi-algorithm password cracking |

</details>

---

## 📥 Installation

### Option 1: Standalone Flatpak Bundle (Easiest!)

**Download and install a single file** - no build tools or source code needed!

#### For Users:

1. **Download** `cryptea-VERSION.flatpak` from [Releases](https://github.com/avnixm/cryptea/releases)
2. **Install** with one command:
   ```bash
   flatpak install cryptea-1.0.0-20251005.flatpak
   ```
   Or just **double-click** the file!

3. **Run** from your application menu or:
   ```bash
   flatpak run org.avnixm.Cryptea
   ```

**What's included:** Application + radare2 + binwalk + exiftool + zbar + ffmpeg (~500MB)

See [FLATPAK_BUNDLE.md](FLATPAK_BUNDLE.md) for detailed bundle installation guide.

#### For Developers (Creating Bundle):

```bash
# Clone repository
git clone https://github.com/avnixm/cryptea.git
cd cryptea

# Create distributable bundle
./create-bundle.sh

# This creates: cryptea-VERSION-DATE.flatpak
# Share this single file with users!
```

### Option 2: Build Flatpak from Source

Build and install locally for development:

```bash
# Clone repository
git clone https://github.com/avnixm/cryptea.git
cd cryptea

# Build and install
./build-flatpak.sh

# Run
flatpak run org.avnixm.Cryptea
```

**Advantages:**
- ✅ Sandboxed and secure
- ✅ Includes radare2, binwalk, exiftool, zbar, and ffmpeg
- ✅ Works across all Linux distributions
- ✅ Easy to update and remove

See [FLATPAK.md](FLATPAK.md) for detailed Flatpak documentation.

### 📚 Feature Documentation

- **[Attachment Manager](ATTACHMENT_MANAGER.md)** - Complete guide for screenshots and file attachments
- **[Performance Optimization](PERFORMANCE_OPTIMIZATION.md)** - System performance tuning
- **[Flatpak Packaging](FLATPAK.md)** - Distribution and installation

---

### Option 3: System Installation

For development or system-wide installation:

#### Prerequisites

**Required:**
- Python 3.11 or higher
- GTK 4.6+
- Libadwaita 1.2+
- PyGObject (python3-gobject)
- Meson build system
- SQLite 3

**Optional (for specific tools):**
- \`hashcat\` - GPU-accelerated hash cracking
- \`john\` - Password cracking
- \`ghidra\` - Advanced reverse engineering
- \`radare2\` or \`rizin\` - Binary analysis
- \`gdb\` - Debugging
- \`objdump\` - Disassembly
- \`binwalk\` - Firmware analysis
- \`strings\` - String extraction
- \`exiftool\` - EXIF metadata
- \`zsteg\` - PNG/BMP steganography
- \`steghide\` - JPEG steganography
- `zbarimg` - QR/barcode scanning
- `ffmpeg` - Video frame extraction
- `sox` - Audio analysis
- `nmap` - Network scanning (local only)

#### Quick Install (Fedora)

\`\`\`bash
# Install system dependencies
sudo dnf install python3 python3-pip python3-gobject gtk4 libadwaita meson

# Install optional tools
sudo dnf install hashcat john ghidra radare2 gdb binutils binwalk \\
                 exiftool zbar ffmpeg sox nmap

# Clone repository
git clone https://github.com/avnixm/cryptea.git
cd cryptea

# Build and install
meson setup builddir-user --prefix=$HOME/.local
meson compile -C builddir-user
meson install -C builddir-user

# Add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Launch
cryptea
```

#### Ubuntu/Debian

```bash
# Install system dependencies
sudo apt install python3 python3-pip python3-gi gir1.2-gtk-4.0 \\
                 gir1.2-adw-1 meson ninja-build

# Install optional tools
sudo apt install hashcat john radare2 gdb binutils binwalk exiftool \\
                 zbar-tools ffmpeg sox nmap

# Clone and build (same as Fedora)
git clone https://github.com/avnixm/cryptea.git
cd cryptea
meson setup builddir-user --prefix=$HOME/.local
meson compile -C builddir-user
meson install -C builddir-user
```

#### Arch Linux

```bash
# Install system dependencies
sudo pacman -S python python-pip python-gobject gtk4 libadwaita meson

# Install optional tools
sudo pacman -S hashcat john-jumbo radare2 gdb binutils binwalk \\
               perl-image-exiftool zbar ffmpeg sox nmap

# Clone and build
git clone https://github.com/avnixm/cryptea.git
cd cryptea
meson setup builddir-user --prefix=$HOME/.local
meson compile -C builddir-user
meson install -C builddir-user
```

#### Running from Source

```bash
# Clone repository
git clone https://github.com/avnixm/cryptea.git
cd cryptea

# Run directly (no installation required)
python3 run.py
\`\`\`

---

## 🚀 Usage

### Quick Start

1. **Launch Application**
   \`\`\`bash
   cryptea
   \`\`\`
   Or search for "Cryptea" in your application menu.

2. **Create a Challenge**
   - Click the **"+ Add Challenge"** button
   - Fill in details: Title, Project, Category, Difficulty
   - Add description and flag when found
   - Auto-saves as you type

3. **Take Notes**
   - Click on any challenge
   - Scroll to Notes section
   - Write in Markdown format
   - Auto-saves every few seconds

4. **Use Tools**
   - Click **"Tools"** in sidebar
   - Browse categories or search
   - Click any tool to open
   - Enter data and click **Run**
   - Copy results with **Copy** button

5. **Search & Filter**
   - Use search bar for instant filtering
   - Click status badges (In Progress, Completed)
   - Star challenges to mark as favorites

6. **Export/Import**
   - Click settings gear → **Export .ctfpack**
   - Choose location to save
   - To import: settings gear → **Import .ctfpack**

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| \`Ctrl+N\` | Create new challenge |
| \`Ctrl+F\` | Focus search bar |
| \`Ctrl+W\` | Close window |
| \`Ctrl+Q\` | Quit application |

---

## 📂 Data Storage

All data is stored locally:

| Data Type | Location |
|-----------|----------|
| **Challenges & Flags** | \`~/.local/share/cryptea/db.sqlite3\` |
| **Notes** | Stored in database with challenges |
| **Logs** | \`~/.local/share/cryptea/logs/cryptea.log\` |
| **Config** | \`~/.config/cryptea/\` |
| **Application Files** | \`~/.local/lib/python3.*/site-packages/ctf_helper/\` |
| **Executable** | \`~/.local/bin/cryptea\` |

### Backup Your Data

\`\`\`bash
# Backup database
cp ~/.local/share/cryptea/db.sqlite3 ~/cryptea-backup.db

# Or use the built-in Export feature
# Settings → Export .ctfpack
\`\`\`

---

## 🏗️ Development

### Project Structure

\`\`\`
cryptea/
├── src/
│   ├── main.py                    # Entry point
│   └── ctf_helper/
│       ├── application.py         # Main UI and logic
│       ├── config.py              # Configuration
│       ├── db.py                  # Database interface
│       ├── logger.py              # Logging
│       ├── manager/               # Challenge management
│       ├── modules/               # Tool modules
│       │   ├── crypto/            # Cryptography tools
│       │   ├── forensics/         # Forensics tools
│       │   ├── reverse/           # Reverse engineering
│       │   ├── stego/             # Steganography
│       │   ├── web/               # Web exploitation
│       │   └── network/           # Network tools
│       ├── notes/                 # Note management
│       └── templates/             # Templates
├── data/
│   ├── org.avnixm.Cryptea.desktop # Desktop entry
│   ├── style.css                  # Custom styling
│   ├── icons/                     # App icons
│   ├── help/                      # Documentation
│   ├── templates/                 # Challenge templates
│   └── SecLists/                  # Wordlists
├── tests/                         # Unit tests
├── meson.build                    # Build config
├── pyproject.toml                 # Python metadata
└── README.md                      # This file
\`\`\`

### Running Tests

\`\`\`bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/

# Run with coverage
pytest --cov=ctf_helper tests/
\`\`\`

### Adding a New Tool

1. Create module in \`src/ctf_helper/modules/<category>/\`
2. Inherit from \`BaseOfflineTool\`
3. Implement \`run()\` method
4. Register in \`__init__.py\`
5. Add UI integration in \`application.py\`

Example:

\`\`\`python
from ctf_helper.modules.base import BaseOfflineTool

class MyTool(BaseOfflineTool):
    name = "My Tool"
    category = "Crypto"
    description = "Does something useful"
    
    def run(self, input_data: str) -> str:
        # Tool logic here
        return f"Result: {input_data}"
\`\`\`

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| \`CRYPTEA_SUPPRESS_SANDBOX_WARNING\` | Disable network warnings | \`0\` |
| \`OFFLINE_BUILD\` | Enable offline build mode | \`0\` |
| \`DEV_PROFILE_ENABLED\` | Enable dev seeding | \`0\` |

---

## 🐛 Troubleshooting

### Application won't start

\`\`\`bash
# Check logs
tail -f ~/.local/share/cryptea/logs/cryptea.log

# Verify installation
which cryptea
python3 -c "import ctf_helper; print(ctf_helper.__file__)"
\`\`\`

### Database errors

\`\`\`bash
# Check database integrity
sqlite3 ~/.local/share/cryptea/db.sqlite3 "PRAGMA integrity_check;"

# Reset database (WARNING: deletes all data)
rm ~/.local/share/cryptea/db.sqlite3
# Restart application to recreate
\`\`\`

### Tools not working

\`\`\`bash
# Check if tool is installed
which hashcat
which ghidra
which radare2

# Check logs for errors
tail -f ~/.local/share/cryptea/logs/cryptea.log
\`\`\`

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create feature branch (\`git checkout -b feature/amazing-feature\`)
3. Make changes and add tests
4. Run tests (\`pytest tests/\`)
5. Commit changes (\`git commit -m 'Add amazing feature'\`)
6. Push to branch (\`git push origin feature/amazing-feature\`)
7. Open Pull Request

### Code Style

- Follow PEP 8 for Python code
- Use type hints where possible
- Add docstrings to public functions
- Keep functions focused and small
- Write tests for new features

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later).

See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **SecLists** - Daniel Miessler's wordlist collection
- **GTK** and **Libadwaita** - UI framework
- **PyGObject** - Python bindings for GTK
- All open-source security tools integrated

---

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/avnixm/cryptea/issues)
- **Discussions**: [GitHub Discussions](https://github.com/avnixm/cryptea/discussions)

---

## 🗺️ Roadmap

- [ ] Plugin system for custom tools
- [ ] Team collaboration mode (air-gap compatible)
- [ ] Challenge templates library
- [ ] Advanced filtering and sorting
- [ ] Statistics and progress tracking
- [ ] Export to PDF reports
- [ ] Encrypted database option
- [ ] Multi-language support

---

## ⚠️ Security Notice

Cryptea is designed for **educational purposes** and **ethical security research** only. Always:

- Obtain proper authorization before testing systems
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Use in isolated/lab environments when appropriate

**The developers are not responsible for misuse of this software.**

---

<div align="center">

**Made with ❤️ for the CTF and security research community**

</div>
