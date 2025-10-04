# Cryptea - Offline CTF Workspace# Cryptea (Offline Edition)



[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)Cryptea is a 100% offline desktop companion for Capture the Flag training. It ships challenge management, Markdown note taking, offline tool modules, and bundled documentation without ever touching the network.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

[![GTK 4](https://img.shields.io/badge/GTK-4-green.svg)](https://www.gtk.org/)## Installation



**Cryptea** is a 100% offline desktop application for Capture The Flag (CTF) challenge management and security tool integration. Built with GTK4 and Libadwaita, it provides a modern, native Linux experience for CTF players and security researchers who need a secure, air-gapped environment.### Quick Setup (Fedora)



---```bash

./setup.sh

## 🌟 Key Features```



### 🔒 **100% Offline Operation**This interactive script will check dependencies and guide you through installation.

- **No network access required** - Works completely air-gapped

- **No telemetry** - Your data stays localFor detailed instructions, see [BUILD.md](BUILD.md) and [INSTALL.md](INSTALL.md).

- **No external dependencies** at runtime

- Perfect for sensitive security research and exam environments### Running from Source



### 📊 **Challenge Management**```bash

- Create and organize CTF challenges by project, category, and difficultypython run.py

- Track challenge status (Not Started, In Progress, Completed)```

- Store flags securely in local SQLite database

- Rich metadata support (title, description, tags, difficulty levels)## Features

- Search and filter challenges instantly

- Mark challenges as favorites for quick access- **Offline-first**: No network sockets, analytics, or update checks.

- **Challenge tracker** with SQLite storage under `~/.local/share/ctf-helper/`.

### 📝 **Integrated Note Taking**- **Markdown notes** with live preview and autosave snapshots.

- Built-in Markdown editor with live preview- **Local tooling** for crypto, forensics, reverse engineering, and web exploitation drills.

- Auto-save functionality (no data loss)- **Export/Import** via `.ctfpack` archives for air-gapped transfers.

- Syntax highlighting support- **Bundled docs and templates** stored locally and rendered in-app.

- Quick access to challenge-specific notes

- Export notes as part of challenge packs## Available Tools



### 🛠️ **40+ Offline Security Tools**Cryptea includes 40+ offline tools organized by category:

Tools are organized into categories for easy access:

### Crypto & Encoding

#### **Crypto & Encoding**- **Caesar Cipher** - Encrypt, decrypt, or brute force Caesar shifts

- **Caesar Cipher** - Encrypt, decrypt, or brute force Caesar shifts- **Vigenère Cipher** - Encrypt/decrypt with autokey and custom alphabets

- **Vigenère Cipher** - Classical polyalphabetic cipher with autokey support- **Morse Decoder** - Decode Morse code from text or audio

- **Morse Decoder** - Text and audio Morse code decoding- **XOR Analyzer** - Recover keystreams from known-plaintext

- **XOR Analyzer** - Keystream recovery from known-plaintext attacks- **RSA Toolkit** - Analyze moduli and detect small-e issues

- **RSA Toolkit** - Modulus analysis, small-e attacks, and key recovery- **Decoder Workbench** - Chain base64, hex, ROT, gzip, URL and XOR transforms

- **Decoder Workbench** - Chain multiple encoding schemes (Base64, Hex, ROT13, URL, Gzip, XOR)- **Hash Suite** - Comprehensive hash identification, cracking, and management

- **Hash Suite** - Complete hash management workspace- **Hash Digest** - Compute message digests using Python's hashlib

  - Hash identification and type detection- **Hash Workspace** - Hash identification, parsing, and batch analysis

  - Cracking with wordlist and brute force modes- **Hash Identifier** - Quick hash type identification

  - Hash format conversion- **Hash Cracker Pro** - Advanced hash cracking with multiple attack modes

  - Benchmark and time estimation- **Hash Benchmark** - Performance testing and time estimation

  - htpasswd generation- **Hash Format Converter** - Convert between hash formats

  - Hashcat/John command builder- **htpasswd Generator** - Generate Apache htpasswd entries

- **Hashcat/John Builder** - Compose cracking commands offline

#### **Forensics**

- **File Inspector** - Deep file analysis (magic bytes, entropy, metadata)### Forensics

- **PCAP Viewer** - Network capture analysis without Wireshark- **PCAP Viewer** - Summarize PCAP/PCAPNG captures and conversations

- **Memory Analyzer** - Memory dump string extraction and analysis- **Timeline Builder** - Generate file timestamp timelines (CSV/JSON)

- **Disk Image Tools** - Partition table parsing and analysis- **Disk Image Tools** - Parse partition tables and layouts

- **Timeline Builder** - Generate file timestamp timelines (CSV/JSON)- **Memory Analyzer** - Scan memory dumps for suspicious strings

- **File Inspector** - Analyze file metadata, hashes, and magic bytes

#### **Steganography**

- **Image Stego Toolkit** - zsteg, steghide, LSB analysis### Reverse Engineering

- **EXIF Metadata Viewer** - Photo metadata and GPS extraction- **PE/ELF Inspector** - Inspect headers, sections, and security flags

- **Audio Analyzer** - DTMF tone and Morse beep detection- **Quick Disassembly** - Disassemble code using objdump/radare2/rizin

- **Video Frame Exporter** - Extract frames at custom intervals- **EXE Decompiler** - Decompile executables to C-like pseudocode (Ghidra/Rizin)

- **QR/Barcode Scanner** - Decode QR codes and barcodes from images- **Disassembler Launcher** - Launch Ghidra, IDA, Cutter, or rizin

- **ROP Gadget Finder** - Find ROP gadgets in binaries

#### **Reverse Engineering**- **Binary Diff** - Compare binaries via radiff2 or hash

- **PE/ELF Inspector** - Binary header and section analysis- **Extract Strings** - Run strings utility on binaries

- **Quick Disassembly** - Fast disassembly preview window- **GDB Runner** - Execute scripted GDB sessions

- **EXE Decompiler** - Ghidra/Rizin-based decompilation to pseudocode- **Radare/Rizin Console** - Run scripted rizin/radare2 commands

- **Disassembler Launcher** - Launch Ghidra, IDA, Cutter, or Rizin

- **ROP Gadget Finder** - Find return-oriented programming gadgets### Media Analysis

- **Binary Diff** - Compare binary files for differences- **EXIF Metadata Viewer** - Inspect photo metadata and GPS data

- **Extract Strings** - Run strings utility with filtering- **Image Stego Toolkit** - Run zsteg, steghide, stegsolve

- **GDB Runner** - Execute scripted GDB debugging sessions- **QR/Barcode Scanner** - Scan for QR codes and barcodes

- **Radare/Rizin Console** - Scriptable binary analysis- **Audio Analyzer** - Detect DTMF tones and Morse beeps

- **Video Frame Exporter** - Export video frames at intervals

#### **Web Exploitation**

- **Directory Discovery** - Bruteforce directories with SecLists wordlists### Web Exploitation

- **JWT Tool** - Decode, verify, and tamper with JSON Web Tokens- **Dir Discovery** - Directory bruteforcing with SecLists

- **XSS Tester** - Test for cross-site scripting vulnerabilities- **JWT Tool** - Decode, verify, and tamper with JWTs

- **SQLi Tester** - SQL injection detection and testing- **XSS Tester** - Test for reflected XSS payloads

- **SQLMap Integration** - Run SQLMap against local targets (optional)- **SQLi Tester** - Test SQL injection vulnerabilities

- **File Upload Tester** - Generate file upload bypass payloads- **File Upload Tester** - Generate upload bypass payloads

- **Payload Library** - Curated collection of common payloads- **Payload Library** - Browse curated payload examples

- **sqlmap** - Run sqlmap against local targets (opt-in)

#### **Network Analysis**- **OWASP ZAP** - Launch and manage ZAP proxy

- **Nmap** - Network scanning (optional, for local networks only)

- **Nping** - Packet crafting and analysis (optional)### Network

- **Nmap** - Run local network scans (opt-in)

#### **Password Tools**- **nping** - Send crafted packets (opt-in)

- **Wordlist Generator** - Generate custom wordlists and permutations

- **Hash Cracker** - Multi-algorithm password cracking### Misc

- **htpasswd Generator** - Create Apache htpasswd entries- **Wordlist Generator** - Generate token permutations offline



### 📦 **Import/Export System**## Repository Layout

- Export challenges as `.ctfpack` files

- Import challenge packs from other Cryptea installations```

- Perfect for sharing writeups or backing up worksrc/                  Application sources (PyGObject + Libadwaita)

- Air-gap compatible file formatdata/                 Installable assets (desktop file, help, templates)

build-aux/            Flatpak manifest and vendored wheels placeholder

### 🎨 **Modern UI**tests/                Offline unit tests and fixtures

- Built with GTK4 and Libadwaita for a native GNOME experience```

- Responsive design adapts to window size

- Dark mode support (follows system theme)## Running from Source

- Keyboard shortcuts for power users

- Smooth animations and transitionsEnsure Python 3.11+, GTK4, Libadwaita, and PyGObject are installed locally. Then:



---```bash

python3 -m venv .venv

## 📥 Installationsource .venv/bin/activate

pip install --no-index --find-links=build-aux/python-deps markdown2 PyNaCl cryptography

### Prerequisitespython3 src/main.py

```

**Required:**

- Python 3.11 or higherSet `OFFLINE_BUILD=1` in your environment to enable additional runtime checks when running from source (the default).

- GTK 4.6+

- Libadwaita 1.2+## Building with Meson

- PyGObject (python3-gobject)

- Meson build system```bash

- SQLite 3meson setup builddir -Doffline-build=true

meson compile -C builddir

**Optional (for specific tools):**meson install -C builddir --destdir=dist

- `hashcat` - GPU-accelerated hash cracking```

- `john` - Password cracking

- `ghidra` - Advanced reverse engineeringThe Meson build generates `ctf_helper/build_config.py` to freeze the offline posture at build time.

- `radare2` or `rizin` - Binary analysis

- `gdb` - Debugging## Flatpak Packaging

- `objdump` - Disassembly

- `binwalk` - Firmware analysis1. Download wheel files for the required Python packages and place them in `build-aux/python-deps/`.

- `strings` - String extraction2. Build the Flatpak app bundle:

- `exiftool` - EXIF metadata

- `zsteg` - PNG/BMP steganography```bash

- `steghide` - JPEG steganographyflatpak-builder --force-clean builddir build-aux/org.example.CTFHelper.Devel.json --install-deps-from=flathub --user

- `zbarimg` - QR/barcode scanning```

- `ffmpeg` - Video frame extraction

- `sox` - Audio analysisThe manifest **does not grant network permissions** and mounts only:

- `nmap` - Network scanning

- `sqlmap` - SQL injection- `--socket=wayland`

- `--filesystem=xdg-data/ctf-helper:rw`

### Fedora/RHEL Installation- `--filesystem=xdg-documents:rw`



```bash## Air-Gapped Installation

# Install system dependencies

sudo dnf install python3 python3-pip python3-gobject gtk4 libadwaita meson1. Build the Flatpak bundle on a trusted machine.

2. Export the repository:

# Install optional tools

sudo dnf install hashcat john ghidra radare2 gdb binutils binwalk \```bash

                 exiftool zbar ffmpeg sox nmap sqlmapflatpak build-bundle builddir ctf-helper.flatpak org.example.CTFHelper

```

# Clone repository

git clone https://github.com/yourusername/cryptea.git3. Transfer the `.flatpak` file via removable media and install it offline:

cd cryptea/cryptea

```bash

# Run automated setupflatpak install --user ctf-helper.flatpak

./setup.sh```

```

## Offline QA Checklist

### Ubuntu/Debian Installation

- Disconnect all networking hardware and launch the app.

```bash- Confirm challenge creation, note editing, flag storage, and exports succeed.

# Install system dependencies- Open the Tools tab and run each offline module.

sudo apt install python3 python3-pip python3-gi gir1.2-gtk-4.0 \- Verify the help tab renders bundled Markdown.

                 gir1.2-adw-1 meson ninja-build- Inspect `~/.local/share/ctf-helper/logs/` for runtime logs (copy manually if needed).



# Install optional tools## Development Fixtures

sudo apt install hashcat john radare2 gdb binutils binwalk exiftool \

                 zbar-tools ffmpeg sox nmap sqlmapEnable the Meson option `-Ddev-profile=true` (or set `DEV_PROFILE_ENABLED=1`) to seed sample challenges for UI testing. Test assets live under `tests/assets/`.



# Clone repository## License

git clone https://github.com/yourusername/cryptea.git

cd cryptea/crypteaGPL-3.0-or-later.


# Build and install
meson setup builddir-user --prefix=$HOME/.local
meson compile -C builddir-user
meson install -C builddir-user

# Add to PATH if needed
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Arch Linux Installation

```bash
# Install system dependencies
sudo pacman -S python python-pip python-gobject gtk4 libadwaita meson

# Install optional tools
sudo pacman -S hashcat john-jumbo radare2 gdb binutils binwalk \
               perl-image-exiftool zbar ffmpeg sox nmap sqlmap

# Clone and build
git clone https://github.com/yourusername/cryptea.git
cd cryptea/cryptea
meson setup builddir-user --prefix=$HOME/.local
meson compile -C builddir-user
meson install -C builddir-user
```

### Manual Installation

```bash
# Setup build directory
meson setup builddir-user --prefix=$HOME/.local

# Compile
meson compile -C builddir-user

# Install to user directory
meson install -C builddir-user

# Launch
cryptea
```

### System-Wide Installation

```bash
# Build for system installation
meson setup builddir --prefix=/usr/local

# Compile
meson compile -C builddir

# Install (requires sudo)
sudo meson install -C builddir

# Launch
cryptea
```

---

## 🚀 Usage

### Launching the Application

```bash
# Launch from terminal
cryptea

# Or search for "Cryptea" in your application menu
```

### Quick Start Guide

#### 1. **Creating a Challenge**
- Click the pink **"+ Add Challenge"** button in the sidebar
- Fill in challenge details:
  - Title (required)
  - Project (e.g., "PicoCTF", "HackTheBox")
  - Category (Crypto, Web, Reverse, Forensics, etc.)
  - Difficulty (Easy, Medium, Hard)
  - Description
  - Flag (when found)
- Challenge is auto-saved as you type

#### 2. **Taking Notes**
- Click on any challenge to open the detail view
- Scroll to the **Notes** section
- Write in Markdown format
- Notes auto-save every few seconds
- Support for code blocks, lists, headers, and more

#### 3. **Using Tools**
- Click **"Tools"** in the sidebar to see all categories
- Click on any tool card to open it
- Most tools have:
  - Input field(s) for data
  - Options/settings panel
  - **Run** button to execute
  - Output display area
  - **Copy** button for results

#### 4. **Searching Challenges**
- Use the search bar at the top of the sidebar
- Searches across titles, projects, and categories
- Real-time filtering as you type

#### 5. **Filtering by Status**
- Click **"In Progress"** to see active challenges
- Click **"Completed"** to view solved challenges
- Click **"Favorites"** (star icon) for marked challenges

#### 6. **Exporting Data**
- Click the **settings gear** icon in the top-right
- Select **"Export .ctfpack"**
- Choose save location
- Exports all challenges, notes, and metadata

#### 7. **Importing Data**
- Click the settings gear icon
- Select **"Import .ctfpack"**
- Choose a `.ctfpack` file
- All challenges will be imported

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | Create new challenge |
| `Ctrl+F` | Focus search bar |
| `Ctrl+W` | Close window |
| `Ctrl+Q` | Quit application |

---

## 🏗️ Development

### Running from Source

```bash
# Clone repository
git clone https://github.com/yourusername/cryptea.git
cd cryptea/cryptea

# Run directly (no installation)
python3 run.py
```

### Project Structure

```
cryptea/cryptea/
├── src/
│   ├── main.py                 # Entry point
│   └── ctf_helper/
│       ├── application.py      # Main application window and logic
│       ├── config.py          # Configuration management
│       ├── db.py              # SQLite database interface
│       ├── logger.py          # Logging setup
│       ├── resources.py       # Resource management
│       ├── data_paths.py      # Path resolution
│       ├── offline_guard.py   # Offline enforcement (disabled)
│       ├── manager/
│       │   ├── challenge_manager.py  # Challenge CRUD operations
│       │   ├── export_import.py      # .ctfpack handling
│       │   └── models.py             # Data models
│       ├── modules/           # Tool modules
│       │   ├── crypto/        # Cryptography tools
│       │   ├── forensics/     # Forensics tools
│       │   ├── reverse/       # Reverse engineering tools
│       │   ├── stego/         # Steganography tools
│       │   ├── web/           # Web exploitation tools
│       │   └── network/       # Network tools
│       ├── notes/
│       │   └── note_manager.py       # Note storage
│       └── templates/
│           └── markdown_renderer.py  # Markdown processing
├── data/
│   ├── org.avnixm.Cryptea.desktop   # Desktop entry
│   ├── style.css                     # Custom styling
│   ├── icons/                        # Application icons
│   ├── help/                         # Help documentation
│   ├── templates/                    # Challenge templates
│   └── SecLists/                     # Wordlists
├── tests/                    # Unit tests
├── meson.build              # Build configuration
├── pyproject.toml           # Python project metadata
└── README.md                # This file
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/

# Run with coverage
pytest --cov=ctf_helper tests/
```

### Adding a New Tool

1. Create a new module in `src/ctf_helper/modules/<category>/`
2. Inherit from `BaseOfflineTool`
3. Implement the `run()` method
4. Register in `src/ctf_helper/modules/<category>/__init__.py`
5. Add UI integration in `application.py`

Example:

```python
from ctf_helper.modules.base import BaseOfflineTool

class MyTool(BaseOfflineTool):
    name = "My Tool"
    category = "Crypto"
    description = "Does something useful"
    
    def run(self, input_data: str) -> str:
        # Tool logic here
        return f"Result: {input_data}"
```

---

## 📂 Data Storage

Cryptea stores all data locally:

| Data Type | Location |
|-----------|----------|
| Challenges & Flags | `~/.local/share/cryptea/db.sqlite3` |
| Notes | Stored in database with challenge metadata |
| Logs | `~/.local/share/cryptea/logs/cryptea.log` |
| Configuration | `~/.config/cryptea/` (if needed) |
| Application Files | `~/.local/lib/python3.*/site-packages/ctf_helper/` |
| Executable | `~/.local/bin/cryptea` |

### Backup Your Data

```bash
# Backup database
cp ~/.local/share/cryptea/db.sqlite3 ~/cryptea-backup.db

# Or export as .ctfpack
# Use the Export function in the application
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `CRYPTEA_SUPPRESS_SANDBOX_WARNING` | Disable network warnings | `0` |
| `OFFLINE_BUILD` | Enable offline build mode | `0` |
| `DEV_PROFILE_ENABLED` | Enable development seeding | `0` |

### Custom Tool Paths

Edit `~/.config/cryptea/config.ini` (created on first run):

```ini
[tools]
hashcat_path = /usr/bin/hashcat
john_path = /usr/bin/john
ghidra_path = /opt/ghidra/ghidraRun
radare2_path = /usr/bin/r2
```

---

## 🐛 Troubleshooting

### Application won't start

```bash
# Check logs
tail -f ~/.local/share/cryptea/logs/cryptea.log

# Verify installation
which cryptea
python3 -c "import ctf_helper; print(ctf_helper.__file__)"
```

### Tools not working

```bash
# Check if tool is installed
which hashcat
which ghidra
which radare2

# Verify tool paths in settings
```

### Database errors

```bash
# Check database integrity
sqlite3 ~/.local/share/cryptea/db.sqlite3 "PRAGMA integrity_check;"

# Reset database (WARNING: deletes all data)
rm ~/.local/share/cryptea/db.sqlite3
# Restart application to recreate
```

### Import/Export issues

- Ensure `.ctfpack` files are not corrupted
- Check file permissions
- Try exporting to a different location

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest tests/`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- Follow PEP 8 for Python code
- Use type hints where possible
- Add docstrings to all public functions
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
- All the open-source security tools integrated

---

## 📧 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/cryptea/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/cryptea/discussions)

---

## 🗺️ Roadmap

### Planned Features

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

## 📊 Statistics

- **40+** Offline security tools
- **8** Tool categories
- **100%** Offline operation
- **0** External dependencies at runtime
- **GPL-3.0** Open source license

---

**Made with ❤️ for the CTF and security research community**
