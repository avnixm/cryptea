# Cryptea (Offline Edition)

Cryptea is a 100% offline desktop companion for Capture the Flag training. It ships challenge management, Markdown note taking, offline tool modules, and bundled documentation without ever touching the network.

## Installation

### Quick Setup (Fedora)

```bash
./setup.sh
```

This interactive script will check dependencies and guide you through installation.

For detailed instructions, see [BUILD.md](BUILD.md) and [INSTALL.md](INSTALL.md).

### Running from Source

```bash
python run.py
```

## Features

- **Offline-first**: No network sockets, analytics, or update checks.
- **Challenge tracker** with SQLite storage under `~/.local/share/ctf-helper/`.
- **Markdown notes** with live preview and autosave snapshots.
- **Local tooling** for crypto, forensics, reverse engineering, and web exploitation drills.
- **Export/Import** via `.ctfpack` archives for air-gapped transfers.
- **Bundled docs and templates** stored locally and rendered in-app.

## Available Tools

Cryptea includes 40+ offline tools organized by category:

### Crypto & Encoding
- **Caesar Cipher** - Encrypt, decrypt, or brute force Caesar shifts
- **Vigenère Cipher** - Encrypt/decrypt with autokey and custom alphabets
- **Morse Decoder** - Decode Morse code from text or audio
- **XOR Analyzer** - Recover keystreams from known-plaintext
- **RSA Toolkit** - Analyze moduli and detect small-e issues
- **Decoder Workbench** - Chain base64, hex, ROT, gzip, URL and XOR transforms
- **Hash Suite** - Comprehensive hash identification, cracking, and management
- **Hash Digest** - Compute message digests using Python's hashlib
- **Hash Workspace** - Hash identification, parsing, and batch analysis
- **Hash Identifier** - Quick hash type identification
- **Hash Cracker Pro** - Advanced hash cracking with multiple attack modes
- **Hash Benchmark** - Performance testing and time estimation
- **Hash Format Converter** - Convert between hash formats
- **htpasswd Generator** - Generate Apache htpasswd entries
- **Hashcat/John Builder** - Compose cracking commands offline

### Forensics
- **PCAP Viewer** - Summarize PCAP/PCAPNG captures and conversations
- **Timeline Builder** - Generate file timestamp timelines (CSV/JSON)
- **Disk Image Tools** - Parse partition tables and layouts
- **Memory Analyzer** - Scan memory dumps for suspicious strings
- **File Inspector** - Analyze file metadata, hashes, and magic bytes

### Reverse Engineering
- **PE/ELF Inspector** - Inspect headers, sections, and security flags
- **Quick Disassembly** - Disassemble code using objdump/radare2/rizin
- **EXE Decompiler** - Decompile executables to C-like pseudocode (Ghidra/Rizin)
- **Disassembler Launcher** - Launch Ghidra, IDA, Cutter, or rizin
- **ROP Gadget Finder** - Find ROP gadgets in binaries
- **Binary Diff** - Compare binaries via radiff2 or hash
- **Extract Strings** - Run strings utility on binaries
- **GDB Runner** - Execute scripted GDB sessions
- **Radare/Rizin Console** - Run scripted rizin/radare2 commands

### Media Analysis
- **EXIF Metadata Viewer** - Inspect photo metadata and GPS data
- **Image Stego Toolkit** - Run zsteg, steghide, stegsolve
- **QR/Barcode Scanner** - Scan for QR codes and barcodes
- **Audio Analyzer** - Detect DTMF tones and Morse beeps
- **Video Frame Exporter** - Export video frames at intervals

### Web Exploitation
- **Dir Discovery** - Directory bruteforcing with SecLists
- **JWT Tool** - Decode, verify, and tamper with JWTs
- **XSS Tester** - Test for reflected XSS payloads
- **SQLi Tester** - Test SQL injection vulnerabilities
- **File Upload Tester** - Generate upload bypass payloads
- **Payload Library** - Browse curated payload examples
- **sqlmap** - Run sqlmap against local targets (opt-in)
- **OWASP ZAP** - Launch and manage ZAP proxy

### Network
- **Nmap** - Run local network scans (opt-in)
- **nping** - Send crafted packets (opt-in)

### Misc
- **Wordlist Generator** - Generate token permutations offline

## Repository Layout

```
src/                  Application sources (PyGObject + Libadwaita)
data/                 Installable assets (desktop file, help, templates)
build-aux/            Flatpak manifest and vendored wheels placeholder
tests/                Offline unit tests and fixtures
```

## Running from Source

Ensure Python 3.11+, GTK4, Libadwaita, and PyGObject are installed locally. Then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --no-index --find-links=build-aux/python-deps markdown2 PyNaCl cryptography
python3 src/main.py
```

Set `OFFLINE_BUILD=1` in your environment to enable additional runtime checks when running from source (the default).

## Building with Meson

```bash
meson setup builddir -Doffline-build=true
meson compile -C builddir
meson install -C builddir --destdir=dist
```

The Meson build generates `ctf_helper/build_config.py` to freeze the offline posture at build time.

## Flatpak Packaging

1. Download wheel files for the required Python packages and place them in `build-aux/python-deps/`.
2. Build the Flatpak app bundle:

```bash
flatpak-builder --force-clean builddir build-aux/org.example.CTFHelper.Devel.json --install-deps-from=flathub --user
```

The manifest **does not grant network permissions** and mounts only:

- `--socket=wayland`
- `--filesystem=xdg-data/ctf-helper:rw`
- `--filesystem=xdg-documents:rw`

## Air-Gapped Installation

1. Build the Flatpak bundle on a trusted machine.
2. Export the repository:

```bash
flatpak build-bundle builddir ctf-helper.flatpak org.example.CTFHelper
```

3. Transfer the `.flatpak` file via removable media and install it offline:

```bash
flatpak install --user ctf-helper.flatpak
```

## Offline QA Checklist

- Disconnect all networking hardware and launch the app.
- Confirm challenge creation, note editing, flag storage, and exports succeed.
- Open the Tools tab and run each offline module.
- Verify the help tab renders bundled Markdown.
- Inspect `~/.local/share/ctf-helper/logs/` for runtime logs (copy manually if needed).

## Development Fixtures

Enable the Meson option `-Ddev-profile=true` (or set `DEV_PROFILE_ENABLED=1`) to seed sample challenges for UI testing. Test assets live under `tests/assets/`.

## License

GPL-3.0-or-later.
