#!/usr/bin/env python3
"""
Cryptea Dependency Checker
Checks for required and optional external tools before installation.
"""

import importlib
import shutil
import sys
from typing import Dict, List, Tuple

# Color codes for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"


class DependencyChecker:
    """Check system dependencies for Cryptea."""

    # Core system dependencies (required)
    REQUIRED_DEPS = {
        "python3": "Python 3.10 or higher",
        "meson": "Meson build system",
        "ninja": "Ninja build tool",
    }

    # Optional tools by category
    OPTIONAL_DEPS = {
        "Reverse Engineering": {
            "radare2": "Advanced binary analysis and disassembly",
            "rizin": "Alternative to radare2 (fork with improvements)",
            "gdb": "GNU Debugger for debugging binaries",
            "objdump": "Display information from object files (usually in binutils)",
            "readelf": "Display information about ELF files (usually in binutils)",
            "strings": "Extract printable strings from binaries (usually in binutils)",
            "ROPgadget": "Find ROP gadgets in binaries",
            "ropper": "Alternative ROP gadget finder",
            "ghidra": "NSA's software reverse engineering suite",
            "cutter": "GUI for Rizin reverse engineering framework",
            "radiff2": "Binary diff tool (part of radare2)",
            "checksec": "Checksec script for binary hardening checks",
        },
        "Forensics": {
            "binwalk": "Firmware analysis and extraction tool",
            "foremost": "File carving and recovery tool",
            "exiftool": "Read/write metadata in files",
            "tshark": "Network protocol analyzer (Wireshark CLI)",
            "tcpdump": "Network packet capture tool",
            "file": "Determine file type",
        },
        "Steganography & Media": {
            "steghide": "Hide data in various image/audio formats",
            "stegsolve": "Analyze images for hidden data",
            "zsteg": "Detect steganography in PNG and BMP images",
            "zbarimg": "QR code and barcode scanner",
            "ffmpeg": "Audio/video processing framework",
            "sox": "Sound processing tool",
        },
        "Cryptography": {
            "hashcat": "Advanced password recovery",
            "john": "John the Ripper password cracker",
            "openssl": "SSL/TLS toolkit and crypto library",
            "RsaCtfTool": "RSA attack automation toolkit",
            "featherduster": "Automated cryptanalysis framework",
        },
        "Network Security": {
            "nmap": "Network exploration and security auditing",
            "nping": "Network packet generation tool (part of nmap)",
            "sqlmap": "Automatic SQL injection tool",
            "hydra": "Network login cracker",
            "medusa": "Parallel network login brute-forcer",
            "wfuzz": "Web fuzzing framework",
            "commix": "Command injection exploitation tool",
            "arjun": "HTTP parameter discovery",
            "sublist3r": "Subdomain enumeration tool",
            "crackmapexec": "Network service exploitation suite",
            "gobuster": "Directory/DNS brute-forcing tool",
            "ffuf": "Fast web fuzzer",
            "nikto": "Web server vulnerability scanner",
            "masscan": "Ultra-fast TCP port scanner",
            "enum4linux": "SMB/Windows enumeration tool",
            "enum4linux-ng": "Improved SMB/Windows enumeration tool",
        },
        "Web Tools": {
            "dirb": "Web content scanner",
            "dirbuster": "Web directory brute-forcer",
            "zap": "OWASP ZAP proxy and scanner",
            "owasp-zap": "OWASP ZAP (alternative name)",
            "zaproxy": "OWASP ZAP (alternative name)",
        },
        "Media Analysis": {
            "tesseract": "OCR engine (for text extraction from images)",
        },
    }

    OPTIONAL_PYTHON = {
        "angr": {
            "import": "angr",
            "category": "Reverse Engineering",
            "description": "Angr symbolic execution engine (Python package)",
            "pip": "angr",
        },
        "pwntools": {
            "import": "pwn",
            "category": "Reverse Engineering",
            "description": "Pwntools exploitation helpers (Python package)",
            "pip": "pwntools",
        },
        "numpy": {
            "import": "numpy",
            "category": "Media Analysis",
            "description": "NumPy for numerical computing (audio/image analysis)",
            "pip": "numpy",
        },
        "scipy": {
            "import": "scipy",
            "category": "Media Analysis",
            "description": "SciPy for scientific computing (signal processing)",
            "pip": "scipy",
        },
        "Pillow": {
            "import": "PIL",
            "category": "Media Analysis",
            "description": "Pillow for image processing",
            "pip": "Pillow",
        },
        "pytesseract": {
            "import": "pytesseract",
            "category": "Media Analysis",
            "description": "Python wrapper for Tesseract OCR",
            "pip": "pytesseract",
        },
        "pyzbar": {
            "import": "pyzbar",
            "category": "Media Analysis",
            "description": "Python wrapper for ZBar barcode/QR scanner",
            "pip": "pyzbar",
        },
        "pydub": {
            "import": "pydub",
            "category": "Media Analysis",
            "description": "Audio manipulation library",
            "pip": "pydub",
        },
        "librosa": {
            "import": "librosa",
            "category": "Media Analysis",
            "description": "Audio and music analysis library",
            "pip": "librosa",
        },
    }

    def __init__(self):
        self.missing_required: List[str] = []
        self.missing_optional: Dict[str, List[str]] = {}
        self.found_optional: Dict[str, List[str]] = {}
        self.missing_python_optional: Dict[str, List[str]] = {}
        self.found_python_optional: Dict[str, List[str]] = {}

    def check_command(self, command: str) -> bool:
        """Check if a command is available in PATH."""
        return shutil.which(command) is not None

    def check_required(self) -> bool:
        """Check all required dependencies."""
        print(f"\n{BOLD}{BLUE}=== Checking Required Dependencies ==={RESET}\n")
        
        all_found = True
        for cmd, description in self.REQUIRED_DEPS.items():
            if self.check_command(cmd):
                print(f"{GREEN}✓{RESET} {cmd:<20} - {description}")
            else:
                print(f"{RED}✗{RESET} {cmd:<20} - {description} {RED}(MISSING){RESET}")
                self.missing_required.append(cmd)
                all_found = False
        
        return all_found

    def check_optional(self) -> None:
        """Check all optional dependencies by category."""
        print(f"\n{BOLD}{BLUE}=== Checking Optional Tools ==={RESET}\n")
        
        for category, tools in self.OPTIONAL_DEPS.items():
            print(f"\n{BOLD}{category}:{RESET}")
            found = []
            missing = []
            
            for cmd, description in tools.items():
                if self.check_command(cmd):
                    print(f"  {GREEN}✓{RESET} {cmd:<20} - {description}")
                    found.append(cmd)
                else:
                    print(f"  {YELLOW}○{RESET} {cmd:<20} - {description}")
                    missing.append(cmd)
            
            if found:
                self.found_optional[category] = found
            if missing:
                self.missing_optional[category] = missing

    def check_optional_python(self) -> None:
        """Check optional Python packages."""
        if not self.OPTIONAL_PYTHON:
            return

        print(f"\n{BOLD}{BLUE}=== Checking Optional Python Packages ==={RESET}\n")

        categorized_missing: Dict[str, List[str]] = {}
        categorized_found: Dict[str, List[str]] = {}

        for name, data in self.OPTIONAL_PYTHON.items():
            category = data["category"]
            description = data["description"]
            module_name = data["import"]
            try:
                importlib.import_module(module_name)
                print(f"{GREEN}✓{RESET} {name:<15} - {description}")
                categorized_found.setdefault(category, []).append(name)
            except ImportError:
                print(f"{YELLOW}○{RESET} {name:<15} - {description}")
                categorized_missing.setdefault(category, []).append(name)

        if categorized_found:
            self.found_python_optional = categorized_found
        if categorized_missing:
            self.missing_python_optional = categorized_missing

    def print_summary(self) -> bool:
        """Print installation summary and recommendations."""
        print(f"\n{BOLD}{BLUE}{'=' * 70}{RESET}")
        print(f"{BOLD}{BLUE}=== Summary ==={RESET}")
        print(f"{BOLD}{BLUE}{'=' * 70}{RESET}\n")

        # Required dependencies
        if not self.missing_required:
            print(f"{GREEN}✓ All required dependencies are installed!{RESET}")
        else:
            print(f"{RED}✗ Missing required dependencies:{RESET}")
            for dep in self.missing_required:
                print(f"  - {dep}")
            print(f"\n{RED}{BOLD}ERROR: Cannot proceed with installation.{RESET}")
            print(f"{YELLOW}Please install the missing required dependencies first.{RESET}\n")
            self.print_install_commands()
            return False

        # Optional tools summary
        total_optional = sum(len(tools) for tools in self.OPTIONAL_DEPS.values())
        total_found = sum(len(tools) for tools in self.found_optional.values())
        total_missing = sum(len(tools) for tools in self.missing_optional.values())

        python_optional_total = len(self.OPTIONAL_PYTHON)
        python_optional_found = sum(len(tools) for tools in self.found_python_optional.values())
        python_optional_missing = sum(len(tools) for tools in self.missing_python_optional.values())

        print(f"\n{BOLD}Optional Tools:{RESET}")
        print(f"  {GREEN}Found:{RESET} {total_found}/{total_optional}")
        print(f"  {YELLOW}Missing:{RESET} {total_missing}/{total_optional}")
        if python_optional_total:
            print(f"  {BOLD}Python packages:{RESET} {python_optional_found}/{python_optional_total} available")

        optional_missing_any = total_missing > 0 or python_optional_missing > 0
        if optional_missing_any:
            print(f"\n{YELLOW}⚠ Some optional tools are missing.{RESET}")
            print(f"{YELLOW}Cryptea will work, but some features may be limited.{RESET}")
            print(f"\n{BOLD}To install missing optional tools:{RESET}")
            self.print_install_commands()
        
        print(f"\n{GREEN}{BOLD}✓ Ready to install Cryptea!{RESET}")
        print(f"\nTo install, run:")
        print(f"  {BOLD}./install.sh{RESET}     (system-wide)")
        print(f"  {BOLD}./install-user.sh{RESET} (user-local)\n")
        
        return True

    def print_install_commands(self) -> None:
        """Print platform-specific installation commands."""
        print(f"\n{BOLD}Installation commands by distribution:{RESET}\n")

        # Fedora/RHEL
        print(f"{BOLD}Fedora/RHEL/CentOS:{RESET}")
        fedora_required = " ".join(["python3", "meson", "ninja-build"])
        fedora_optional = " ".join([
            "radare2", "gdb", "binutils", "binwalk", "exiftool",
            "hashcat", "john", "perl-Image-ExifTool", "zbar", "ffmpeg",
            "sox", "nmap", "sqlmap", "hydra", "medusa", "wfuzz", "commix",
            "arjun", "sublist3r", "crackmapexec", "foremost", "openssl",
            "checksec", "gobuster", "ffuf", "nikto", "masscan",
            "enum4linux-ng", "dirb", "tesseract"
        ])
        if self.missing_required:
            print(f"  sudo dnf install {fedora_required}")
        if self.missing_optional:
            print(f"  sudo dnf install {fedora_optional}")

        # Debian/Ubuntu
        print(f"\n{BOLD}Debian/Ubuntu:{RESET}")
        debian_required = " ".join(["python3", "meson", "ninja-build"])
        debian_optional = " ".join([
            "radare2", "gdb", "binutils", "binwalk", "exiftool",
            "hashcat", "john", "zbar-tools", "ffmpeg", "sox",
            "nmap", "sqlmap", "hydra", "medusa", "wfuzz", "commix",
            "arjun", "sublist3r", "crackmapexec", "foremost", "openssl",
            "checksec", "gobuster", "ffuf", "nikto", "masscan",
            "enum4linux", "dirb", "dirbuster", "tesseract-ocr"
        ])
        if self.missing_required:
            print(f"  sudo apt install {debian_required}")
        if self.missing_optional:
            print(f"  sudo apt install {debian_optional}")

        # Arch Linux
        print(f"\n{BOLD}Arch Linux:{RESET}")
        arch_required = " ".join(["python", "meson", "ninja"])
        arch_optional = " ".join([
            "radare2", "gdb", "binutils", "binwalk", "perl-image-exiftool",
            "hashcat", "john", "zbar", "ffmpeg", "sox", "nmap",
            "sqlmap", "hydra", "medusa", "wfuzz", "commix", "arjun",
            "sublist3r", "crackmapexec", "foremost", "openssl",
            "checksec", "gobuster", "ffuf", "nikto", "masscan",
            "enum4linux-ng", "dirb", "tesseract"
        ])
        if self.missing_required:
            print(f"  sudo pacman -S {arch_required}")
        if self.missing_optional:
            print(f"  sudo pacman -S {arch_optional}")

        # Python packages
        python_missing = sorted({pkg for pkgs in self.missing_python_optional.values() for pkg in pkgs})
        if python_missing:
            print(f"\n{BOLD}Python packages (via pip):{RESET}")
            print(f"  pip install --user {' '.join(python_missing)}")

        if any("ROPgadget" in tools or "ropper" in tools or "zsteg" in tools
               for tools in self.missing_optional.values()):
            print(f"  pip install --user ROPgadget ropper")
            print(f"  gem install zsteg  # for steganography")

        print()

    def run(self) -> int:
        """Run the complete dependency check."""
        print(f"\n{BOLD}{BLUE}{'=' * 70}{RESET}")
        print(f"{BOLD}{BLUE}Cryptea - CTF Helper Application{RESET}")
        print(f"{BOLD}{BLUE}Dependency Checker{RESET}")
        print(f"{BOLD}{BLUE}{'=' * 70}{RESET}")

        # Check required dependencies
        required_ok = self.check_required()

        # Check optional dependencies
        self.check_optional()
        self.check_optional_python()

        # Print summary
        success = self.print_summary()

        # Return appropriate exit code
        if not required_ok:
            return 1
        return 0


def main() -> int:
    """Main entry point."""
    checker = DependencyChecker()
    return checker.run()


if __name__ == "__main__":
    sys.exit(main())
