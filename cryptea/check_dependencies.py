#!/usr/bin/env python3
"""
Cryptea Dependency Checker
Checks for required and optional external tools before installation.
"""

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
        },
        "Network Security": {
            "nmap": "Network exploration and security auditing",
            "sqlmap": "Automatic SQL injection tool",
            "hydra": "Network login cracker",
        },
    }

    def __init__(self):
        self.missing_required: List[str] = []
        self.missing_optional: Dict[str, List[str]] = {}
        self.found_optional: Dict[str, List[str]] = {}

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

        print(f"\n{BOLD}Optional Tools:{RESET}")
        print(f"  {GREEN}Found:{RESET} {total_found}/{total_optional}")
        print(f"  {YELLOW}Missing:{RESET} {total_missing}/{total_optional}")

        if total_missing > 0:
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
            "sox", "nmap", "sqlmap", "hydra", "foremost", "openssl"
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
            "nmap", "sqlmap", "hydra", "foremost", "openssl"
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
            "sqlmap", "hydra", "foremost", "openssl"
        ])
        if self.missing_required:
            print(f"  sudo pacman -S {arch_required}")
        if self.missing_optional:
            print(f"  sudo pacman -S {arch_optional}")

        # Python packages
        if any("ROPgadget" in tools or "ropper" in tools or "zsteg" in tools 
               for tools in self.missing_optional.values()):
            print(f"\n{BOLD}Python packages (via pip):{RESET}")
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
