# ✅ EXE Decompiler Successfully Added!

## Summary

A comprehensive **EXE/ELF Decompiler** has been successfully added to Cryptea's Reverse Engineering tools!

## What Was Added

### New File:
- `src/ctf_helper/modules/reverse/exe_decompiler.py` (561 lines)

### Modified Files:
- `src/ctf_helper/modules/reverse/__init__.py` - Registered ExeDecompiler
- `README.md` - Updated tool count to 41+ tools

### Documentation:
- `EXE_DECOMPILER.md` - Complete usage guide
- `DECOMPILER_ADDED.md` - Feature announcement

## Features

✅ **Multi-Engine Support**: Ghidra, Rizin/r2dec, objdump with auto-detection
✅ **File Format Support**: Windows PE (.exe, .dll) and Linux ELF binaries
✅ **Function Targeting**: Decompile by name, address, or entire binary
✅ **Analysis Options**: Verbose mode and deep analysis
✅ **Clean Output**: C-like pseudocode with copy-to-clipboard
✅ **GUI Interface**: Full GTK4/Libadwaita integration

## How to Use

1. **Launch Cryptea**:
   ```bash
   ctf-helper
   ```

2. **Navigate to Tools** → **Reverse Engineering** → **EXE Decompiler**

3. **Select an executable** (.exe, .dll, or ELF binary)

4. **Choose options**:
   - Function name (e.g., "main") or hex address (e.g., "0x401000")
   - Decompiler engine (auto-detect recommended)
   - Verbose output and deep analysis options

5. **Click Decompile** and wait for results

6. **Copy output** to clipboard for analysis

## Example Output

```c
Engine: Ghidra Decompiler
File: crackme.exe
Function: main

undefined8 main(int argc, char **argv) {
    int iVar1;
    char local_password[32];
    
    printf("Enter password: ");
    scanf("%31s", local_password);
    
    iVar1 = strcmp(local_password, "CTF{d3comp1l3d_s3cr3t}");
    if (iVar1 == 0) {
        puts("Access granted! Flag is correct.");
        return 0;
    }
    
    puts("Access denied!");
    return 1;
}
```

## Installation

The tool is now installed and ready to use! If you need to reinstall:

```bash
cd /home/avnixm/Documents/cryptea/ctf-helper-gnome
meson install -C builddir-user
```

## Optional Dependencies

For best results, install external decompilers:

### Ghidra (Recommended - Best Quality)
```bash
sudo dnf install ghidra
```
Or download from: https://ghidra-sre.org/

### Rizin (Fast Alternative)
```bash
sudo dnf install rizin
# or
sudo dnf install radare2
```

### objdump (Built-in Fallback)
Already available via binutils (pre-installed on most systems)

## Tool Count Update

Cryptea now has **41+ CTF tools**:

- **Crypto & Encoding**: 15 tools
- **Forensics**: 5 tools
- **Reverse Engineering**: 9 tools ⬅️ **NEW: +1 (was 8)**
  - PE/ELF Inspector
  - Quick Disassembly
  - **EXE Decompiler** ⬅️ **NEW!**
  - Disassembler Launcher
  - ROP Gadget Finder
  - Binary Diff
  - Extract Strings
  - GDB Runner
  - Radare/Rizin Console
- **Media Analysis**: 5 tools
- **Web Exploitation**: 8 tools
- **Network**: 2 tools
- **Misc**: 1 tool

## Technical Details

**Implementation**:
- Class-based tool following Cryptea's OfflineTool protocol
- GTK4/Libadwaita UI with Adw widgets
- Subprocess-based execution of external decompilers
- Automatic fallback if preferred tool not available
- Timeout protection (5 minutes for Ghidra, 60s for Rizin, 30s for objdump)
- Proper error handling and user feedback

**Integration**:
- Registered in reverse engineering module
- Accessible via Tools tab
- Works offline (decompilers are local)
- No network access required

## Testing

```bash
# Verify import
python3 -c "from ctf_helper.modules.reverse.exe_decompiler import ExeDecompiler; print('✅ Success')"

# Launch Cryptea
ctf-helper
```

## Use Cases

Perfect for CTF challenges involving:
- 🔓 **Password crackers** - Find hardcoded passwords
- 🧩 **Reverse engineering** - Understand binary logic
- 🚩 **Flag extraction** - Locate hidden flags in code
- 🔐 **Algorithm analysis** - Study encryption/obfuscation
- 🐛 **Vulnerability hunting** - Find exploitable code patterns
- 📊 **Control flow analysis** - Map program behavior

## Next Steps

1. ✅ Launch Cryptea: `ctf-helper`
2. ✅ Navigate to Reverse Engineering tools
3. ✅ Try the EXE Decompiler on a binary
4. ✅ Install Ghidra for best results (optional)
5. ✅ Combine with other reverse engineering tools

## Documentation

- **EXE_DECOMPILER.md** - Full usage guide with examples
- **DECOMPILER_ADDED.md** - Feature announcement
- **README.md** - Updated tools list

## Success! 🎉

The EXE Decompiler is now fully integrated and ready to help you solve CTF challenges!

**Happy decompiling!** 🛡️🔍
