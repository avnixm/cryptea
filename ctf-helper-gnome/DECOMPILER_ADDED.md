# ✅ EXE Decompiler Added to Cryptea!

## What's New

A comprehensive **EXE Decompiler** tool has been added to the Reverse Engineering category.

## Features

### 🎯 Multi-Engine Support
- **Ghidra** - Best quality decompilation to C-like pseudocode
- **Rizin/r2dec** - Fast and accurate decompilation
- **objdump** - Basic disassembly (always available fallback)
- **Auto-detect** - Automatically uses the best available engine

### 📁 File Support
- **Windows PE**: .exe, .dll, .sys files
- **Linux ELF**: Binaries, .so shared libraries
- **Generic**: Any recognized executable format

### 🔧 Capabilities
- Decompile specific functions by name or address
- Decompile entire binaries
- Verbose output with detailed analysis
- Deep analysis mode for complex/obfuscated binaries
- Copy output to clipboard
- Clean, syntax-highlighted pseudocode

## How to Use

1. Launch Cryptea: `ctf-helper`
2. Navigate to **Tools** tab
3. Select **Reverse Engineering** category
4. Click on **EXE Decompiler**
5. Browse and select an executable
6. Choose target function (or leave blank for all)
7. Click **Decompile**

## Installation

The tool is already integrated! Just reinstall to get the latest version:

```bash
cd /home/avnixm/Documents/cryptea/ctf-helper-gnome
meson install -C builddir-user
```

## Optional Dependencies (for best results)

### Ghidra (Best Quality)
```bash
sudo dnf install ghidra
# Or download from: https://ghidra-sre.org/
```

### Rizin (Fast Alternative)
```bash
sudo dnf install rizin
# Or radare2
sudo dnf install radare2
```

### objdump (Always Available)
Usually pre-installed with binutils. If not:
```bash
sudo dnf install binutils
```

## Example Usage

### Decompile main function
1. Select your binary (e.g., `challenge.exe`)
2. Function: `main`
3. Engine: Auto-detect
4. Click Decompile

### Decompile by address
1. Select binary
2. Function: `0x401000`
3. Engine: Ghidra
4. Click Decompile

### Decompile everything
1. Select binary
2. Function: (leave blank)
3. Enable "Deep Analysis"
4. Click Decompile

## Output Example

```c
Engine: Ghidra Decompiler
File: challenge.exe

// ======================================================================
// Function: main @ 0x401000
// ======================================================================

undefined8 main(int argc, char **argv) {
    int iVar1;
    char *local_password;
    
    printf("Enter password: ");
    scanf("%s", &local_password);
    
    iVar1 = strcmp(local_password, "s3cr3t_fl4g");
    if (iVar1 == 0) {
        puts("Access granted!");
        system("cat flag.txt");
        return 0;
    }
    
    puts("Access denied!");
    return 1;
}
```

## Tool Count Updated

Cryptea now includes **41+ CTF tools** (updated from 40+):

- Crypto & Encoding: 15 tools
- Forensics: 5 tools  
- **Reverse Engineering: 9 tools** (was 8)
- Media Analysis: 5 tools
- Web Exploitation: 8 tools
- Network: 2 tools
- Misc: 1 tool

## Documentation

For detailed information, see:
- **EXE_DECOMPILER.md** - Complete usage guide
- **README.md** - Updated tools list

## Benefits for CTF Challenges

✅ **No external tools needed** - Everything in one app
✅ **Offline operation** - Works without internet
✅ **Multiple engines** - Choose quality vs speed
✅ **Easy to use** - GUI interface for complex tools
✅ **Copy output** - Easy to share or analyze
✅ **Function targeting** - Focus on what matters

## Files Added/Modified

### New Files:
- `src/ctf_helper/modules/reverse/exe_decompiler.py` - Main decompiler tool
- `EXE_DECOMPILER.md` - Documentation

### Modified Files:
- `src/ctf_helper/modules/reverse/__init__.py` - Registered new tool
- `README.md` - Updated tools list to 41+ tools

## Next Steps

1. **Launch Cryptea**: `ctf-helper`
2. **Try the decompiler** on a binary from your CTF challenges
3. **Install Ghidra** for best results (optional but recommended)
4. **Explore other reverse engineering tools** in the same category

## Integration

The EXE Decompiler works great with other Cryptea tools:

- **Binary Inspector** → Analyze headers first
- **Strings Extract** → Find interesting strings
- **Quick Disassembly** → Compare with disassembly
- **GDB Helper** → Debug alongside decompilation

Enjoy your new decompiler! 🛡️🔍
