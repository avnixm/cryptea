# EXE Decompiler Tool

## Overview

The EXE Decompiler is a powerful reverse engineering tool integrated into Cryptea that decompiles Windows PE executables (.exe, .dll) and Linux ELF binaries into readable C-like pseudocode.

## Features

### Multi-Engine Support

The decompiler supports three different engines with automatic fallback:

1. **Ghidra Decompiler** (Best Quality)
   - Most accurate decompilation
   - Full program analysis
   - C-like pseudocode output
   - Requires: Ghidra installed and `analyzeHeadless` in PATH

2. **Rizin/r2dec** (Fast & Good)
   - Quick decompilation
   - Good accuracy
   - Works with both Rizin and Radare2
   - Requires: `rizin` or `r2` in PATH

3. **objdump** (Basic Fallback)
   - Always available
   - Provides disassembly (not decompilation)
   - No external dependencies

### Supported File Types

- **Windows PE**: .exe, .dll, .sys
- **Linux ELF**: binaries, .so (shared objects)
- **Generic**: Any executable with recognized format

## Usage

1. **Select File**: Click "Browse..." to select an executable
2. **Choose Engine**: Select decompiler or leave on "Auto-detect"
3. **Specify Target**: 
   - Enter function name (e.g., "main", "entry0")
   - Enter hex address (e.g., "0x401000")
   - Leave blank to decompile all functions
4. **Configure Options**:
   - **Verbose Output**: Include detailed comments and analysis
   - **Deep Analysis**: Thorough analysis (slower but more accurate)
5. **Click "Decompile"**: Wait for the decompilation to complete
6. **Copy Output**: Use "Copy Output" button to copy to clipboard

## Examples

### Decompile main function
```
Function Name: main
Engine: Auto-detect
```

### Decompile specific address
```
Function Name: 0x401550
Engine: Ghidra Decompiler
```

### Decompile entire binary
```
Function Name: (leave blank)
Engine: Rizin/r2dec
```

## Installation Requirements

### For Best Results (Ghidra)

Install Ghidra:
```bash
# Fedora
sudo dnf install ghidra

# Or download from: https://ghidra-sre.org/
```

Make sure `analyzeHeadless` is in your PATH.

### For Fast Decompilation (Rizin)

Install Rizin:
```bash
# Fedora
sudo dnf install rizin

# Or Radare2
sudo dnf install radare2
```

### Basic Disassembly (objdump)

Usually pre-installed. If not:
```bash
sudo dnf install binutils
```

## Output Format

The decompiled output includes:

1. **Header Information**:
   - Engine used
   - File name
   - Function name/address

2. **Decompiled Code**:
   - C-like pseudocode (Ghidra/Rizin)
   - Assembly code (objdump)
   - Variable names and types
   - Control flow structures

3. **Analysis Comments** (if verbose mode enabled):
   - Cross-references
   - String references
   - Function calls
   - Data types

## Tips

1. **Start with Auto-detect**: Let the tool choose the best available engine
2. **Use Verbose Mode**: Get more insights into the binary's behavior
3. **Target Specific Functions**: Faster than decompiling entire binary
4. **Hex Addresses**: Useful when function names are stripped
5. **Deep Analysis**: Enable for obfuscated or complex binaries

## Troubleshooting

### "Ghidra decompilation failed"
- Check Ghidra is installed: `analyzeHeadless --version`
- Ensure file has read permissions
- Try Rizin engine instead

### "Rizin decompilation failed"
- Check Rizin/r2 is installed: `rizin -v` or `r2 -v`
- Binary might be packed or obfuscated
- Try Ghidra for better results

### "Function not found"
- Function name might be stripped or mangled
- Try hex address instead
- Leave blank to see all available functions

### Timeout errors
- Large binaries take time
- Try decompiling specific functions instead of whole binary
- Use Rizin for faster (but less detailed) results

## Integration with Other Tools

The EXE Decompiler works well with:

- **Binary Inspector**: First inspect the binary to identify functions
- **Disassembler**: Compare disassembly with decompiled code
- **Strings Extract**: Find interesting strings to target
- **GDB Helper**: Debug alongside decompilation

## Security Note

This tool executes external decompilers on the selected binary. Only decompile trusted files from trusted sources. Malicious binaries could potentially exploit vulnerabilities in decompiler tools.

## Added to Cryptea

The EXE Decompiler is now available in:
- **Category**: Reverse Engineering
- **Tool Name**: "EXE Decompiler"
- **Description**: "Decompile executables to C-like pseudocode using Ghidra/Rizin"

Launch Cryptea and navigate to the Tools tab to access it!
