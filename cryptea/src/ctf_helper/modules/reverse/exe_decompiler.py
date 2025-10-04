"""EXE/ELF Decompiler - Decompile executables to readable pseudocode."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from ..base import ToolResult


class ExeDecompiler:
    """Decompile Windows PE and Linux ELF executables."""

    name = "EXE Decompiler"
    description = "Decompile executables to C-like pseudocode using Ghidra/Rizin"
    category = "Reverse"

    def run(
        self,
        file_path: str = "",
        engine: str = "auto",
        function: str = "main",
        verbose: str = "false",
        **kwargs
    ) -> ToolResult:
        """Decompile an executable file.
        
        Args:
            file_path: Path to the executable file
            engine: Decompiler engine (auto/ghidra/rizin/objdump)
            function: Function name or address to decompile
            verbose: Show verbose output (true/false)
        """
        if not file_path or not file_path.strip():
            raise ValueError("Please provide a binary file path")
        
        binary_path = Path(file_path).expanduser()
        if not binary_path.exists():
            raise FileNotFoundError(f"File not found: {binary_path}")
        
        if not binary_path.is_file():
            raise ValueError(f"Not a file: {binary_path}")
        
        engine = engine.lower().strip()
        function = function.strip() or "main"
        is_verbose = verbose.lower() in ("true", "1", "yes")
        
        # Detect available engines
        available = []
        if shutil.which("analyzeHeadless"):
            available.append("ghidra")
        if shutil.which("rizin") or shutil.which("r2"):
            available.append("rizin")
        if shutil.which("objdump"):
            available.append("objdump")
        
        if not available:
            return ToolResult(
                title="No Decompilers Available",
                body="No decompilers found. Please install one of:\n"
                     "• Ghidra (best results)\n"
                     "• Rizin/radare2 (fast)\n"
                     "• binutils (basic disassembly)"
            )
        
        # Auto-detect best available engine
        if engine == "auto":
            engine = available[0] if available else "objdump"
        
        # Perform decompilation
        try:
            if engine == "ghidra":
                return self._decompile_with_ghidra(binary_path, function, is_verbose)
            elif engine == "rizin":
                return self._decompile_with_rizin(binary_path, function, is_verbose)
            elif engine == "objdump":
                return self._decompile_with_objdump(binary_path, function)
            else:
                return ToolResult(
                    title="Unknown Engine",
                    body=f"Unknown decompiler engine: {engine}\n\n"
                         f"Available engines: {', '.join(available)}"
                )
        except Exception as e:
            return ToolResult(
                title="Decompilation Failed",
                body=f"Error during decompilation:\n{str(e)}\n\n"
                     f"Engine: {engine}\n"
                     f"Binary: {binary_path}\n"
                     f"Function: {function}"
            )

    def _decompile_with_ghidra(
        self,
        binary_path: Path,
        function: str,
        verbose: bool = False
    ) -> ToolResult:
        """Decompile using Ghidra headless analyzer."""
        
        # Create temporary project directory
        with tempfile.TemporaryDirectory() as project_dir:
            project_path = Path(project_dir)
            project_name = "temp_project"
            
            # Create a simple Ghidra script to decompile the function
            script_content = f'''
// Decompile function
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;

def currentProgram = getCurrentProgram()
def listing = currentProgram.getListing()
def funcMgr = currentProgram.getFunctionManager()

// Find the function
def targetFunc = null
if ("{function}".startsWith("0x") || "{function}".matches("[0-9]+")) {{
    // It's an address
    def addr = toAddr("{function}")
    targetFunc = funcMgr.getFunctionAt(addr)
}} else {{
    // It's a function name
    def funcs = funcMgr.getFunctions(true)
    for (func in funcs) {{
        if (func.getName().equals("{function}") || func.getName().contains("{function}")) {{
            targetFunc = func
            break
        }}
    }}
}}

if (targetFunc == null) {{
    println("ERROR: Function '{function}' not found")
    println("\\nAvailable functions:")
    def funcs = funcMgr.getFunctions(true)
    def count = 0
    for (func in funcs) {{
        println("  " + func.getName() + " @ " + func.getEntryPoint())
        count++
        if (count > 50) {{
            println("  ... (showing first 50)")
            break
        }}
    }}
}} else {{
    println("Decompiling function: " + targetFunc.getName() + " @ " + targetFunc.getEntryPoint())
    println("")
    
    // Decompile
    def decompiler = new DecompInterface()
    decompiler.openProgram(currentProgram)
    def results = decompiler.decompileFunction(targetFunc, 60, null)
    
    if (results.decompileCompleted()) {{
        println(results.getDecompiledFunction().getC())
    }} else {{
        println("Decompilation failed: " + results.getErrorMessage())
    }}
    
    decompiler.dispose()
}}
'''
            
            script_file = project_path / "decompile.java"
            script_file.write_text(script_content)
            
            # Run Ghidra headless
            cmd = [
                "analyzeHeadless",
                str(project_path),
                project_name,
                "-import", str(binary_path),
                "-scriptPath", str(project_path),
                "-postScript", "decompile.java"
            ]
            
            if not verbose:
                cmd.append("-noanalysis")
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                output = result.stdout
                errors = result.stderr
                
                # Extract decompiled code from output
                lines = output.split("\n")
                decompiled_lines = []
                capture = False
                
                for line in lines:
                    if "Decompiling function:" in line or capture:
                        capture = True
                        decompiled_lines.append(line)
                    if "ERROR: Function" in line:
                        decompiled_lines.append(line)
                        capture = True
                
                if decompiled_lines:
                    body = "\n".join(decompiled_lines)
                else:
                    body = f"Ghidra Output:\n{output}\n\n"
                    if errors:
                        body += f"Errors:\n{errors}"
                
                return ToolResult(
                    title=f"Ghidra Decompilation: {function}",
                    body=body
                )
                
            except subprocess.TimeoutExpired:
                return ToolResult(
                    title="Decompilation Timeout",
                    body="Ghidra analysis timed out after 120 seconds.\n"
                         "Try using a smaller binary or specify a specific function."
                )
            except FileNotFoundError:
                return ToolResult(
                    title="Ghidra Not Found",
                    body="Ghidra 'analyzeHeadless' command not found.\n"
                         "Please install Ghidra and ensure it's in your PATH."
                )

    def _decompile_with_rizin(
        self,
        binary_path: Path,
        function: str,
        verbose: bool = False
    ) -> ToolResult:
        """Decompile using Rizin/r2dec."""
        
        # Check which tool is available
        rizin_bin = shutil.which("rizin") or shutil.which("r2")
        if not rizin_bin:
            return ToolResult(
                title="Rizin Not Found",
                body="Rizin or radare2 not found. Please install rizin."
            )
        
        # Rizin commands to analyze and decompile
        commands = [
            "aaa",  # Analyze all
            f"s {function}",  # Seek to function
            "pdf",  # Print disassembly of function
        ]
        
        # Add r2dec/pdd if available
        commands.append("pdd")  # Try decompilation
        
        cmd = [
            rizin_bin,
            "-q",  # Quiet
            "-c", "; ".join(commands),
            str(binary_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output = result.stdout
            errors = result.stderr
            
            if "Cannot find function" in output or not output.strip():
                # Try listing functions
                list_cmd = [rizin_bin, "-q", "-c", "aaa; afl", str(binary_path)]
                list_result = subprocess.run(list_cmd, capture_output=True, text=True, timeout=30)
                
                body = f"Function '{function}' not found.\n\n"
                body += "Available functions:\n"
                body += list_result.stdout or "(no functions found)"
                
                return ToolResult(
                    title="Function Not Found",
                    body=body
                )
            
            body = f"Rizin Analysis for function: {function}\n\n"
            body += output
            
            if errors and verbose:
                body += f"\n\nWarnings/Errors:\n{errors}"
            
            return ToolResult(
                title=f"Rizin Decompilation: {function}",
                body=body
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                title="Analysis Timeout",
                body="Rizin analysis timed out after 60 seconds."
            )
        except Exception as e:
            return ToolResult(
                title="Rizin Error",
                body=f"Error running Rizin: {str(e)}"
            )

    def _decompile_with_objdump(
        self,
        binary_path: Path,
        function: str
    ) -> ToolResult:
        """Basic disassembly using objdump (fallback option)."""
        
        if not shutil.which("objdump"):
            return ToolResult(
                title="objdump Not Found",
                body="objdump not found. Please install binutils."
            )
        
        # Try to disassemble the binary
        cmd = [
            "objdump",
            "-d",  # Disassemble
            "-M", "intel",  # Intel syntax
            "-C",  # Demangle C++ names
            str(binary_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            
            # Try to find the specific function
            if function and function != "main":
                lines = output.split("\n")
                func_lines = []
                capturing = False
                
                for line in lines:
                    if f"<{function}>" in line or f"<{function}@" in line:
                        capturing = True
                    
                    if capturing:
                        func_lines.append(line)
                        
                        # Stop at next function
                        if line.strip() and ":" in line and "<" in line and len(func_lines) > 1:
                            if f"<{function}>" not in line:
                                break
                
                if func_lines:
                    output = "\n".join(func_lines[:-1])  # Remove the next function line
                else:
                    output = f"Function '{function}' not found in disassembly.\n\n" + output[:5000]
            
            body = f"Objdump Disassembly (Basic):\n\n{output}"
            
            if len(output) > 10000:
                body = body[:10000] + "\n\n... (output truncated)"
            
            return ToolResult(
                title=f"objdump Disassembly: {function}",
                body=body
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                title="Disassembly Timeout",
                body="objdump timed out after 30 seconds."
            )
        except Exception as e:
            return ToolResult(
                title="objdump Error",
                body=f"Error running objdump: {str(e)}"
            )


__all__ = ["ExeDecompiler"]
