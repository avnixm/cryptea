"""Angr helper for binary analysis and symbolic execution."""

from __future__ import annotations

from pathlib import Path
from typing import List

from ..base import ToolResult


def is_angr_available() -> bool:
    """Check if angr is available via Python."""
    try:
        import angr  # type: ignore
        return True
    except ImportError:
        return False


class AngrHelperTool:
    name = "Angr Helper"
    description = "Binary analysis framework for symbolic execution."
    category = "Reverse"

    def run(
        self,
        binary_file: str,
        find_address: str = "",
        avoid_address: str = "",
        analysis_type: str = "cfg",
        extra: str = "",
    ) -> ToolResult:
        """
        Run angr analysis on a binary.
        
        analysis_type options:
        - cfg: Control Flow Graph analysis
        - info: Basic binary information
        - functions: List functions
        - symbolic: Simple symbolic execution (requires find_address)
        """
        if not is_angr_available():
            raise RuntimeError("angr not installed. Install with: pip install angr")

        binary_path = Path(binary_file).expanduser()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_file}")

        result_lines: List[str] = []
        result_lines.append(f"Binary: {binary_path.name}")
        result_lines.append(f"Analysis: {analysis_type}")
        result_lines.append("")

        try:
            import angr  # type: ignore

            # Load the binary
            result_lines.append("Loading binary...")
            proj = angr.Project(str(binary_path), auto_load_libs=False)
            result_lines.append(f"Architecture: {proj.arch.name}")
            result_lines.append(f"Entry point: {hex(proj.entry)}")
            result_lines.append("")

            if analysis_type == "info":
                # Basic information
                result_lines.append("Binary Information:")
                result_lines.append(f"  Filename: {proj.filename}")
                result_lines.append(f"  Architecture: {proj.arch.name}")
                result_lines.append(f"  Entry point: {hex(proj.entry)}")
                result_lines.append(f"  Base address: {hex(proj.loader.main_object.min_addr)}")
                result_lines.append(f"  Max address: {hex(proj.loader.main_object.max_addr)}")

            elif analysis_type == "cfg":
                # Control Flow Graph
                result_lines.append("Generating CFG (this may take a while)...")
                cfg = proj.analyses.CFGFast()
                result_lines.append(f"CFG nodes: {len(cfg.graph.nodes())}")
                result_lines.append(f"CFG edges: {len(cfg.graph.edges())}")
                result_lines.append("")
                result_lines.append("Functions found:")
                for func_addr in sorted(cfg.kb.functions.keys())[:20]:
                    func = cfg.kb.functions[func_addr]
                    result_lines.append(f"  {hex(func_addr)}: {func.name}")
                if len(cfg.kb.functions) > 20:
                    result_lines.append(f"  ... and {len(cfg.kb.functions) - 20} more")

            elif analysis_type == "functions":
                # List functions
                result_lines.append("Analyzing functions...")
                cfg = proj.analyses.CFGFast()
                result_lines.append(f"Total functions: {len(cfg.kb.functions)}")
                result_lines.append("")
                result_lines.append("Functions:")
                for func_addr in sorted(cfg.kb.functions.keys()):
                    func = cfg.kb.functions[func_addr]
                    result_lines.append(f"  {hex(func_addr)}: {func.name} (size: {func.size} bytes)")

            elif analysis_type == "symbolic":
                # Simple symbolic execution
                if not find_address.strip():
                    raise ValueError("find_address is required for symbolic execution")
                
                find_addr = int(find_address.strip(), 16) if find_address.strip().startswith("0x") else int(find_address.strip())
                
                result_lines.append(f"Running symbolic execution to find address {hex(find_addr)}...")
                
                state = proj.factory.entry_state()
                simgr = proj.factory.simulation_manager(state)
                
                # Set up avoid addresses if provided
                avoid_addrs = []
                if avoid_address.strip():
                    for addr_str in avoid_address.split(","):
                        addr = int(addr_str.strip(), 16) if addr_str.strip().startswith("0x") else int(addr_str.strip())
                        avoid_addrs.append(addr)
                
                # Explore
                if avoid_addrs:
                    simgr.explore(find=find_addr, avoid=avoid_addrs)
                else:
                    simgr.explore(find=find_addr)
                
                if simgr.found:
                    result_lines.append(f"Found {len(simgr.found)} solution(s)!")
                    for i, found_state in enumerate(simgr.found[:5], 1):
                        result_lines.append(f"\nSolution {i}:")
                        # Try to get stdin
                        try:
                            stdin = found_state.posix.dumps(0)
                            result_lines.append(f"  Input: {stdin}")
                        except:
                            result_lines.append("  (Could not extract input)")
                else:
                    result_lines.append("No solution found.")

            else:
                raise ValueError(f"Unknown analysis type: {analysis_type}")

        except Exception as e:
            result_lines.append("")
            result_lines.append(f"Error: {str(e)}")
            import traceback
            result_lines.append("")
            result_lines.append("Traceback:")
            result_lines.append(traceback.format_exc())

        return ToolResult(
            title=f"Angr: {binary_path.name}",
            body="\n".join(result_lines),
            mime_type="text/plain",
        )

