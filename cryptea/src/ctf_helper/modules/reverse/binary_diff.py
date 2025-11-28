"""Helpers for diffing two binaries."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

from ..base import ToolResult


class BinaryDiffTool:
    name = "Binary Diff"
    description = "Compare two binaries via radiff2, cmp, or hash summary."
    category = "Reverse"

    def run(
        self,
        original: str,
        modified: str,
        tool: str = "auto",
        extra: str = "",
        show_stats: str = "true",
    ) -> ToolResult:
        src = Path(original).expanduser()
        dst = Path(modified).expanduser()
        if not src.exists():
            raise FileNotFoundError(src)
        if not dst.exists():
            raise FileNotFoundError(dst)

        executor, label = self._select_tool(tool)
        show_statistics = show_stats.lower() in ("true", "1", "yes")
        
        diff_output = executor(src, dst, extra)
        
        # Add statistics if requested
        if show_statistics:
            stats = self._calculate_diff_stats(src, dst)
            if stats:
                stats_text = "\n\n=== Statistics ===\n"
                stats_text += json.dumps(stats, indent=2)
                diff_output = diff_output + stats_text
        
        title = f"{label} diff: {src.name} vs {dst.name}"
        return ToolResult(title=title, body=diff_output)

    def _select_tool(self, requested: str):
        requested = requested.strip().lower()
        if requested in {"radiff2", "rizin"}:
            return self._radiff2, "radiff2"
        if requested in {"cmp"}:
            return self._cmp, "cmp"
        if requested in {"hash"}:
            return self._hash_summary, "hash"
        if shutil.which("radiff2"):
            return self._radiff2, "radiff2"
        if shutil.which("cmp"):
            return self._cmp, "cmp"
        return self._hash_summary, "hash"

    def _radiff2(self, src: Path, dst: Path, extra: str) -> str:
        binary = shutil.which("radiff2")
        if not binary:
            raise RuntimeError("radiff2 not available")
        argv = [binary, str(src), str(dst)]
        if extra.strip():
            argv += extra.split()
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.stdout or result.stderr or "(no output)"

    def _cmp(self, src: Path, dst: Path, extra: str) -> str:
        binary = shutil.which("cmp")
        if not binary:
            raise RuntimeError("cmp not available")
        argv = [binary, "-l", str(src), str(dst)]
        if extra.strip():
            argv += extra.split()
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.stdout or result.stderr or "(files are identical)"

    def _hash_summary(self, src: Path, dst: Path, _extra: str) -> str:
        data = {
            "source": self._digest_file(src),
            "target": self._digest_file(dst),
        }
        return json.dumps(data, indent=2)

    def _digest_file(self, path: Path) -> dict:
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        size = path.stat().st_size
        return {"file": str(path), "size": size, "sha256": sha256}

    def _calculate_diff_stats(self, src: Path, dst: Path) -> Dict[str, object]:
        """Calculate statistics about the differences between two binaries."""
        stats: Dict[str, object] = {}
        
        try:
            src_data = src.read_bytes()
            dst_data = dst.read_bytes()
            
            src_size = len(src_data)
            dst_size = len(dst_data)
            
            # Calculate byte-level differences
            min_size = min(src_size, dst_size)
            max_size = max(src_size, dst_size)
            
            differences = 0
            for i in range(min_size):
                if src_data[i] != dst_data[i]:
                    differences += 1
            
            # Add size difference
            if src_size != dst_size:
                differences += abs(src_size - dst_size)
            
            stats = {
                "source_size": src_size,
                "target_size": dst_size,
                "size_difference": abs(src_size - dst_size),
                "size_difference_percent": round((abs(src_size - dst_size) / max_size) * 100, 2) if max_size > 0 else 0,
                "byte_differences": differences,
                "similarity_percent": round((1 - (differences / max_size)) * 100, 2) if max_size > 0 else 100,
                "identical": differences == 0 and src_size == dst_size,
            }
            
            # Hash comparison
            src_hash = hashlib.sha256(src_data).hexdigest()
            dst_hash = hashlib.sha256(dst_data).hexdigest()
            stats["source_sha256"] = src_hash
            stats["target_sha256"] = dst_hash
            stats["hashes_match"] = src_hash == dst_hash
            
        except Exception:
            pass
        
        return stats


__all__ = ["BinaryDiffTool"]
