"""Helpers for diffing two binaries."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

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
    ) -> ToolResult:
        src = Path(original).expanduser()
        dst = Path(modified).expanduser()
        if not src.exists():
            raise FileNotFoundError(src)
        if not dst.exists():
            raise FileNotFoundError(dst)

        executor, label = self._select_tool(tool)
        body = executor(src, dst, extra)
        title = f"{label} diff: {src.name} vs {dst.name}"
        return ToolResult(title=title, body=body)

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


__all__ = ["BinaryDiffTool"]
