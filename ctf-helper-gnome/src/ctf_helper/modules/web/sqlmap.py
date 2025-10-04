"""sqlmap wrapper (opt-in) for local testing only."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import List

from ..base import ToolResult
from ...data_paths import user_data_dir


def is_sqlmap_available() -> bool:
    return shutil.which("sqlmap") is not None


class SqlmapTool:
    name = "sqlmap"
    description = "Run sqlmap against local targets with explicit consent."
    category = "Web"

    def run(
        self,
        target: str,
        level: str = "1",
        risk: str = "1",
        options: str = "",
        method: str = "get",
        data: str = "",
        cookies: str = "",
        tamper: str = "",
        threads: str = "1",
        timeout: str = "30",
        i_understand: str = "no",
    ) -> ToolResult:
        if i_understand.lower() != "yes":
            raise RuntimeError("Consent required. Set i_understand=yes to proceed.")
        if not is_sqlmap_available():
            raise RuntimeError("sqlmap not found in PATH")
        if not target.strip():
            raise ValueError("Target is required")

        args: List[str] = ["sqlmap", "-u", target, "--batch", "--level", level, "--risk", risk]

        method_normalised = method.strip().upper() or "GET"
        if method_normalised not in {"GET", "POST", "PUT", "DELETE", "HEAD"}:
            method_normalised = "GET"
        args += ["--method", method_normalised]

        if data.strip():
            args += ["--data", data]
        if cookies.strip():
            args += ["--cookie", cookies]
        if tamper.strip():
            args += ["--tamper", tamper]

        threads_val = threads.strip() or "1"
        args += ["--threads", threads_val]

        timeout_val = timeout.strip()
        if timeout_val:
            args += ["--timeout", timeout_val]

        if options.strip():
            args += options.split()

        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        body = proc.stdout or proc.stderr
        return ToolResult(title="sqlmap", body=body)


