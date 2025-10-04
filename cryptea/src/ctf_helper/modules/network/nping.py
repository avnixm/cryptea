"""nping wrapper (opt-in) for local packet crafting/testing."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import List

from ..base import ToolResult
from .nmap import network_consent_enabled


def is_nping_available() -> bool:
    return shutil.which("nping") is not None


class NpingTool:
    name = "nping"
    description = "Send crafted packets locally (consent required)."
    category = "Network"

    def run(self, target: str, proto: str = "tcp", dport: str = "80", payload: str = "", rate: str = "1") -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_nping_available():
            raise RuntimeError("nping not found in PATH")
        if not target.strip():
            raise ValueError("Target is required")
        args: List[str] = ["nping", "--rate", rate]
        if proto.lower() == "tcp":
            args += ["--tcp", "-p", dport]
        elif proto.lower() == "udp":
            args += ["--udp", "-p", dport]
        else:
            args += ["--icmp"]
        if payload:
            args += ["--data", payload.encode().hex()]
        args.append(target)
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return ToolResult(title="nping", body=proc.stdout or proc.stderr)



