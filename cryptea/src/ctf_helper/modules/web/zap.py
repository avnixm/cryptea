"""OWASP ZAP local integration (opt-in).

Runs locally installed ZAP and reports basic status. No remote calls.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List

from ..base import ToolResult
from ...data_paths import user_config_dir


CONFIG = user_config_dir() / "zap_config.json"


def zap_binary() -> str | None:
    for name in ("zap.sh", "zap", "owasp-zap", "zaproxy"):  # common names
        found = shutil.which(name)
        if found:
            return found
    return None


def get_config() -> dict:
    if CONFIG.exists():
        try:
            return json.loads(CONFIG.read_text())
        except Exception:
            return {}
    return {}


def set_config(data: dict) -> None:
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(data, indent=2))


class ZapTool:
    name = "OWASP ZAP"
    description = "Launch and manage a local OWASP ZAP instance."
    category = "Web"

    def run(self, action: str = "status", api_key: str = "", proxy_port: str = "8080") -> ToolResult:
        cfg = get_config()
        if action == "enable_proxy":
            cfg["enabled"] = True
            cfg["api_key"] = api_key
            cfg["port"] = proxy_port
            set_config(cfg)
            return ToolResult(title="ZAP", body="Proxy enabled locally (configure your client to 127.0.0.1:" + proxy_port + ")")
        if action == "disable_proxy":
            cfg["enabled"] = False
            set_config(cfg)
            return ToolResult(title="ZAP", body="Proxy disabled")
        if action == "launch":
            binary = zap_binary()
            if not binary:
                return ToolResult(title="ZAP", body="ZAP binary not found. Install OWASP ZAP.")
            try:
                subprocess.Popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return ToolResult(title="ZAP", body="ZAP launched")
            except Exception as exc:
                return ToolResult(title="ZAP", body=f"Error launching ZAP: {exc}")
        # status
        binary = zap_binary()
        status = {
            "binary": binary or "not found",
            "proxy_enabled": bool(cfg.get("enabled")),
            "port": cfg.get("port", "8080"),
        }
        return ToolResult(title="ZAP Status", body=json.dumps(status, indent=2), mime_type="application/json")



