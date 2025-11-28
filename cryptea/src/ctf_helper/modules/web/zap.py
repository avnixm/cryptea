"""OWASP ZAP local integration (opt-in).

Runs locally installed ZAP and reports basic status. No remote calls.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

from ..base import ToolResult
from ...data_paths import user_config_dir, user_data_dir


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

    def run(
        self,
        action: str = "status",
        api_key: str = "",
        proxy_port: str = "8080",
        target_url: str = "",
        scan_type: str = "passive",
        spider_enabled: str = "false",
        generate_report: str = "false",
        report_format: str = "json",
    ) -> ToolResult:
        cfg = get_config()
        
        if action == "enable_proxy":
            cfg["enabled"] = True
            cfg["api_key"] = api_key or cfg.get("api_key", "")
            cfg["port"] = proxy_port or cfg.get("port", "8080")
            set_config(cfg)
            return ToolResult(title="ZAP", body="Proxy enabled locally (configure your client to 127.0.0.1:" + cfg["port"] + ")")
        
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
        
        if action == "spider":
            return self._run_spider(target_url, cfg, spider_enabled)
        
        if action == "scan":
            return self._run_scan(target_url, cfg, scan_type, spider_enabled)
        
        if action == "report":
            return self._generate_report(cfg, report_format)
        
        # status
        binary = zap_binary()
        status = {
            "binary": binary or "not found",
            "proxy_enabled": bool(cfg.get("enabled")),
            "port": cfg.get("port", "8080"),
            "api_key": "configured" if cfg.get("api_key") else "not set",
        }
        return ToolResult(title="ZAP Status", body=json.dumps(status, indent=2), mime_type="application/json")

    def _run_spider(self, target_url: str, cfg: dict, spider_enabled: str) -> ToolResult:
        """Run ZAP spider crawl."""
        api_key = cfg.get("api_key", "")
        port = cfg.get("port", "8080")
        api_base = f"http://localhost:{port}"
        
        if not target_url.strip():
            return ToolResult(title="ZAP Spider", body="Target URL is required for spider action")
        
        try:
            # Start spider
            spider_url = f"{api_base}/JSON/spider/action/scan/"
            params = {"url": target_url}
            if api_key:
                params["apikey"] = api_key
            
            req = urllib.request.Request(f"{spider_url}?{urllib.parse.urlencode(params)}")
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
            
            spider_id = result.get("scan")
            
            # Wait for completion (simplified - in production would poll status)
            time.sleep(2)
            
            return ToolResult(
                title="ZAP Spider",
                body=f"Spider started for {target_url}. Scan ID: {spider_id}\nNote: This is a simplified implementation. Use ZAP API directly for full control."
            )
        except Exception as exc:
            return ToolResult(title="ZAP Spider", body=f"Error running spider: {exc}")

    def _run_scan(self, target_url: str, cfg: dict, scan_type: str, spider_enabled: str) -> ToolResult:
        """Run ZAP scan (passive or active)."""
        if not target_url.strip():
            return ToolResult(title="ZAP Scan", body="Target URL is required for scan action")
        
        return ToolResult(
            title="ZAP Scan",
            body=f"Scan functionality requires ZAP API integration.\nTarget: {target_url}\nScan type: {scan_type}\n\n"
                 f"To use ZAP scanning:\n1. Launch ZAP: action=launch\n2. Configure proxy: action=enable_proxy\n"
                 f"3. Use ZAP API or GUI for full scanning capabilities."
        )

    def _generate_report(self, cfg: dict, report_format: str) -> ToolResult:
        """Generate ZAP report."""
        port = cfg.get("port", "8080")
        api_key = cfg.get("api_key", "")
        api_base = f"http://localhost:{port}"
        
        try:
            # Try to generate report via API
            report_url = f"{api_base}/OTHER/core/other/htmlreport/"
            if report_format == "json":
                report_url = f"{api_base}/JSON/core/view/alerts/"
            
            params = {}
            if api_key:
                params["apikey"] = api_key
            
            req_url = f"{report_url}?{urllib.parse.urlencode(params)}"
            req = urllib.request.Request(req_url)
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                report_data = resp.read()
            
            # Save report
            output_dir = user_data_dir() / "zap_reports"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            ext = "html" if report_format == "html" else "json"
            timestamp = int(time.time())
            report_file = output_dir / f"zap_report_{timestamp}.{ext}"
            report_file.write_bytes(report_data)
            
            return ToolResult(
                title="ZAP Report",
                body=f"Report generated: {report_file}\nFormat: {report_format}"
            )
        except Exception as exc:
            return ToolResult(
                title="ZAP Report",
                body=f"Error generating report: {exc}\nMake sure ZAP is running and API is accessible."
            )



