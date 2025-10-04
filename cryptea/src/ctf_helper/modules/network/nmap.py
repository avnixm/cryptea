"""Local nmap wrapper (opt-in) for offline scanning.

This module only runs the locally installed `nmap` binary. It respects an
opt-in consent flag stored in the user's config directory.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, NamedTuple, Sequence

from ..base import ToolResult
from ...data_paths import user_config_dir


CONSENT_FILE = user_config_dir() / "network_consent.json"


def network_consent_enabled() -> bool:
    try:
        if not CONSENT_FILE.exists():
            return False
        data = json.loads(CONSENT_FILE.read_text())
        return bool(data.get("enabled", False))
    except Exception:
        return False


def set_network_consent(enabled: bool) -> None:
    payload = {"enabled": bool(enabled)}
    CONSENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONSENT_FILE.write_text(json.dumps(payload))


def is_nmap_available() -> bool:
    return shutil.which("nmap") is not None


class NmapProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[NmapProfile] = (
    NmapProfile(
        "quick",
        "Quick",
        "Fast scan of top 100 TCP ports with aggressive timing",
        ("-T4", "-F"),
    ),
    NmapProfile(
        "default",
        "Default",
        "Balanced scan using nmap defaults",
        (),
    ),
    NmapProfile(
        "full",
        "Full TCP",
        "Scan all 65535 TCP ports with faster timing",
        ("-T4", "-p-"),
    ),
    NmapProfile(
        "aggressive",
        "Aggressive",
        "Includes OS detection, scripts, and traceroute (-A)",
        ("-T4", "-A"),
    ),
)

PROFILE_ARGS: Dict[str, Sequence[str]] = {profile.profile_id: profile.args for profile in PROFILE_CHOICES}


@dataclass
class NmapRow:
    host: str
    port: str
    proto: str
    service: str
    banner: str
    script: str


def _parse_nmap_xml(xml_text: str) -> List[NmapRow]:
    rows: List[NmapRow] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return rows
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "?"
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            portid = p.get("portid", "?")
            proto = p.get("protocol", "?")
            state = p.find("state")
            if state is not None and state.get("state") != "open":
                continue
            service_el = p.find("service")
            service = service_el.get("name") if service_el is not None else "?"
            banner_parts: List[str] = []
            for k in ("product", "version", "extrainfo"):
                v = service_el.get(k) if service_el is not None else None
                if v:
                    banner_parts.append(v)
            banner = " ".join(banner_parts)
            script_out: List[str] = []
            for sc in p.findall("script"):
                out = sc.get("output")
                if out:
                    script_out.append(out)
            # Ensure addr and service are str, not None
            rows.append(NmapRow(
                addr if addr is not None else "?",
                portid if portid is not None else "?",
                proto if proto is not None else "?",
                service if service is not None else "?",
                banner,
                " | ".join(script_out)
            ))
    return rows


class NmapTool:
    name = "Nmap"
    description = "Run local nmap scans (opt-in)."
    category = "Network"

    def run(
        self,
        target: str,
        profile: str = "default",
        extra: str = "",
        os_detect: str = "0",
        version_detect: str = "1",
        default_scripts: str = "0",
        skip_ping: str = "0",
        ports: str = "",
    ) -> ToolResult:
        if not network_consent_enabled():
            raise RuntimeError("Network modules disabled. Enable in settings.")
        if not is_nmap_available():
            raise RuntimeError("nmap not found in PATH. Install nmap locally.")
        if not target.strip():
            raise ValueError("Target is required")
        args: List[str] = ["nmap", "-oX", "-"]
        args.extend(PROFILE_ARGS.get(profile, ()))
        if _is_truthy(version_detect):
            args.append("-sV")
        if _is_truthy(os_detect):
            args.append("-O")
        if _is_truthy(default_scripts):
            args.append("-sC")
        if _is_truthy(skip_ping):
            args.append("-Pn")
        if ports.strip():
            args.extend(["-p", ports.strip()])
        if extra.strip():
            try:
                args.extend(shlex.split(extra, comments=False, posix=True))
            except ValueError as exc:
                raise ValueError(f"Invalid extra arguments: {exc}") from exc
        args.append(target)

        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(proc.stderr.strip() or "nmap failed")
        rows = _parse_nmap_xml(proc.stdout)
        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        body_lines.append(_format_rows(rows))
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Warnings/Notes:")
            body_lines.append(proc.stderr.strip())
        return ToolResult(
            title=f"nmap results for {target}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )


def _is_truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "on"}


def _format_rows(rows: Sequence[NmapRow]) -> str:
    if not rows:
        return "No open ports reported."
    headers = ("Host", "Port", "Proto", "Service", "Banner", "Scripts")
    table: List[Sequence[str]] = [
        (r.host, r.port, r.proto, r.service, _clip(r.banner), _clip(r.script))
        for r in rows
    ]
    widths = [len(h) for h in headers]
    for row in table:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))
    divider = "  ".join("-" * w for w in widths)
    header_line = "  ".join(_pad(headers[idx], widths[idx]) for idx in range(len(headers)))
    lines = [header_line, divider]
    for row in table:
        lines.append("  ".join(_pad(cell, widths[idx]) for idx, cell in enumerate(row)))
    return "\n".join(lines)


def _pad(text: str, width: int) -> str:
    return text.ljust(width)


def _clip(text: str, max_len: int = 48) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"
