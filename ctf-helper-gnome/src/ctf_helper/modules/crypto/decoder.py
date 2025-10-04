"""Chainable decoder/encoder helpers inspired by CyberChef."""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import string
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote_from_bytes, unquote_to_bytes

from ..base import ToolResult

Operation = Callable[[bytes, Optional[str]], Tuple[bytes, Optional[str]]]


class DecoderWorkbenchTool:
    """Apply a sequence of encoding/decoding operations to data offline."""

    name = "Decoder Workbench"
    description = "Chain base64, hex, ROT, gzip, URL and XOR transforms offline."
    category = "Crypto & Encoding"

    def __init__(self) -> None:
        self._operations: Dict[str, Operation] = {
            "base64_decode": self._op_base64_decode,
            "base64_encode": self._op_base64_encode,
            "hex_decode": self._op_hex_decode,
            "hex_encode": self._op_hex_encode,
            "rot13": self._op_rot13,
            "rot": self._op_rot,
            "url_decode": self._op_url_decode,
            "url_encode": self._op_url_encode,
            "gzip_decompress": self._op_gzip_decompress,
            "gzip_compress": self._op_gzip_compress,
            "reverse": self._op_reverse,
            "xor": self._op_xor,
        }

    def run(self, data: str, operations: str = "", input_format: str = "text") -> ToolResult:
        if data is None:
            raise ValueError("Provide data to transform")

        current = self._initial_bytes(data, input_format)
        steps: List[Dict[str, object]] = []

        for op_name, argument in self._parse_operations(operations):
            if op_name not in self._operations:
                raise ValueError(f"Unknown operation: {op_name}")
            current, note = self._operations[op_name](current, argument)
            preview = {
                "operation": self._format_operation(op_name, argument),
                "length": len(current),
                "text_preview": self._preview_text(current),
                "hex_preview": current[:64].hex(),
            }
            if note:
                preview["note"] = note
            steps.append(preview)

        final = {
            "length": len(current),
            "text": self._safe_text(current),
            "hex": current.hex(),
            "base64": base64.b64encode(current).decode("utf-8"),
        }

        body = json.dumps({"steps": steps, "final": final}, indent=2)
        return ToolResult(title="Decoder workbench result", body=body, mime_type="application/json")

    # ------------------------------------------------------------------
    # Operation helpers
    # ------------------------------------------------------------------
    def _initial_bytes(self, data: str, input_format: str) -> bytes:
        fmt = (input_format or "text").strip().lower()
        if fmt == "hex":
            cleaned = ''.join(data.split())
            try:
                return bytes.fromhex(cleaned)
            except ValueError as exc:
                raise ValueError("Invalid hex input") from exc
        if fmt == "base64":
            try:
                return base64.b64decode(data, validate=False)
            except binascii.Error as exc:
                raise ValueError("Invalid base64 input") from exc
        return data.encode("utf-8")

    def _parse_operations(self, operations: str) -> List[Tuple[str, Optional[str]]]:
        if not operations.strip():
            return []
        parsed: List[Tuple[str, Optional[str]]] = []
        for raw in operations.split("|"):
            entry = raw.strip()
            if not entry:
                continue
            if ":" in entry:
                op, arg = entry.split(":", 1)
                parsed.append((op.strip().lower(), arg.strip()))
            else:
                parsed.append((entry.lower(), None))
        return parsed

    def _format_operation(self, name: str, argument: Optional[str]) -> str:
        return name if argument is None else f"{name}:{argument}"

    def _preview_text(self, data: bytes, limit: int = 64) -> str:
        segment = data[:limit]
        return ''.join(chr(b) if 32 <= b < 127 else '.' for b in segment)

    def _safe_text(self, data: bytes) -> str:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace")

    # individual operations -------------------------------------------------
    def _op_base64_decode(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        try:
            return base64.b64decode(data, validate=False), None
        except binascii.Error as exc:
            raise ValueError("base64 decode failed") from exc

    def _op_base64_encode(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        return base64.b64encode(data), None

    def _op_hex_decode(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        cleaned = ''.join(self._safe_text(data).split())
        try:
            return bytes.fromhex(cleaned), None
        except ValueError as exc:
            raise ValueError("hex decode failed") from exc

    def _op_hex_encode(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        return data.hex().encode("ascii"), None

    def _op_rot13(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        text = self._safe_text(data)
        translated = text.translate(str.maketrans(
            string.ascii_letters,
            string.ascii_lowercase[13:] + string.ascii_lowercase[:13] +
            string.ascii_uppercase[13:] + string.ascii_uppercase[:13],
        ))
        return translated.encode("utf-8"), None

    def _op_rot(self, data: bytes, arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        if not arg:
            raise ValueError("rot operation requires an integer argument")
        try:
            shift = int(arg)
        except ValueError as exc:
            raise ValueError("rot argument must be an integer") from exc

        shift %= 26
        text = self._safe_text(data)
        def _rotate(char: str, base: str) -> str:
            return base[(base.index(char) + shift) % 26]

        result_chars: List[str] = []
        for char in text:
            if 'a' <= char <= 'z':
                result_chars.append(_rotate(char, string.ascii_lowercase))
            elif 'A' <= char <= 'Z':
                result_chars.append(_rotate(char, string.ascii_uppercase))
            else:
                result_chars.append(char)
        return ''.join(result_chars).encode("utf-8"), None

    def _op_url_decode(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        try:
            return unquote_to_bytes(self._safe_text(data)), None
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("URL decode failed") from exc

    def _op_url_encode(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        return quote_from_bytes(data).encode("ascii"), None

    def _op_gzip_decompress(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        try:
            return gzip.decompress(data), None
        except OSError as exc:
            raise ValueError("gzip decompress failed") from exc

    def _op_gzip_compress(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        return gzip.compress(data), None

    def _op_reverse(self, data: bytes, _arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        return data[::-1], None

    def _op_xor(self, data: bytes, arg: Optional[str]) -> Tuple[bytes, Optional[str]]:
        if not arg:
            raise ValueError("xor operation requires a key (hex or ASCII)")
        key = self._parse_xor_key(arg)
        result = bytes(byte ^ key[idx % len(key)] for idx, byte in enumerate(data))
        return result, f"Applied repeating XOR with key length {len(key)}"

    def _parse_xor_key(self, value: str) -> bytes:
        candidate = value.strip()
        if candidate.startswith("0x"):
            candidate = candidate[2:]
        try:
            cleaned = ''.join(candidate.split())
            if cleaned:
                return bytes.fromhex(cleaned)
        except ValueError:
            pass
        return candidate.encode("utf-8")