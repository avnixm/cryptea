"""Helpers for analysing XOR-based ciphertext reuse."""

from __future__ import annotations

import base64
import json
from typing import Dict, List

from ..base import ToolResult


class XORKeystreamAnalyzer:
    name = "XOR Analyzer"
    description = "Recover keystreams from known-plaintext and study XOR reuse."
    category = "Crypto & Encoding"

    def run(
        self,
        mode: str = "known_plaintext",
        ciphertext: str = "",
        known_plaintext: str = "",
        ciphertexts: str = "",
        input_format: str = "hex",
        keystream: str = "",
    ) -> ToolResult:
        mode_normalised = (mode or "known_plaintext").strip().lower()
        if mode_normalised == "known_plaintext":
            return self._known_plaintext(ciphertext, known_plaintext, input_format)
        if mode_normalised == "pairwise":
            return self._pairwise(ciphertexts, input_format)
        if mode_normalised == "apply_keystream":
            return self._apply_keystream(ciphertext, keystream, input_format)
        raise ValueError("mode must be known_plaintext, pairwise, or apply_keystream")

    def _known_plaintext(self, ciphertext: str, plaintext: str, input_format: str) -> ToolResult:
        if not ciphertext or not plaintext:
            raise ValueError("Provide ciphertext and known plaintext")
        c_bytes = self._decode(ciphertext, input_format)
        p_bytes = plaintext.encode("utf-8")
        if len(p_bytes) > len(c_bytes):
            raise ValueError("Known plaintext is longer than ciphertext")
        keystream = bytes(c ^ p for c, p in zip(c_bytes, p_bytes))
        recovered = bytes(c ^ k for c, k in zip(c_bytes, keystream))
        payload = {
            "keystream_hex": keystream.hex(),
            "keystream_base64": base64.b64encode(keystream).decode("utf-8"),
            "recovered_plaintext": recovered.decode("utf-8", errors="replace"),
        }
        return ToolResult(title="XOR known-plaintext", body=json.dumps(payload, indent=2), mime_type="application/json")

    def _pairwise(self, ciphertexts: str, input_format: str) -> ToolResult:
        lines = [line.strip() for line in ciphertexts.splitlines() if line.strip()]
        if len(lines) < 2:
            raise ValueError("Provide at least two ciphertexts")
        decoded = [self._decode(line, input_format) for line in lines]
        matrix: List[Dict[str, str]] = []
        for i in range(len(decoded)):
            for j in range(i + 1, len(decoded)):
                xor_bytes = self._xor_bytes(decoded[i], decoded[j])
                matrix.append({
                    "pair": f"{i}-{j}",
                    "hex": xor_bytes.hex(),
                    "text_preview": self._preview(xor_bytes),
                })
        payload = {
            "ciphertexts": lines,
            "pairwise": matrix,
        }
        return ToolResult(title="XOR pairwise analysis", body=json.dumps(payload, indent=2), mime_type="application/json")

    def _apply_keystream(self, ciphertext: str, keystream: str, input_format: str) -> ToolResult:
        if not ciphertext or not keystream:
            raise ValueError("Provide ciphertext and keystream")
        c_bytes = self._decode(ciphertext, input_format)
        k_bytes = self._decode(keystream, "hex")
        plaintext_bytes = self._xor_bytes(c_bytes, k_bytes)
        payload = {
            "plaintext_hex": plaintext_bytes.hex(),
            "plaintext_text": plaintext_bytes.decode("utf-8", errors="replace"),
        }
        return ToolResult(title="XOR keystream application", body=json.dumps(payload, indent=2), mime_type="application/json")

    def _decode(self, value: str, fmt: str) -> bytes:
        format_normalised = fmt.strip().lower()
        if format_normalised == "hex":
            cleaned = ''.join(value.split())
            return bytes.fromhex(cleaned)
        if format_normalised == "base64":
            return base64.b64decode(value)
        return value.encode("utf-8")

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        length = min(len(a), len(b))
        return bytes(x ^ y for x, y in zip(a[:length], b[:length]))

    def _preview(self, data: bytes, limit: int = 64) -> str:
        segment = data[:limit]
        return ''.join(chr(b) if 32 <= b < 127 else '.' for b in segment)