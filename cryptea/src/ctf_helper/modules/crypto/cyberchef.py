"""CyberChef-style recipe executor using Python implementations."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import urllib.parse
import zlib
from typing import Any, List

from ..base import ToolResult


class CyberChefTool:
    name = "CyberChef Recipes"
    description = "Chain multiple encoding/decoding operations (offline Python implementation)."
    category = "Crypto"

    def run(
        self,
        input_data: str,
        recipe: str = "base64_decode",
        custom_recipe: str = "",
    ) -> ToolResult:
        """
        Execute a CyberChef-style recipe on input data.
        
        Supported operations:
        - base64_decode, base64_encode
        - hex_decode, hex_encode
        - url_decode, url_encode
        - rot13
        - reverse
        - gzip_decompress, gzip_compress
        - zlib_decompress, zlib_compress
        - md5, sha1, sha256
        - from_hex, to_hex
        - from_base64, to_base64
        
        Custom recipe format: operation1,operation2,operation3
        Example: base64_decode,hex_decode,rot13
        """
        
        if not input_data.strip():
            raise ValueError("Input data is required")

        # Parse recipe
        if custom_recipe.strip():
            operations = [op.strip() for op in custom_recipe.split(",")]
        else:
            operations = [recipe.strip()]

        result = input_data.strip()
        steps: List[str] = []
        steps.append(f"Input: {self._preview(result)}")
        steps.append("")

        # Execute each operation in sequence
        for i, op in enumerate(operations, 1):
            try:
                result = self._execute_operation(op, result)
                steps.append(f"Step {i}: {op}")
                steps.append(f"  Output: {self._preview(result)}")
                steps.append("")
            except Exception as e:
                steps.append(f"Step {i}: {op}")
                steps.append(f"  ERROR: {str(e)}")
                steps.append("")
                break

        steps.append("=" * 80)
        steps.append("Final Result:")
        steps.append(result)

        return ToolResult(
            title="CyberChef Recipe Execution",
            body="\n".join(steps),
            mime_type="text/plain",
        )

    def _execute_operation(self, operation: str, data: str) -> str:
        """Execute a single operation on the data."""
        op = operation.lower().replace(" ", "_")

        # Base64 operations
        if op in ("base64_decode", "from_base64"):
            return base64.b64decode(data).decode("utf-8", errors="replace")
        elif op in ("base64_encode", "to_base64"):
            return base64.b64encode(data.encode()).decode()

        # Hex operations
        elif op in ("hex_decode", "from_hex", "unhex"):
            return bytes.fromhex(data.replace(" ", "")).decode("utf-8", errors="replace")
        elif op in ("hex_encode", "to_hex"):
            return data.encode().hex()

        # URL operations
        elif op in ("url_decode", "urldecode"):
            return urllib.parse.unquote(data)
        elif op in ("url_encode", "urlencode"):
            return urllib.parse.quote(data)

        # ROT13
        elif op == "rot13":
            import codecs
            return codecs.decode(data, "rot_13")

        # Reverse
        elif op == "reverse":
            return data[::-1]

        # Gzip
        elif op in ("gzip_decompress", "gunzip"):
            return gzip.decompress(data.encode("latin-1")).decode("utf-8", errors="replace")
        elif op in ("gzip_compress", "gzip"):
            return gzip.compress(data.encode()).decode("latin-1")

        # Zlib
        elif op in ("zlib_decompress", "inflate"):
            return zlib.decompress(data.encode("latin-1")).decode("utf-8", errors="replace")
        elif op in ("zlib_compress", "deflate"):
            return zlib.compress(data.encode()).decode("latin-1")

        # Hashing
        elif op == "md5":
            return hashlib.md5(data.encode()).hexdigest()
        elif op == "sha1":
            return hashlib.sha1(data.encode()).hexdigest()
        elif op == "sha256":
            return hashlib.sha256(data.encode()).hexdigest()
        elif op == "sha512":
            return hashlib.sha512(data.encode()).hexdigest()

        # Case operations
        elif op == "to_upper":
            return data.upper()
        elif op == "to_lower":
            return data.lower()

        # Remove whitespace
        elif op == "remove_whitespace":
            return "".join(data.split())

        # XOR with key (format: xor:KEY)
        elif op.startswith("xor:"):
            key = op.split(":", 1)[1]
            result = []
            for i, char in enumerate(data):
                result.append(chr(ord(char) ^ ord(key[i % len(key)])))
            return "".join(result)

        else:
            raise ValueError(f"Unknown operation: {operation}")

    def _preview(self, data: str, max_len: int = 100) -> str:
        """Create a preview of the data."""
        if len(data) <= max_len:
            return repr(data)
        return repr(data[:max_len]) + f"... ({len(data)} chars total)"

