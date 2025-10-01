"""Classic cipher helpers that run fully offline."""

from __future__ import annotations

from typing import List

from ..base import ToolResult


class CaesarCipherTool:
    name = "Caesar Cipher"
    description = "Apply a Caesar shift to the supplied text."
    category = "Crypto"

    def run(self, text: str, shift: str = "13") -> ToolResult:
        amount = int(shift)
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                rotated = chr((ord(char) - base + amount) % 26 + base)
                result.append(rotated)
            else:
                result.append(char)
        return ToolResult(
            title=f"Caesar shift ({amount})",
            body=''.join(result),
        )


class VigenereCipherTool:
    name = "Vigenère Cipher"
    description = "Encrypt or decrypt using a Vigenère key (set mode parameter)."
    category = "Crypto"

    def run(self, text: str, key: str, mode: str = "encrypt") -> ToolResult:
        if not key.isalpha():
            raise ValueError("Key must be alphabetic")
        result: List[str] = []
        key_shifts = [(ord(ch.upper()) - ord('A')) % 26 for ch in key]
        key_idx = 0
        direction = 1 if mode != "decrypt" else -1
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shift = key_shifts[key_idx % len(key_shifts)] * direction
                rotated = chr((ord(char) - base + shift) % 26 + base)
                result.append(rotated)
                key_idx += 1
            else:
                result.append(char)
        action = "Encrypted" if direction == 1 else "Decrypted"
        return ToolResult(title=f"{action} with Vigenère", body=''.join(result))
