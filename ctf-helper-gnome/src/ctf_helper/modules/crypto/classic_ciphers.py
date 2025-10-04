"""Classic cipher helpers that run fully offline."""

from __future__ import annotations

from typing import Dict, List

from ..base import ToolResult


class CaesarCipherTool:
    name = "Caesar Cipher"
    description = "Encrypt, decrypt, or brute force Caesar shifts with custom alphabets."
    category = "Crypto & Encoding"

    def run(
        self,
        text: str,
        shift: str = "13",
        mode: str = "encrypt",
        alphabet: str = "",
        include_digits: str = "false",
    ) -> ToolResult:
        if not text:
            return ToolResult(title="Caesar Cipher", body="")

        alpha = self._normalise_alphabet(alphabet, include_digits)
        mode_normalised = (mode or "encrypt").strip().lower()

        if mode_normalised in {"bruteforce", "brute", "auto"}:
            lines: List[str] = []
            for amount in range(len(alpha)):
                shifted = self._apply_shift(text, amount, alpha)
                lines.append(f"{amount:02d}: {shifted}")
            body = "\n".join(lines)
            return ToolResult(title="Caesar brute force", body=body)

        amount = int(shift)
        if mode_normalised in {"decrypt", "decode", "dec"}:
            amount = -amount

        shifted_text = self._apply_shift(text, amount, alpha)
        title = "Decrypt" if amount < 0 else "Encrypt"
        return ToolResult(title=f"{title} with shift {amount}", body=shifted_text)

    def _normalise_alphabet(self, alphabet: str, include_digits: str) -> str:
        base = alphabet.strip() or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if str(include_digits).strip().lower() in {"1", "true", "yes", "on"}:
            base += "0123456789"
        seen: Dict[str, None] = {}
        for char in base:
            upper = char.upper()
            if upper not in seen:
                seen[upper] = None
        if len(seen) < 2:
            raise ValueError("Alphabet must contain at least two unique characters")
        return "".join(seen.keys())

    def _apply_shift(self, text: str, amount: int, alphabet: str) -> str:
        length = len(alphabet)
        offset = amount % length
        upper_map = {char: idx for idx, char in enumerate(alphabet)}
        lower_alphabet = alphabet.lower()
        lower_map = {char: idx for idx, char in enumerate(lower_alphabet)}

        result: List[str] = []
        for char in text:
            if char in upper_map:
                idx = upper_map[char]
                result.append(alphabet[(idx + offset) % length])
            elif char in lower_map:
                idx = lower_map[char]
                result.append(lower_alphabet[(idx + offset) % length])
            else:
                result.append(char)
        return "".join(result)


class VigenereCipherTool:
    name = "Vigenère Cipher"
    description = "Encrypt or decrypt with optional autokey and custom alphabets."
    category = "Crypto & Encoding"

    def run(
        self,
        text: str,
        key: str,
        mode: str = "encrypt",
        alphabet: str = "",
        include_digits: str = "false",
        autokey: str = "false",
    ) -> ToolResult:
        if not key:
            raise ValueError("Key is required")
        alpha = self._normalise_alphabet(alphabet, include_digits)
        key_indices = self._prepare_key(key, alpha)
        if not key_indices:
            raise ValueError("Key must contain characters from the alphabet")

        autokey_enabled = self._truthy(autokey)
        mode_normalised = (mode or "encrypt").strip().lower()
        direction = 1 if mode_normalised != "decrypt" else -1

        lower_alpha = alpha.lower()
        result: List[str] = []
        dynamic_key = list(key_indices)
        key_idx = 0

        for char in text:
            idx = self._index_in_alphabet(char, alpha, lower_alpha)
            if idx is None:
                result.append(char)
                continue

            shift = dynamic_key[key_idx] if dynamic_key else 0
            key_idx = (key_idx + 1) % len(dynamic_key) if dynamic_key else 0

            rotated_idx = (idx + shift * direction) % len(alpha)
            rotated_char = alpha[rotated_idx] if char.isupper() else lower_alpha[rotated_idx]
            result.append(rotated_char)

            if autokey_enabled:
                if direction == 1:
                    dynamic_key.append(idx)
                else:
                    dynamic_key.append(rotated_idx)

        title = "Encrypted" if direction == 1 else "Decrypted"
        return ToolResult(title=f"{title} with Vigenère", body=''.join(result))

    def _normalise_alphabet(self, alphabet: str, include_digits: str) -> str:
        base = alphabet.strip() or "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if self._truthy(include_digits):
            base += "0123456789"
        seen: Dict[str, None] = {}
        for char in base:
            upper = char.upper()
            if upper not in seen:
                seen[upper] = None
        if len(seen) < 2:
            raise ValueError("Alphabet must contain at least two unique symbols")
        return ''.join(seen.keys())

    def _prepare_key(self, key: str, alphabet: str) -> List[int]:
        lower_alpha = alphabet.lower()
        mapping = {char: idx for idx, char in enumerate(alphabet)}
        mapping_lower = {char: idx for idx, char in enumerate(lower_alpha)}
        indices: List[int] = []
        for char in key:
            if char in mapping:
                indices.append(mapping[char])
            elif char in mapping_lower:
                indices.append(mapping_lower[char])
        return indices

    def _index_in_alphabet(self, char: str, alphabet: str, lower_alpha: str) -> int | None:
        if char in alphabet:
            return alphabet.index(char)
        if char in lower_alpha:
            return lower_alpha.index(char)
        return None

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
