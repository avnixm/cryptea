"""Offline helpers for analysing classical RSA challenge scenarios."""

from __future__ import annotations

import json
import math
import random
from typing import Dict, List, Optional, Sequence, Tuple

from ..base import ToolResult


class RSAToolkit:
    name = "RSA Toolkit"
    description = "Analyse moduli, detect small-e issues, and assemble CRT recoveries."
    category = "Crypto & Encoding"

    def run(
        self,
        mode: str = "analyse",
        n: str = "",
        e: str = "65537",
        ciphertext: str = "",
        known_factors: str = "",
        factor_limit: str = "500000",
        instances: str = "",
    ) -> ToolResult:
        mode_normalised = (mode or "analyse").strip().lower()
        if mode_normalised == "analyse":
            return self._analyse_modulus(n, e, ciphertext, known_factors, factor_limit)
        if mode_normalised == "crt":
            return self._hastad_crt(instances, e)
        raise ValueError("mode must be 'analyse' or 'crt'")

    # ------------------------------------------------------------------
    # Analyse mode
    # ------------------------------------------------------------------
    def _analyse_modulus(
        self,
        n_value: str,
        e_value: str,
        ciphertext: str,
        known_factors: str,
        factor_limit: str,
    ) -> ToolResult:
        if not n_value:
            raise ValueError("Provide modulus n")

        n = self._parse_int(n_value)
        e = self._parse_int(e_value or "65537")
        factors = self._collect_factors(n, known_factors)

        limit = int(factor_limit or "0")
        if n > 1 and self._product(factors) != n:
            trial_limit = max(limit, 0)
            factors = self._factor(n, trial_limit)

        result: Dict[str, object] = {
            "n": str(n),
            "bit_length": n.bit_length(),
            "factors": [str(factor) for factor in factors] if factors else [],
            "factored": self._product(factors) == n,
        }

        notes: List[str] = []
        phi: Optional[int] = None
        if self._product(factors) == n and len(factors) >= 2:
            phi = 1
            for factor in factors:
                phi *= factor - 1
            result["phi"] = str(phi)

        d: Optional[int] = None
        if phi and math.gcd(e, phi) == 1:
            d = pow(e, -1, phi)
            result["d"] = str(d)
        elif phi:
            notes.append("Public exponent and totient are not coprime; modular inverse unavailable.")

        plaintext_preview: Optional[Dict[str, object]] = None
        if ciphertext:
            c = self._parse_int(ciphertext)
            if d is not None:
                plaintext_preview = self._decrypt_preview(c, d, n)
            elif e <= 5:
                root = self._integer_root(c, e)
                if root is not None and pow(root, e) == c:
                    as_bytes = self._int_to_bytes(root)
                    plaintext_preview = {
                        "method": "small-e root",
                        "value": root,
                        "hex": as_bytes.hex(),
                        "text": self._safe_ascii(as_bytes),
                    }
                    notes.append("Ciphertext is a perfect e-th power. Plaintext recovered without private key.")
        if plaintext_preview:
            result["plaintext"] = plaintext_preview

        if e <= 5:
            notes.append("Detected small public exponent (<=5); ensure message padding or CRT attack assumptions hold.")

        result["notes"] = notes
        return ToolResult(title="RSA analysis", body=json.dumps(result, indent=2), mime_type="application/json")

    # ------------------------------------------------------------------
    # CRT / Håstad helpers
    # ------------------------------------------------------------------
    def _hastad_crt(self, instances: str, e_value: str) -> ToolResult:
        lines = [line.strip() for line in instances.splitlines() if line.strip()]
        if len(lines) < 2:
            raise ValueError("Provide at least two ciphertext,modulus pairs")

        pairs: List[Tuple[int, int]] = []
        for line in lines:
            if "," in line:
                c_str, n_str = line.split(",", 1)
            elif " " in line:
                c_str, n_str = line.split(None, 1)
            else:
                raise ValueError("Each line must contain ciphertext and modulus separated by comma or space")
            pairs.append((self._parse_int(c_str), self._parse_int(n_str)))

        e = self._parse_int(e_value or "3")
        combined_c, combined_n = self._crt_combine(pairs)
        root = self._integer_root(combined_c, e)
        if root is None or pow(root, e) != combined_c:
            raise ValueError("Combined value is not a perfect e-th power. Provide more instances or verify inputs.")

        plaintext_bytes = self._int_to_bytes(root)
        payload = {
            "ciphertexts": [str(c) for c, _ in pairs],
            "moduli": [str(n) for _, n in pairs],
            "combined_c": str(combined_c),
            "combined_modulus": str(combined_n),
            "plaintext_hex": plaintext_bytes.hex(),
            "plaintext_text": self._safe_ascii(plaintext_bytes),
        }
        return ToolResult(title="RSA CRT recovery", body=json.dumps(payload, indent=2), mime_type="application/json")

    # ------------------------------------------------------------------
    # Number theory helpers
    # ------------------------------------------------------------------
    def _parse_int(self, value: str) -> int:
        return int(value.strip(), 0)

    def _collect_factors(self, n: int, csv: str) -> List[int]:
        factors: List[int] = []
        if csv:
            for chunk in csv.split(","):
                chunk = chunk.strip()
                if chunk:
                    factors.append(self._parse_int(chunk))
        return factors

    def _product(self, values: Sequence[int]) -> int:
        result = 1
        for value in values:
            result *= value
        return result

    def _factor(self, n: int, limit: int) -> List[int]:
        factors: List[int] = []
        remainder = n
        bound = max(2, limit)
        candidate = 2
        while candidate <= bound and candidate * candidate <= remainder:
            while remainder % candidate == 0:
                factors.append(candidate)
                remainder //= candidate
            candidate = 3 if candidate == 2 else candidate + 2
        if remainder != 1:
            if remainder != n:
                factors.append(remainder)
            else:
                pollard = self._pollards_rho(remainder)
                if pollard and pollard not in {1, remainder}:
                    factors.extend(self._factor(pollard, limit))
                    factors.extend(self._factor(remainder // pollard, limit))
                else:
                    factors.append(remainder)
        return sorted(factors)

    def _pollards_rho(self, n: int) -> Optional[int]:
        if n % 2 == 0:
            return 2
        if n % 3 == 0:
            return 3
        for _ in range(5):
            x = random.randrange(2, n - 1)
            y = x
            c = random.randrange(1, n - 1)
            d = 1
            while d == 1:
                x = (x * x + c) % n
                y = (y * y + c) % n
                y = (y * y + c) % n
                d = math.gcd(abs(x - y), n)
                if d == n:
                    break
            if 1 < d < n:
                return d
        return None

    def _decrypt_preview(self, ciphertext: int, d: int, n: int) -> Dict[str, object]:
        message = pow(ciphertext, d, n)
        message_bytes = self._int_to_bytes(message)
        return {
            "method": "private key decrypt",
            "value": message,
            "hex": message_bytes.hex(),
            "text": self._safe_ascii(message_bytes),
        }

    def _integer_root(self, value: int, exponent: int) -> Optional[int]:
        if exponent <= 0:
            return None
        root = int(round(value ** (1 / exponent)))
        while pow(root, exponent) > value:
            root -= 1
        while pow(root + 1, exponent) <= value:
            root += 1
        if pow(root, exponent) == value:
            return root
        return None

    def _crt_combine(self, pairs: Sequence[Tuple[int, int]]) -> Tuple[int, int]:
        total_modulus = 1
        for _, modulus in pairs:
            total_modulus *= modulus

        total = 0
        for ciphertext, modulus in pairs:
            partial = total_modulus // modulus
            inverse = pow(partial, -1, modulus)
            total += ciphertext * partial * inverse
        return total % total_modulus, total_modulus

    def _int_to_bytes(self, value: int) -> bytes:
        if value == 0:
            return b"\x00"
        length = (value.bit_length() + 7) // 8
        return value.to_bytes(length, "big")

    def _safe_ascii(self, data: bytes) -> str:
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            decoded = data.decode("utf-8", errors="replace")
        return ''.join(char if 32 <= ord(char) < 127 else '.' for char in decoded)