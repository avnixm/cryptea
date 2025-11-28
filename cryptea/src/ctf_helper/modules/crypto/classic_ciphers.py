"""Classic cipher helpers that run fully offline."""

from __future__ import annotations

import json
import math
from collections import Counter
from typing import Dict, List, Tuple

from ..base import ToolResult

# English letter frequency for frequency analysis attacks
ENGLISH_LETTER_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074
}


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
            candidates: List[Dict[str, object]] = []
            for amount in range(len(alpha)):
                shifted = self._apply_shift(text, amount, alpha)
                score = self._calculate_frequency_score(shifted, alpha)
                candidates.append({
                    "shift": amount,
                    "decrypted": shifted,
                    "score": round(score, 2),
                })
            
            # Sort by score (highest first)
            candidates.sort(key=lambda x: float(str(x.get("score", 0))), reverse=True)
            
            # Format output with scores
            lines: List[str] = []
            lines.append("Top candidates (sorted by frequency analysis score):\n")
            for idx, candidate in enumerate(candidates[:26], 1):
                shift_val = candidate.get("shift", 0)
                shift_int = int(str(shift_val)) if shift_val is not None else 0
                decrypted = str(candidate.get("decrypted", ""))
                score_val = candidate.get("score", 0.0)
                score_float = float(str(score_val)) if score_val is not None else 0.0
                marker = " ★ " if idx == 1 else "   "
                lines.append(f"{marker}Shift {shift_int:02d} (score: {score_float:6.2f}): {decrypted}")
            
            body = "\n".join(lines)
            return ToolResult(title="Caesar brute force (with frequency analysis)", body=body)

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

    def _calculate_frequency_score(self, text: str, alphabet: str) -> float:
        """Calculate frequency analysis score for Caesar cipher brute-force."""
        if not text:
            return 0.0
        
        # Count letter frequencies (case-insensitive)
        char_counts: Dict[str, int] = {}
        total_alpha_chars = 0
        
        text_upper = text.upper()
        for char in text_upper:
            if char in alphabet.upper():
                char_counts[char] = char_counts.get(char, 0) + 1
                total_alpha_chars += 1
        
        if total_alpha_chars == 0:
            return 0.0
        
        # Map alphabet characters to English letters for frequency comparison
        # Assume standard A-Z alphabet for frequency matching
        if len(alphabet) == 26 and alphabet.upper().startswith("A"):
            score = 0.0
            for char in char_counts:
                if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    freq = (char_counts[char] / total_alpha_chars) * 100
                    char_lower = char.lower()
                    expected_freq = ENGLISH_LETTER_FREQ.get(char_lower, 0.0)
                    if expected_freq > 0:
                        # Score based on how close we are to expected frequency
                        score += expected_freq * (1.0 - abs(freq - expected_freq) / expected_freq)
            return score
        
        # For non-standard alphabets, use basic scoring
        return total_alpha_chars / len(text) if text else 0.0


class VigenereCipherTool:
    name = "Vigenère Cipher"
    description = "Encrypt or decrypt with optional autokey and custom alphabets."
    category = "Crypto & Encoding"

    def run(
        self,
        text: str,
        key: str = "",
        mode: str = "encrypt",
        alphabet: str = "",
        include_digits: str = "false",
        autokey: str = "false",
    ) -> ToolResult:
        mode_normalised = (mode or "encrypt").strip().lower()
        
        # Handle keyword cracking mode
        if mode_normalised == "crack_keyword":
            return self._crack_keyword(text, alphabet, include_digits)
        
        # Normal encrypt/decrypt mode
        if not key:
            raise ValueError("Key is required for encrypt/decrypt mode")
        
        alpha = self._normalise_alphabet(alphabet, include_digits)
        key_indices = self._prepare_key(key, alpha)
        if not key_indices:
            raise ValueError("Key must contain characters from the alphabet")

        autokey_enabled = self._truthy(autokey)
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

    def _crack_keyword(self, ciphertext: str, alphabet: str, include_digits: str) -> ToolResult:
        """Crack Vigenère cipher using Kasiski examination and frequency analysis."""
        alpha = self._normalise_alphabet(alphabet, include_digits)
        ciphertext_clean = ''.join(c for c in ciphertext.upper() if c in alpha)
        
        if len(ciphertext_clean) < 50:
            raise ValueError("Ciphertext too short for keyword cracking (need at least 50 characters)")
        
        # Step 1: Kasiski examination to find likely keyword lengths
        keyword_lengths = self._kasiski_examination(ciphertext_clean, alpha)
        
        # Step 2: Try most likely keyword lengths
        results = []
        for length_data in keyword_lengths[:3]:  # Try top 3
            key_length_val = length_data.get("key_length")
            if not isinstance(key_length_val, int):
                key_length = int(str(key_length_val))
            else:
                key_length = key_length_val
            recovered_key = self._frequency_analysis_attack(ciphertext_clean, key_length, alpha)
            if recovered_key:
                decrypted = self._decrypt_with_key(ciphertext_clean, recovered_key, alpha)
                results.append({
                    "key_length": key_length,
                    "recovered_key": recovered_key,
                    "confidence": length_data.get("confidence", 0.0),
                    "decrypted_preview": decrypted[:100],
                    "full_decrypted": decrypted,
                })
        
        payload = {
            "ciphertext_length": len(ciphertext_clean),
            "kasiski_analysis": keyword_lengths[:10],
            "recovery_attempts": results,
            "best_result": results[0] if results else None,
        }
        
        return ToolResult(
            title="Vigenère keyword recovery",
            body=json.dumps(payload, indent=2),
            mime_type="application/json"
        )

    def _kasiski_examination(self, ciphertext: str, alphabet: str) -> List[Dict[str, object]]:
        """Find repeated n-grams and calculate likely keyword lengths."""
        # Find repeated 3-grams and 4-grams
        ngram_lengths = [3, 4]
        all_distances: List[int] = []
        
        for n in ngram_lengths:
            ngram_positions: Dict[str, List[int]] = {}
            
            # Find all n-grams and their positions
            for i in range(len(ciphertext) - n + 1):
                ngram = ciphertext[i:i+n]
                if ngram not in ngram_positions:
                    ngram_positions[ngram] = []
                ngram_positions[ngram].append(i)
            
            # Calculate distances between repeated n-grams
            for ngram, positions in ngram_positions.items():
                if len(positions) >= 2:
                    for i in range(len(positions)):
                        for j in range(i + 1, len(positions)):
                            distance = positions[j] - positions[i]
                            if distance > 0:
                                all_distances.append(distance)
        
        # Find common factors (likely keyword lengths)
        keyword_length_scores: Dict[int, int] = {}
        
        for distance in all_distances:
            # Test factors from 2 to min(40, distance//2)
            max_factor = min(40, distance // 2)
            for factor in range(2, max_factor + 1):
                if distance % factor == 0:
                    keyword_length_scores[factor] = keyword_length_scores.get(factor, 0) + 1
        
        # Convert to sorted list
        keyword_lengths: List[Dict[str, object]] = [
            {
                "key_length": length,
                "confidence": float(score),
                "occurrences": score,
            }
            for length, score in sorted(keyword_length_scores.items(), key=lambda x: x[1], reverse=True)
        ]
        
        return keyword_lengths

    def _frequency_analysis_attack(self, ciphertext: str, key_length: int, alphabet: str) -> str:
        """Recover keyword using frequency analysis per column."""
        # Split ciphertext into columns based on key length
        columns: List[List[str]] = [[] for _ in range(key_length)]
        for i, char in enumerate(ciphertext):
            if char in alphabet:
                columns[i % key_length].append(char)
        
        recovered_key = ""
        
        # For each column, find the shift that gives best English frequency match
        for col in columns:
            if not col:
                continue
            
            best_shift = 0
            best_score = 0.0
            
            # Try all possible shifts for this column
            for shift in range(len(alphabet)):
                # Decrypt column with this shift
                decrypted_col = [alphabet[(alphabet.index(c) - shift) % len(alphabet)] for c in col]
                
                # Calculate frequency match score
                freq_counter = Counter(decrypted_col)
                score = 0.0
                total_chars = len(decrypted_col)
                
                for char_lower in 'abcdefghijklmnopqrstuvwxyz':
                    char_upper = char_lower.upper()
                    if char_upper in alphabet:
                        actual_freq = (freq_counter.get(char_upper, 0) / total_chars) * 100
                        expected_freq = ENGLISH_LETTER_FREQ.get(char_lower, 0.0)
                        if expected_freq > 0:
                            # Score based on how close we are to expected frequency
                            score += expected_freq * (1.0 - abs(actual_freq - expected_freq) / expected_freq)
                
                if score > best_score:
                    best_score = score
                    best_shift = shift
            
            recovered_key += alphabet[best_shift]
        
        return recovered_key

    def _decrypt_with_key(self, ciphertext: str, key: str, alphabet: str) -> str:
        """Decrypt ciphertext using recovered key."""
        key_indices = self._prepare_key(key, alphabet)
        result = []
        key_idx = 0
        
        for char in ciphertext:
            if char not in alphabet:
                result.append(char)
                continue
            
            idx = alphabet.index(char)
            shift = key_indices[key_idx % len(key_indices)]
            rotated_idx = (idx - shift) % len(alphabet)
            result.append(alphabet[rotated_idx])
            key_idx += 1
        
        return ''.join(result)
