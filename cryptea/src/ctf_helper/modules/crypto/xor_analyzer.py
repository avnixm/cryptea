"""Helpers for analysing XOR-based ciphertext reuse."""

from __future__ import annotations

import base64
import json
import string
from typing import Dict, List, Tuple

from ..base import ToolResult

# English letter frequency (percentage)
ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074, ' ': 13.000  # Space is very common
}


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
        if mode_normalised == "single_byte_brute":
            return self._single_byte_bruteforce(ciphertext, input_format)
        if mode_normalised == "detect_key_length":
            return self._detect_key_length(ciphertext, input_format)
        if mode_normalised == "multi_byte_crack":
            return self._multi_byte_crack(ciphertext, input_format)
        raise ValueError("mode must be known_plaintext, pairwise, apply_keystream, single_byte_brute, detect_key_length, or multi_byte_crack")

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

    def _single_byte_bruteforce(self, ciphertext: str, input_format: str) -> ToolResult:
        """Brute-force single-byte XOR encryption using frequency analysis."""
        if not ciphertext:
            raise ValueError("Provide ciphertext to brute-force")
        
        c_bytes = self._decode(ciphertext, input_format)
        candidates: List[Dict[str, object]] = []
        
        # Try all 256 possible keys
        for key in range(256):
            decrypted = bytes(b ^ key for b in c_bytes)
            score = self._score_plaintext(decrypted)
            text_preview = decrypted.decode("utf-8", errors="replace")
            
            # Check if result is printable
            printable_count = sum(1 for b in decrypted if 32 <= b < 127 or b in {9, 10, 13})
            printable_ratio = printable_count / len(decrypted) if decrypted else 0
            
            candidates.append({
                "key": key,
                "key_hex": f"0x{key:02x}",
                "key_char": chr(key) if 32 <= key < 127 else "?",
                "score": round(score, 2),
                "printable_ratio": round(printable_ratio, 3),
                "plaintext": text_preview,
                "plaintext_preview": self._preview(decrypted, 80),
                "length": len(decrypted),
            })
        
        # Sort by score (highest first)
        candidates.sort(key=lambda x: float(x["score"]), reverse=True)
        
        # Take top 20 candidates
        top_candidates = candidates[:20]
        
        payload = {
            "ciphertext_length": len(c_bytes),
            "candidates_tested": 256,
            "top_candidates": top_candidates,
            "best_key": top_candidates[0]["key"] if top_candidates else None,
            "best_plaintext": top_candidates[0]["plaintext"] if top_candidates else None,
        }
        
        return ToolResult(
            title="XOR single-byte brute-force",
            body=json.dumps(payload, indent=2),
            mime_type="application/json"
        )

    def _score_plaintext(self, data: bytes) -> float:
        """Score plaintext based on English letter frequency."""
        if not data:
            return 0.0
        
        # Count character frequencies
        char_counts: Dict[str, int] = {}
        total_chars = 0
        
        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                char = chr(byte).lower()
                char_counts[char] = char_counts.get(char, 0) + 1
                total_chars += 1
            elif byte in {9, 10, 13}:  # Tab, newline, carriage return
                char_counts[' '] = char_counts.get(' ', 0) + 1
                total_chars += 1
        
        if total_chars == 0:
            return 0.0
        
        # Calculate frequency score
        score = 0.0
        for char, count in char_counts.items():
            frequency = (count / total_chars) * 100
            expected_freq = ENGLISH_FREQ.get(char, 0.0)
            if expected_freq > 0:
                # Score based on how close actual frequency is to expected
                score += expected_freq * (1.0 - abs(frequency - expected_freq) / expected_freq)
        
        # Bonus for high printable character ratio
        printable_count = sum(1 for b in data if 32 <= b < 127 or b in {9, 10, 13})
        printable_ratio = printable_count / len(data) if data else 0
        score *= printable_ratio
        
        # Penalty for control characters (except common whitespace)
        control_count = sum(1 for b in data if 0 <= b < 32 and b not in {9, 10, 13})
        if control_count > len(data) * 0.1:  # More than 10% control chars
            score *= 0.5
        
        return score

    def _hamming_distance(self, a: bytes, b: bytes) -> int:
        """Calculate Hamming distance (number of differing bits) between two byte sequences."""
        return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

    def _normalized_hamming_distance(self, a: bytes, b: bytes) -> float:
        """Calculate normalized Hamming distance (per byte)."""
        if len(a) != len(b) or len(a) == 0:
            return float('inf')
        return self._hamming_distance(a, b) / len(a)

    def _detect_key_length(self, ciphertext: str, input_format: str, max_key_len: int = 40) -> ToolResult:
        """Detect repeating XOR key length using Hamming distance analysis."""
        if not ciphertext:
            raise ValueError("Provide ciphertext to analyze")
        
        c_bytes = self._decode(ciphertext, input_format)
        if len(c_bytes) < 4:
            raise ValueError("Ciphertext too short for key length detection")
        
        key_length_scores: List[Dict[str, object]] = []
        
        # Test key lengths from 2 to max_key_len
        for key_len in range(2, min(max_key_len + 1, len(c_bytes) // 2 + 1)):
            distances: List[float] = []
            
            # Take multiple blocks and compute normalized Hamming distance
            num_blocks = min(4, len(c_bytes) // key_len)
            if num_blocks < 2:
                continue
            
            for i in range(num_blocks - 1):
                block1 = c_bytes[i * key_len:(i + 1) * key_len]
                block2 = c_bytes[(i + 1) * key_len:(i + 2) * key_len]
                if len(block1) == len(block2) == key_len:
                    dist = self._normalized_hamming_distance(block1, block2)
                    distances.append(dist)
            
            if distances:
                avg_distance = sum(distances) / len(distances)
                # Normalize by key length (expected distance for English text is ~2-3 bits per byte)
                normalized_score = avg_distance / key_len
                key_length_scores.append({
                    "key_length": key_len,
                    "average_normalized_distance": round(avg_distance, 4),
                    "score": round(normalized_score, 4),
                    "num_blocks_tested": num_blocks,
                })
        
        # Sort by score (lower is better for English text)
        key_length_scores.sort(key=lambda x: float(x["score"]))
        
        # Take top 10 candidates
        top_candidates = key_length_scores[:10]
        
        payload = {
            "ciphertext_length": len(c_bytes),
            "max_key_length_tested": max_key_len,
            "key_length_candidates": top_candidates,
            "most_likely_length": top_candidates[0]["key_length"] if top_candidates else None,
        }
        
        return ToolResult(
            title="XOR key length detection",
            body=json.dumps(payload, indent=2),
            mime_type="application/json"
        )

    def _multi_byte_crack(self, ciphertext: str, input_format: str, key_length: int = 0) -> ToolResult:
        """Crack multi-byte repeating XOR key using frequency analysis per position."""
        if not ciphertext:
            raise ValueError("Provide ciphertext to crack")
        
        c_bytes = self._decode(ciphertext, input_format)
        
        # Auto-detect key length if not provided
        if key_length <= 0:
            detection_result = self._detect_key_length(ciphertext, input_format)
            # Parse the JSON result to get most likely length
            detection_data = json.loads(detection_result.body)
            if detection_data.get("most_likely_length"):
                key_length = int(detection_data["most_likely_length"])
            else:
                raise ValueError("Could not auto-detect key length. Provide key_length parameter.")
        
        if key_length > len(c_bytes):
            raise ValueError(f"Key length ({key_length}) exceeds ciphertext length ({len(c_bytes)})")
        
        # Break ciphertext into key-length blocks
        blocks: List[List[int]] = [[] for _ in range(key_length)]
        for i, byte in enumerate(c_bytes):
            blocks[i % key_length].append(byte)
        
        # Recover key byte by byte using single-byte XOR brute-force
        recovered_key: List[int] = []
        key_confidence: List[float] = []
        
        for pos, byte_stream in enumerate(blocks):
            # Try all 256 keys for this position
            best_key = 0
            best_score = 0.0
            
            for key in range(256):
                decrypted = bytes(b ^ key for b in byte_stream)
                score = self._score_plaintext(decrypted)
                if score > best_score:
                    best_score = score
                    best_key = key
            
            recovered_key.append(best_key)
            key_confidence.append(round(best_score, 2))
        
        # Decrypt using recovered key
        key_bytes = bytes(recovered_key)
        decrypted = bytes(c_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(c_bytes)))
        
        payload = {
            "key_length": key_length,
            "key_hex": key_bytes.hex(),
            "key_text": ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in key_bytes),
            "key_bytes": list(key_bytes),
            "key_confidence_per_position": key_confidence,
            "average_confidence": round(sum(key_confidence) / len(key_confidence), 2),
            "decrypted_plaintext": decrypted.decode("utf-8", errors="replace"),
            "decrypted_preview": self._preview(decrypted, 100),
        }
        
        return ToolResult(
            title="XOR multi-byte key recovery",
            body=json.dumps(payload, indent=2),
            mime_type="application/json"
        )