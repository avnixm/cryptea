"""Comprehensive hash identification, parsing, and cracking toolkit."""

from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import json
import math
import re
import secrets
import string
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:  # pragma: no cover - crypt availability depends on platform
    import crypt
except ImportError:  # pragma: no cover - crypt missing on some systems
    crypt = None  # type: ignore[assignment]

try:
    import bcrypt  # type: ignore[import]
except ImportError:
    bcrypt = None

from ..base import ToolResult


# Enhanced hash identification database
_HASH_LENGTH_MAP: Dict[int, List[Tuple[str, float]]] = {
    8: [("CRC32", 0.9), ("Adler32", 0.7)],
    16: [("MySQL323", 0.9), ("CRC64 (truncated)", 0.5)],
    20: [("SHA-1 (raw)", 0.8), ("MySQL4", 0.6), ("RIPEMD-160 (raw)", 0.5)],
    24: [("CRC96", 0.6)],
    28: [("SHA-224 (truncated)", 0.7), ("RIPEMD-224 (truncated)", 0.5)],
    32: [("MD5", 0.95), ("MD4", 0.8), ("NTLM", 0.85), ("LM", 0.7), ("CRC128", 0.4)],
    40: [("SHA-1", 0.95), ("RIPEMD-160", 0.8), ("MySQL5 (old)", 0.7), ("Tiger-160", 0.6)],
    48: [("SHA-384 (truncated)", 0.6), ("Tiger-192", 0.7)],
    56: [("SHA-224", 0.9), ("SHA3-224", 0.85), ("RIPEMD-224", 0.7)],
    64: [("SHA-256", 0.95), ("SHA3-256", 0.9), ("BLAKE2s", 0.8), ("GOST", 0.7), ("Whirlpool (truncated)", 0.5)],
    96: [("SHA-384", 0.95), ("SHA3-384", 0.9), ("Tiger-384", 0.6)],
    128: [("SHA-512", 0.95), ("SHA3-512", 0.9), ("BLAKE2b", 0.8), ("Whirlpool", 0.85)],
}

# Extended prefix patterns with confidence scoring
_PREFIX_PATTERNS: Dict[str, List[Tuple[str, float, str]]] = {
    # Standard Unix crypt formats
    "$1$": [("MD5 crypt", 0.98, r"^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$")],
    "$2a$": [("bcrypt", 0.98, r"^\$2a\$\d{2}\$[./0-9A-Za-z]{53}$")],
    "$2b$": [("bcrypt", 0.98, r"^\$2b\$\d{2}\$[./0-9A-Za-z]{53}$")],
    "$2y$": [("bcrypt", 0.98, r"^\$2y\$\d{2}\$[./0-9A-Za-z]{53}$")],
    "$5$": [("SHA-256 crypt", 0.98, r"^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$")],
    "$6$": [("SHA-512 crypt", 0.98, r"^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$")],
    
    # LDAP formats
    "{SSHA}": [("LDAP SSHA", 0.95, r"^\{SSHA\}[A-Za-z0-9+/=]+$")],
    "{SHA}": [("LDAP SHA", 0.95, r"^\{SHA\}[A-Za-z0-9+/=]{28}$")],
    "{MD5}": [("LDAP MD5", 0.95, r"^\{MD5\}[A-Za-z0-9+/=]{24}$")],
    
    # Database formats
    "*": [("MySQL5", 0.9, r"^\*[0-9A-Fa-f]{40}$")],
    
    # Web application formats
    "$P$": [("phpBB3", 0.95, r"^\$P\$[./0-9A-Za-z]{31}$")],
    "$H$": [("phpBB3", 0.95, r"^\$H\$[./0-9A-Za-z]{31}$")],
    "pbkdf2_sha256$": [("Django PBKDF2", 0.95, r"^pbkdf2_sha256\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$")],
    
    # Modern KDF formats
    "$argon2i$": [("Argon2i", 0.98, r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")],
    "$argon2id$": [("Argon2id", 0.98, r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")],
    "$scrypt$": [("scrypt", 0.95, r"^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")],
    
    # MSSQL formats
    "0x0100": [("MSSQL 2000", 0.9, r"^0x0100[0-9A-Fa-f]{8}[0-9A-Fa-f]{40}$")],
    "0x0200": [("MSSQL 2005+", 0.9, r"^0x0200[0-9A-Fa-f]{8}[0-9A-Fa-f]{128}$")],
}

# Special patterns for format detection
_SPECIAL_PATTERNS = [
    (r"^[0-9A-Fa-f]{13}$", [("DES crypt", 0.8)]),
    (r"^[A-Za-z0-9+/]{22}==$", [("Base64 MD5", 0.7)]),
    (r"^[A-Za-z0-9+/]{28}=$", [("Base64 SHA-1", 0.7)]),
    (r"^[A-Za-z0-9+/]{44}==$", [("Base64 SHA-256", 0.7)]),
    (r"^[A-Za-z0-9+/]{88}==$", [("Base64 SHA-512", 0.7)]),
]


def available_algorithms() -> Iterable[str]:
    """Expose hashlib algorithms that are guaranteed to exist."""

    yield from sorted(hashlib.algorithms_guaranteed)


class HashDigestTool:
    name = "Hash Digest"
    description = "Compute message digests using Python's hashlib (offline)."
    category = "Crypto & Encoding"

    def run(self, text: str = "", file: str = "", algorithm: str = "sha256") -> ToolResult:
        """Compute a digest for a string or a file."""

        algo = algorithm.lower()
        supported = {"md5", "sha1", "sha256", "sha512"}
        if algo not in supported:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        hasher = hashlib.new(algo)

        if text:
            hasher.update(text.encode("utf-8"))
        elif file:
            with open(file, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    hasher.update(chunk)
        else:
            raise ValueError("Provide text or select a file to hash")

        return ToolResult(title=f"{algorithm.upper()} digest", body=hasher.hexdigest())


class HashWorkspaceTool:
    name = "Hash Workspace"
    description = "Comprehensive hash identification, parsing, and batch analysis for CTF challenges."
    category = "Crypto & Encoding"

    def run(
        self,
        hashes: str = "",
        file_path: str = "",
        mode: str = "identify",
        known_plaintext: str = "",
        auto_decode: str = "true",
    ) -> ToolResult:
        """
        Main hash workspace entry point.
        
        Modes:
        - identify: Detect hash types with confidence scores
        - verify: Test known plaintext against hashes
        - analyze: Deep analysis including entropy and patterns
        - batch: Process multiple hashes from input or file
        """
        if not hashes.strip() and not file_path:
            raise ValueError("Provide hash values or select a file")
            
        hash_list = self._parse_input(hashes, file_path)
        if not hash_list:
            raise ValueError("No valid hashes found in input")
            
        results = []
        for i, hash_value in enumerate(hash_list):
            try:
                if mode == "identify":
                    result = self._identify_hash(hash_value, auto_decode == "true")
                elif mode == "verify":
                    result = self._verify_hash(hash_value, known_plaintext)
                elif mode == "analyze":
                    result = self._analyze_hash(hash_value, auto_decode == "true")
                elif mode == "batch":
                    result = self._batch_process(hash_value, auto_decode == "true")
                else:
                    raise ValueError(f"Unknown mode: {mode}")
                    
                result["index"] = i + 1
                results.append(result)
            except Exception as e:
                results.append({
                    "index": i + 1,
                    "input": hash_value,
                    "error": str(e),
                    "success": False
                })
        
        summary = {
            "mode": mode,
            "total_hashes": len(hash_list),
            "successful_analyses": sum(1 for r in results if r.get("success", True)),
            "results": results
        }
        
        return ToolResult(
            title=f"Hash Workspace - {mode.title()} Mode",
            body=json.dumps(summary, indent=2),
            mime_type="application/json"
        )
    
    def _parse_input(self, hashes: str, file_path: str) -> List[str]:
        """Parse input from text or file, one hash per line."""
        hash_list = []
        
        if hashes.strip():
            for line in hashes.splitlines():
                cleaned = line.strip()
                if cleaned and not cleaned.startswith('#'):  # Skip comments
                    hash_list.append(cleaned)
        
        if file_path:
            path = Path(file_path).expanduser()
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            try:
                with path.open('r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        cleaned = line.strip()
                        if cleaned and not cleaned.startswith('#'):
                            hash_list.append(cleaned)
            except Exception as e:
                raise ValueError(f"Error reading file: {e}")
        
        return hash_list
    
    def _identify_hash(self, hash_value: str, auto_decode: bool = True) -> Dict[str, Any]:
        """Advanced hash identification with confidence scoring."""
        original_hash = hash_value.strip()
        candidates = []
        
        # Try direct identification
        direct_candidates = self._direct_identify(original_hash)
        candidates.extend(direct_candidates)
        
        # Try base64 decoding if enabled
        if auto_decode:
            base64_candidates = self._try_base64_decode(original_hash)
            candidates.extend(base64_candidates)
            
            # Try hex decoding
            hex_candidates = self._try_hex_decode(original_hash)
            candidates.extend(hex_candidates)
        
        # Sort by confidence
        candidates.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        # Calculate entropy for additional insights
        entropy = self._calculate_entropy(original_hash)
        
        return {
            "input": original_hash,
            "length": len(original_hash),
            "entropy": round(entropy, 3),
            "character_analysis": self._analyze_charset(original_hash),
            "candidates": candidates[:10],  # Top 10 candidates
            "success": True,
            "auto_decode_attempted": auto_decode
        }
    
    def _direct_identify(self, hash_value: str) -> List[Dict[str, Any]]:
        """Direct hash identification based on length and patterns."""
        candidates = []
        length = len(hash_value)
        is_hex = all(c in string.hexdigits for c in hash_value.lower())
        
        # Length-based identification
        if length in _HASH_LENGTH_MAP:
            for algo_name, confidence in _HASH_LENGTH_MAP[length]:
                base_confidence = confidence
                # Boost confidence for hex strings where appropriate
                if is_hex and any(x in algo_name.lower() for x in ['md5', 'sha', 'ntlm']):
                    base_confidence += 0.05
                    
                candidates.append({
                    "algorithm": algo_name,
                    "confidence": min(base_confidence, 1.0),
                    "reason": f"Length {length} matches canonical format",
                    "hashcat_mode": self._get_hashcat_mode(algo_name),
                    "john_format": self._get_john_format(algo_name)
                })
        
        # Prefix-based identification
        for prefix, patterns in _PREFIX_PATTERNS.items():
            if hash_value.startswith(prefix):
                for algo_name, confidence, regex_pattern in patterns:
                    pattern_match = re.match(regex_pattern, hash_value) if regex_pattern else True
                    final_confidence = confidence if pattern_match else confidence * 0.7
                    
                    candidates.append({
                        "algorithm": algo_name,
                        "confidence": final_confidence,
                        "reason": f"Matches prefix '{prefix}' and pattern",
                        "pattern_verified": bool(pattern_match),
                        "hashcat_mode": self._get_hashcat_mode(algo_name),
                        "john_format": self._get_john_format(algo_name)
                    })
        
        # Special pattern matching
        for pattern, algos in _SPECIAL_PATTERNS:
            if re.match(pattern, hash_value):
                for algo_name, confidence in algos:
                    candidates.append({
                        "algorithm": algo_name,
                        "confidence": confidence,
                        "reason": f"Matches special pattern: {pattern}",
                        "hashcat_mode": self._get_hashcat_mode(algo_name),
                        "john_format": self._get_john_format(algo_name)
                    })
        
        return candidates
    
    def _try_base64_decode(self, hash_value: str) -> List[Dict[str, Any]]:
        """Attempt base64 decoding and re-identify."""
        candidates = []
        try:
            # Check if it looks like base64
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', hash_value) and len(hash_value) % 4 == 0:
                decoded = base64.b64decode(hash_value)
                hex_decoded = decoded.hex()
                
                # Re-identify the decoded value
                decoded_candidates = self._direct_identify(hex_decoded)
                for candidate in decoded_candidates:
                    candidate['algorithm'] = f"Base64({candidate['algorithm']})"
                    candidate['confidence'] *= 0.8  # Reduce confidence for decoded
                    candidate['reason'] = f"Base64 decoded: {candidate['reason']}"
                    candidate['decoded_value'] = hex_decoded
                    candidates.append(candidate)
        except Exception:
            pass  # Base64 decode failed, ignore
            
        return candidates
    
    def _try_hex_decode(self, hash_value: str) -> List[Dict[str, Any]]:
        """Attempt hex decoding for potential binary hash representations."""
        candidates = []
        try:
            if len(hash_value) % 2 == 0 and all(c in string.hexdigits for c in hash_value):
                # Try interpreting as hex-encoded binary
                decoded = bytes.fromhex(hash_value)
                if 8 <= len(decoded) <= 64:  # Reasonable hash lengths
                    candidates.append({
                        "algorithm": f"Binary hash ({len(decoded)} bytes)",
                        "confidence": 0.6,
                        "reason": f"Could be hex-encoded {len(decoded)}-byte hash",
                        "binary_length": len(decoded),
                        "hashcat_mode": "unknown",
                        "john_format": "raw-hex"
                    })
        except ValueError:
            pass
            
        return candidates
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the text."""
        if not text:
            return 0.0
            
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _analyze_charset(self, text: str) -> Dict[str, Any]:
        """Analyze character set composition."""
        charset_info = {
            "total_chars": len(text),
            "unique_chars": len(set(text)),
            "is_hex": all(c in string.hexdigits for c in text.lower()),
            "is_base64": bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', text)),
            "has_uppercase": any(c.isupper() for c in text),
            "has_lowercase": any(c.islower() for c in text),
            "has_digits": any(c.isdigit() for c in text),
            "has_special": any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in text),
            "charset_distribution": {}
        }
        
        # Character distribution
        for category, chars in [
            ("letters", string.ascii_letters),
            ("digits", string.digits),
            ("hex", string.hexdigits.lower()),
            ("base64", string.ascii_letters + string.digits + '+/=')
        ]:
            count = sum(1 for c in text if c.lower() in chars)
            charset_info["charset_distribution"][category] = {
                "count": count,
                "percentage": round(count / len(text) * 100, 1) if text else 0
            }
        
        return charset_info
    
    def _get_hashcat_mode(self, algorithm: str) -> str:
        """Map algorithm to Hashcat mode number."""
        hashcat_modes = {
            "MD5": "0", "MD4": "900", "SHA-1": "100", "SHA-224": "1300",
            "SHA-256": "1400", "SHA-384": "10800", "SHA-512": "1700",
            "SHA3-224": "17300", "SHA3-256": "17400", "SHA3-384": "17500", "SHA3-512": "17600",
            "NTLM": "1000", "LM": "3000", "bcrypt": "3200",
            "MD5 crypt": "500", "SHA-256 crypt": "7400", "SHA-512 crypt": "1800",
            "MySQL5": "300", "MSSQL 2005+": "131", "LDAP SSHA": "111",
            "phpBB3": "400", "Django PBKDF2": "10000", "Argon2": "m", 
            "scrypt": "8900", "Whirlpool": "6100", "RIPEMD-160": "6000"
        }
        
        for key, mode in hashcat_modes.items():
            if key.lower() in algorithm.lower():
                return mode
        return "unknown"
    
    def _get_john_format(self, algorithm: str) -> str:
        """Map algorithm to John the Ripper format."""
        john_formats = {
            "MD5": "raw-md5", "SHA-1": "raw-sha1", "SHA-256": "raw-sha256", "SHA-512": "raw-sha512",
            "NTLM": "nt", "LM": "lm", "bcrypt": "bcrypt",
            "MD5 crypt": "md5crypt", "SHA-256 crypt": "sha256crypt", "SHA-512 crypt": "sha512crypt",
            "MySQL5": "mysql-sha1", "MSSQL": "mssql", "LDAP": "ldap",
            "Django": "django", "phpBB3": "phpass"
        }
        
        for key, fmt in john_formats.items():
            if key.lower() in algorithm.lower():
                return fmt
        return "unknown"
    
    def _verify_hash(self, hash_value: str, plaintext: str) -> Dict[str, Any]:
        """Verify if plaintext produces the given hash."""
        if not plaintext:
            raise ValueError("Plaintext required for verification")
            
        results = []
        candidates = self._identify_hash(hash_value, auto_decode=True)
        
        for candidate in candidates["candidates"][:5]:  # Test top 5 candidates
            algo = candidate["algorithm"]
            verified = self._test_hash_match(hash_value, plaintext, algo)
            results.append({
                "algorithm": algo,
                "verified": verified,
                "confidence": candidate["confidence"]
            })
        
        return {
            "input": hash_value,
            "plaintext": plaintext,
            "verification_results": results,
            "any_verified": any(r["verified"] for r in results),
            "success": True
        }
    
    def _test_hash_match(self, hash_value: str, plaintext: str, algorithm: str) -> bool:
        """Test if plaintext produces the hash using the specified algorithm."""
        try:
            if "MD5" in algorithm:
                return hashlib.md5(plaintext.encode()).hexdigest().lower() == hash_value.lower()
            elif "SHA-1" in algorithm:
                return hashlib.sha1(plaintext.encode()).hexdigest().lower() == hash_value.lower()
            elif "SHA-256" in algorithm:
                return hashlib.sha256(plaintext.encode()).hexdigest().lower() == hash_value.lower()
            elif "SHA-512" in algorithm:
                return hashlib.sha512(plaintext.encode()).hexdigest().lower() == hash_value.lower()
            elif "NTLM" in algorithm:
                return hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest().lower() == hash_value.lower()
            # Add more algorithm tests as needed
        except Exception:
            pass
        return False
    
    def _analyze_hash(self, hash_value: str, auto_decode: bool = True) -> Dict[str, Any]:
        """Deep analysis combining identification with additional insights."""
        identification = self._identify_hash(hash_value, auto_decode)
        
        # Add cracking difficulty estimation
        difficulty = self._estimate_cracking_difficulty(hash_value, identification["candidates"])
        
        # Add format parsing for structured hashes
        parsed_components = self._parse_hash_components(hash_value)
        
        identification.update({
            "cracking_difficulty": difficulty,
            "parsed_components": parsed_components,
            "recommendations": self._generate_recommendations(identification["candidates"])
        })
        
        return identification
    
    def _batch_process(self, hash_value: str, auto_decode: bool = True) -> Dict[str, Any]:
        """Optimized processing for batch operations."""
        return self._identify_hash(hash_value, auto_decode)
    
    def _estimate_cracking_difficulty(self, hash_value: str, candidates: List[Dict]) -> Dict[str, Any]:
        """Estimate cracking difficulty based on hash type and characteristics."""
        if not candidates:
            return {"level": "unknown", "factors": []}
        
        top_candidate = candidates[0]
        algorithm = top_candidate["algorithm"].lower()
        
        difficulty_factors = []
        base_difficulty = "medium"
        
        # Algorithm-based difficulty
        if any(x in algorithm for x in ["bcrypt", "scrypt", "argon2", "pbkdf2"]):
            base_difficulty = "very_hard"
            difficulty_factors.append("Uses key derivation function")
        elif any(x in algorithm for x in ["sha-512", "sha3"]):
            base_difficulty = "hard"
            difficulty_factors.append("Strong cryptographic hash")
        elif any(x in algorithm for x in ["md5", "sha-1", "ntlm"]):
            base_difficulty = "easy"
            difficulty_factors.append("Fast hash algorithm")
        
        # Length-based factors
        if len(hash_value) > 64:
            difficulty_factors.append("Long hash format")
        
        return {
            "level": base_difficulty,
            "factors": difficulty_factors,
            "estimated_gpu_time": self._estimate_gpu_time(algorithm),
            "recommended_attack": self._recommend_attack_type(algorithm)
        }
    
    def _estimate_gpu_time(self, algorithm: str) -> str:
        """Rough GPU cracking time estimates."""
        if "bcrypt" in algorithm.lower():
            return "Hours to days (depending on cost factor)"
        elif "argon2" in algorithm.lower():
            return "Hours to weeks (depending on parameters)"
        elif any(x in algorithm.lower() for x in ["md5", "ntlm"]):
            return "Seconds to minutes (with good wordlist)"
        elif "sha-256" in algorithm.lower():
            return "Minutes to hours"
        else:
            return "Variable (depends on implementation)"
    
    def _recommend_attack_type(self, algorithm: str) -> str:
        """Recommend attack strategy based on algorithm."""
        if any(x in algorithm.lower() for x in ["bcrypt", "argon2", "scrypt"]):
            return "Dictionary attack with rules (brute force impractical)"
        elif "ntlm" in algorithm.lower():
            return "Rainbow tables or hybrid attack"
        else:
            return "Dictionary + rules, then mask attack"
    
    def _parse_hash_components(self, hash_value: str) -> Dict[str, Any]:
        """Parse structured hash formats to extract components."""
        components = {"format": "raw", "components": {}}
        
        # Unix crypt formats
        if hash_value.startswith('$'):
            parts = hash_value.split('$')
            if len(parts) >= 4:
                components.update({
                    "format": "unix_crypt",
                    "components": {
                        "identifier": parts[1],
                        "salt": parts[2] if len(parts) > 2 else None,
                        "hash": parts[3] if len(parts) > 3 else None,
                        "additional_params": parts[4:] if len(parts) > 4 else []
                    }
                })
        
        # LDAP formats
        elif hash_value.startswith('{'):
            match = re.match(r'^\{([^}]+)\}(.+)$', hash_value)
            if match:
                components.update({
                    "format": "ldap",
                    "components": {
                        "scheme": match.group(1),
                        "hash_data": match.group(2)
                    }
                })
        
        # MySQL format
        elif hash_value.startswith('*'):
            components.update({
                "format": "mysql",
                "components": {
                    "version": "5.x+",
                    "hash": hash_value[1:]
                }
            })
        
        return components
    
    def _generate_recommendations(self, candidates: List[Dict]) -> List[str]:
        """Generate actionable recommendations based on identified hash types."""
        if not candidates:
            return ["Unable to identify hash type - try manual analysis"]
        
        recommendations = []
        top_candidate = candidates[0]
        
        # Hashcat recommendation
        if top_candidate.get("hashcat_mode") != "unknown":
            recommendations.append(
                f"Try Hashcat with mode {top_candidate['hashcat_mode']}: "
                f"hashcat -m {top_candidate['hashcat_mode']} hash.txt wordlist.txt"
            )
        
        # John recommendation
        if top_candidate.get("john_format") != "unknown":
            recommendations.append(
                f"Try John the Ripper: john --format={top_candidate['john_format']} hash.txt"
            )
        
        # Algorithm-specific advice
        algorithm = top_candidate["algorithm"].lower()
        if "ntlm" in algorithm:
            recommendations.append("Consider rainbow tables or pass-the-hash attacks")
        elif "bcrypt" in algorithm:
            recommendations.append("Focus on dictionary attacks - brute force is impractical")
        elif any(x in algorithm for x in ["md5", "sha-1"]):
            recommendations.append("Fast algorithm - suitable for brute force with GPU")
        
        return recommendations


# Keep the original simpler tool for backward compatibility
class HashIdentifierTool:
    name = "Hash Identifier (Simple)"
    description = "Basic hash identification for quick analysis."
    category = "Crypto & Encoding"

    def run(self, value: str) -> ToolResult:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Provide a hash value to analyse")

        # Use the new workspace tool for identification
        workspace = HashWorkspaceTool()
        result = workspace._identify_hash(cleaned, auto_decode=True)
        
        # Format for simple output
        simple_result = {
            "input": result["input"],
            "length": result["length"],
            "entropy": result["entropy"],
            "top_candidates": result["candidates"][:3],  # Top 3 only
            "is_hex": result["character_analysis"]["is_hex"],
            "is_base64": result["character_analysis"]["is_base64"],
        }
        
        return ToolResult(title="Hash identifier", body=json.dumps(simple_result, indent=2), mime_type="application/json")


class HtpasswdGeneratorTool:
    name = "htpasswd Generator"
    description = "Generate Apache htpasswd entries for MD5/SHA crypt schemes."
    category = "Crypto & Encoding"

    def run(self, username: str, password: str, algorithm: str = "sha512", salt: str = "") -> ToolResult:
        if not username:
            raise ValueError("Username is required")
        if not password:
            raise ValueError("Password is required")

        method = algorithm.lower()
        if method == "plaintext":
            hashed = password
            salt_used: Optional[str] = None
        else:
            if crypt is None:
                raise RuntimeError("The Python 'crypt' module is unavailable on this platform")

            prefix_map = {
                "md5": "$1$",
                "sha256": "$5$",
                "sha512": "$6$",
            }
            if method not in prefix_map:
                raise ValueError("Unsupported algorithm. Choose md5, sha256, sha512, or plaintext")

            salt_used = salt or self._random_salt()
            hashed = crypt.crypt(password, prefix_map[method] + salt_used)

        entry = f"{username}:{hashed}"
        payload = {
            "entry": entry,
            "username": username,
            "algorithm": method,
            "salt": salt_used,
        }
        return ToolResult(title="htpasswd entry", body=json.dumps(payload, indent=2), mime_type="application/json")

    def _random_salt(self, length: int = 8) -> str:
        alphabet = string.ascii_letters + string.digits + "./"
        return ''.join(secrets.choice(alphabet) for _ in range(length))


class HashCrackHelperTool:
    name = "Hash Crack Helper"
    description = "Test candidate passwords against a hash digest using hashlib."
    category = "Crypto & Encoding"

    def run(
        self,
        hash_value: str,
        algorithm: str = "sha256",
        candidates: str = "",
        wordlist_path: str = "",
    ) -> ToolResult:
        digest = hash_value.strip().lower()
        if not digest:
            raise ValueError("Provide a hash value to crack")

        algo = algorithm.lower()
        if algo not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        candidates_list: List[str] = []
        if candidates.strip():
            candidates_list.extend([line.strip() for line in candidates.splitlines() if line.strip()])
        if wordlist_path:
            path = Path(wordlist_path).expanduser()
            if not path.exists():
                raise FileNotFoundError(path)
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    trimmed = line.strip()
                    if trimmed:
                        candidates_list.append(trimmed)

        if not candidates_list:
            raise ValueError("Provide inline candidates or a wordlist path")

        matches: List[str] = []
        tested = 0
        for candidate in candidates_list:
            tested += 1
            hasher = hashlib.new(algo)
            hasher.update(candidate.encode("utf-8"))
            if hasher.hexdigest() == digest:
                matches.append(candidate)

        result = {
            "hash": digest,
            "algorithm": algo,
            "tested": tested,
            "matches": matches,
            "cracked": bool(matches),
        }
        return ToolResult(title="Hash crack helper", body=json.dumps(result, indent=2), mime_type="application/json")


class HashCrackerTool:
    name = "Hash Cracker Pro"
    description = "Advanced hash cracking with multiple attack modes and security controls."
    category = "Crypto & Encoding"

    def __init__(self):
        self.max_attempts = 1000000  # Safety limit
        self.timeout_seconds = 300   # 5 minute timeout
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_224': hashlib.sha3_224,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512,
        }

    def run(
        self,
        hash_value: str,
        attack_mode: str = "dictionary",
        wordlist_path: str = "",
        charset: str = "lowercase",
        min_length: str = "1",
        max_length: str = "8",
        algorithm: str = "auto",
        rules: str = "basic",
        timeout: str = "300"
    ) -> ToolResult:
        """
        Comprehensive hash cracking tool.
        
        Attack modes:
        - dictionary: Use wordlist
        - brute_force: Try all combinations
        - hybrid: Dictionary + rules
        - mask: Custom character masks
        
        Charsets: lowercase, uppercase, digits, mixed, all, custom
        Rules: none, basic, advanced, custom
        """
        cleaned_hash = hash_value.strip()
        if not cleaned_hash:
            raise ValueError("Provide a hash to crack")

        # Parse parameters
        try:
            min_len = max(1, int(min_length))
            max_len = min(20, int(max_length))  # Reasonable limit
            timeout_sec = min(3600, int(timeout))  # Max 1 hour
        except ValueError:
            raise ValueError("Invalid numeric parameters")

        # Auto-identify algorithm if needed
        target_algorithms = []
        if algorithm == "auto":
            identifier = HashWorkspaceTool()
            identification = identifier._identify_hash(cleaned_hash, auto_decode=True)
            for candidate in identification["candidates"][:3]:  # Try top 3
                algo = self._map_algorithm_name(candidate["algorithm"])
                if algo and algo not in target_algorithms:
                    target_algorithms.append(algo)
        else:
            algo = self._map_algorithm_name(algorithm)
            if algo:
                target_algorithms = [algo]

        if not target_algorithms:
            target_algorithms = ['md5', 'sha1', 'sha256']  # Default fallback

        # Set up wordlist
        if not wordlist_path and attack_mode == "dictionary":
            wordlist_path = str(Path(__file__).parent.parent.parent.parent / "data" / "SecLists" / "common.txt")

        # Execute attack
        start_time = time.time()
        result = None
        
        try:
            if attack_mode == "dictionary":
                result = self._dictionary_attack(
                    cleaned_hash, target_algorithms, wordlist_path, rules, timeout_sec
                )
            elif attack_mode == "brute_force":
                result = self._brute_force_attack(
                    cleaned_hash, target_algorithms, charset, min_len, max_len, timeout_sec
                )
            elif attack_mode == "hybrid":
                result = self._hybrid_attack(
                    cleaned_hash, target_algorithms, wordlist_path, charset, rules, timeout_sec
                )
            elif attack_mode == "mask":
                result = self._mask_attack(
                    cleaned_hash, target_algorithms, charset, min_len, max_len, timeout_sec
                )
            else:
                raise ValueError(f"Unknown attack mode: {attack_mode}")
                
        except Exception as e:
            result = {
                "error": str(e),
                "success": False
            }

        elapsed_time = time.time() - start_time
        
        result.update({
            "hash_input": cleaned_hash,
            "attack_mode": attack_mode,
            "algorithms_tested": target_algorithms,
            "elapsed_time": round(elapsed_time, 2),
            "security_limits": {
                "max_attempts": self.max_attempts,
                "timeout_seconds": timeout_sec
            }
        })

        return ToolResult(
            title=f"Hash Cracker - {attack_mode.title()}",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    def _map_algorithm_name(self, algorithm_name: str) -> Optional[str]:
        """Map various algorithm names to internal keys."""
        algo_lower = algorithm_name.lower()
        if "md5" in algo_lower:
            return "md5"
        elif "sha-1" in algo_lower or "sha1" in algo_lower:
            return "sha1"
        elif "sha-224" in algo_lower or "sha224" in algo_lower:
            return "sha224"
        elif "sha-256" in algo_lower or "sha256" in algo_lower:
            return "sha256"
        elif "sha-384" in algo_lower or "sha384" in algo_lower:
            return "sha384"
        elif "sha-512" in algo_lower or "sha512" in algo_lower:
            return "sha512"
        elif "sha3-224" in algo_lower:
            return "sha3_224"
        elif "sha3-256" in algo_lower:
            return "sha3_256"
        elif "sha3-384" in algo_lower:
            return "sha3_384"
        elif "sha3-512" in algo_lower:
            return "sha3_512"
        return None

    def _dictionary_attack(self, target_hash: str, algorithms: List[str], wordlist_path: str, rules: str, timeout: int) -> Dict[str, Any]:
        """Execute dictionary attack with optional rules."""
        wordlist = Path(wordlist_path).expanduser()
        if not wordlist.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

        attempts = 0
        start_time = time.time()
        
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if time.time() - start_time > timeout:
                        break
                    if attempts >= self.max_attempts:
                        break

                    base_password = line.strip()
                    if not base_password:
                        continue

                    # Generate password variants based on rules
                    password_variants = self._apply_rules(base_password, rules)
                    
                    for password in password_variants:
                        attempts += 1
                        
                        for algo in algorithms:
                            if self._test_password(target_hash, password, algo):
                                return {
                                    "success": True,
                                    "password": password,
                                    "algorithm": algo.upper(),
                                    "attempts": attempts,
                                    "rule_applied": password != base_password,
                                    "base_word": base_password if password != base_password else None
                                }
                        
                        if attempts >= self.max_attempts:
                            break
                    
                    if attempts >= self.max_attempts:
                        break

        except Exception as e:
            raise Exception(f"Dictionary attack failed: {e}")

        return {
            "success": False,
            "attempts": attempts,
            "message": f"Password not found after {attempts} attempts",
            "timeout_reached": time.time() - start_time >= timeout
        }

    def _brute_force_attack(self, target_hash: str, algorithms: List[str], charset: str, min_len: int, max_len: int, timeout: int) -> Dict[str, Any]:
        """Execute brute force attack with character set."""
        charset_map = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'mixed': string.ascii_letters + string.digits,
            'all': string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'hex': string.hexdigits.lower()
        }
        
        chars = charset_map.get(charset, charset)  # Use custom if not in map
        attempts = 0
        start_time = time.time()

        try:
            for length in range(min_len, max_len + 1):
                if time.time() - start_time > timeout:
                    break
                if attempts >= self.max_attempts:
                    break

                for password_tuple in itertools.product(chars, repeat=length):
                    if time.time() - start_time > timeout:
                        break
                    if attempts >= self.max_attempts:
                        break

                    attempts += 1
                    password = ''.join(password_tuple)

                    for algo in algorithms:
                        if self._test_password(target_hash, password, algo):
                            return {
                                "success": True,
                                "password": password,
                                "algorithm": algo.upper(),
                                "attempts": attempts,
                                "password_length": len(password)
                            }

        except Exception as e:
            raise Exception(f"Brute force attack failed: {e}")

        return {
            "success": False,
            "attempts": attempts,
            "message": f"Password not found after {attempts} attempts",
            "timeout_reached": time.time() - start_time >= timeout,
            "search_space_size": self._calculate_search_space(chars, min_len, max_len)
        }

    def _hybrid_attack(self, target_hash: str, algorithms: List[str], wordlist_path: str, charset: str, rules: str, timeout: int) -> Dict[str, Any]:
        """Combine dictionary and brute force approaches."""
        # First try dictionary attack (faster)
        dict_result = self._dictionary_attack(target_hash, algorithms, wordlist_path, rules, timeout // 2)
        
        if dict_result["success"]:
            dict_result["attack_phase"] = "dictionary"
            return dict_result

        # If dictionary fails, try brute force on shorter passwords
        remaining_time = timeout - dict_result.get("elapsed_time", timeout // 2)
        if remaining_time > 0:
            brute_result = self._brute_force_attack(target_hash, algorithms, charset, 1, 6, remaining_time)
            brute_result["attack_phase"] = "brute_force"
            brute_result["dictionary_attempts"] = dict_result["attempts"]
            return brute_result

        return {
            "success": False,
            "message": "Password not found in hybrid attack",
            "dictionary_attempts": dict_result["attempts"],
            "brute_force_attempted": remaining_time > 0
        }

    def _mask_attack(self, target_hash: str, algorithms: List[str], mask: str, min_len: int, max_len: int, timeout: int) -> Dict[str, Any]:
        """Attack using custom character masks (simplified implementation)."""
        # This is a simplified mask attack - in practice, this would be more sophisticated
        return self._brute_force_attack(target_hash, algorithms, mask, min_len, max_len, timeout)

    def _apply_rules(self, base_word: str, rules: str) -> List[str]:
        """Apply transformation rules to base word."""
        variants = [base_word]
        
        if rules == "none":
            return variants
        
        if rules in ["basic", "advanced"]:
            # Common transformations
            variants.extend([
                base_word.upper(),
                base_word.capitalize(),
                base_word + "123",
                base_word + "1",
                base_word + "!",
                "123" + base_word,
                base_word[::-1],  # Reverse
            ])
            
            if rules == "advanced":
                # More aggressive transformations
                variants.extend([
                    base_word + "2023",
                    base_word + "2024",
                    base_word + "@",
                    base_word.replace('a', '@'),
                    base_word.replace('e', '3'),
                    base_word.replace('i', '1'),
                    base_word.replace('o', '0'),
                    base_word.replace('s', '$'),
                ])

        # Remove duplicates and empty strings
        return list(filter(None, set(variants)))

    def _test_password(self, target_hash: str, password: str, algorithm: str) -> bool:
        """Test if password produces target hash using specified algorithm."""
        try:
            hash_func = self.supported_algorithms.get(algorithm)
            if not hash_func:
                return False
                
            # Handle special cases
            if algorithm == 'ntlm':
                # NTLM uses MD4 of UTF-16LE encoded password
                candidate = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
            else:
                candidate = hash_func(password.encode()).hexdigest()
            
            return candidate.lower() == target_hash.lower()
        except Exception:
            return False

    def _calculate_search_space(self, charset: str, min_len: int, max_len: int) -> int:
        """Calculate total search space size."""
        total = 0
        charset_size = len(charset)
        for length in range(min_len, max_len + 1):
            total += charset_size ** length
        return total


class HashBenchmarkTool:
    name = "Hash Benchmark"
    description = "Benchmark hash cracking performance and estimate attack times."
    category = "Crypto & Encoding"

    def run(self, algorithm: str = "md5", duration: str = "5") -> ToolResult:
        """Benchmark hash computation speed for attack time estimation."""
        try:
            test_duration = min(30, int(duration))  # Max 30 seconds
        except ValueError:
            test_duration = 5

        cracker = HashCrackerTool()
        hash_func = cracker.supported_algorithms.get(algorithm.lower())
        
        if not hash_func:
            available = list(cracker.supported_algorithms.keys())
            raise ValueError(f"Algorithm {algorithm} not supported. Available: {available}")

        # Benchmark hash computation
        test_password = "benchmark_test_password"
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < test_duration:
            hash_func(f"{test_password}{count}".encode()).hexdigest()
            count += 1

        elapsed = time.time() - start_time
        hashes_per_second = count / elapsed

        # Calculate attack time estimates
        estimates = self._calculate_attack_estimates(hashes_per_second)

        result = {
            "algorithm": algorithm.upper(),
            "test_duration": round(elapsed, 2),
            "hashes_computed": count,
            "hashes_per_second": round(hashes_per_second, 0),
            "attack_time_estimates": estimates,
            "note": "These are single-threaded estimates. GPU acceleration can be 100-1000x faster."
        }

        return ToolResult(
            title=f"Hash Benchmark - {algorithm.upper()}",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    def _calculate_attack_estimates(self, hashes_per_second: float) -> Dict[str, str]:
        """Calculate estimated attack times for various scenarios."""
        scenarios = {
            "4_digit_pin": 10000,
            "6_lowercase": 26 ** 6,
            "8_lowercase": 26 ** 8,
            "6_mixed": 62 ** 6,
            "8_mixed": 62 ** 8,
            "common_passwords_10k": 10000,
            "common_passwords_1M": 1000000
        }

        estimates = {}
        for scenario, keyspace in scenarios.items():
            avg_attempts = keyspace / 2  # Average case
            seconds = avg_attempts / hashes_per_second
            estimates[scenario] = self._format_time_estimate(seconds)

        return estimates

    def _format_time_estimate(self, seconds: float) -> str:
        """Format time estimate in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"


class HashFormatConverterTool:
    name = "Hash Format Converter"
    description = "Convert between different hash formats and extract hash components."
    category = "Crypto & Encoding"

    def run(
        self,
        hash_input: str,
        source_format: str = "auto",
        target_format: str = "raw",
        include_metadata: str = "true"
    ) -> ToolResult:
        """
        Convert hash formats and extract components.
        
        Source formats: auto, raw, unix_crypt, ldap, mysql, postgresql, wordpress, drupal
        Target formats: raw, hex, base64, unix_crypt, hashcat, john
        """
        cleaned_input = hash_input.strip()
        if not cleaned_input:
            raise ValueError("Provide a hash to convert")

        # Parse the input hash
        parsed = self._parse_hash_format(cleaned_input, source_format)
        
        # Convert to target format
        converted = self._convert_to_format(parsed, target_format)
        
        result = {
            "original_input": cleaned_input,
            "detected_format": parsed["format"],
            "target_format": target_format,
            "converted_hash": converted,
        }
        
        if include_metadata == "true":
            result.update({
                "parsed_components": parsed["components"],
                "conversion_notes": self._get_conversion_notes(parsed["format"], target_format),
                "recommended_tools": self._get_recommended_tools(parsed["format"])
            })

        return ToolResult(
            title="Hash Format Converter",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    def _parse_hash_format(self, hash_input: str, source_format: str) -> Dict[str, Any]:
        """Parse hash input and detect format."""
        if source_format != "auto":
            return self._parse_specific_format(hash_input, source_format)
        
        # Auto-detect format
        # Unix crypt format ($id$salt$hash)
        if hash_input.startswith('$') and hash_input.count('$') >= 3:
            return self._parse_unix_crypt(hash_input)
        
        # LDAP format ({SCHEME}base64data)
        if hash_input.startswith('{') and '}' in hash_input:
            return self._parse_ldap_format(hash_input)
        
        # MySQL format (*HEXSTRING)
        if hash_input.startswith('*') and len(hash_input) == 41:
            return self._parse_mysql_format(hash_input)
        
        # PostgreSQL format (md5 + username hash)
        if hash_input.startswith('md5') and len(hash_input) == 35:
            return self._parse_postgresql_format(hash_input)
        
        # WordPress/phpBB format ($P$...)
        if hash_input.startswith('$P$') or hash_input.startswith('$H$'):
            return self._parse_phpass_format(hash_input)
        
        # Drupal format ($S$...)
        if hash_input.startswith('$S$'):
            return self._parse_drupal_format(hash_input)
        
        # Default to raw format
        return {
            "format": "raw",
            "algorithm": "unknown",
            "components": {
                "hash": hash_input,
                "encoding": "hex" if all(c in string.hexdigits for c in hash_input.lower()) else "unknown"
            }
        }

    def _parse_unix_crypt(self, hash_input: str) -> Dict[str, Any]:
        """Parse Unix crypt format."""
        parts = hash_input.split('$')
        if len(parts) < 4:
            raise ValueError("Invalid Unix crypt format")
        
        crypt_id = parts[1]
        salt = parts[2]
        hash_part = parts[3]
        
        # Map crypt IDs to algorithms
        crypt_algorithms = {
            '1': 'MD5 crypt',
            '2a': 'bcrypt',
            '2b': 'bcrypt',
            '2x': 'bcrypt', 
            '2y': 'bcrypt',
            '5': 'SHA-256 crypt',
            '6': 'SHA-512 crypt',
            'y': 'yescrypt'
        }
        
        algorithm = crypt_algorithms.get(crypt_id, f"Unknown crypt ID: {crypt_id}")
        
        return {
            "format": "unix_crypt",
            "algorithm": algorithm,
            "components": {
                "crypt_id": crypt_id,
                "salt": salt,
                "hash": hash_part,
                "full_hash": hash_input,
                "additional_params": parts[4:] if len(parts) > 4 else []
            }
        }

    def _parse_ldap_format(self, hash_input: str) -> Dict[str, Any]:
        """Parse LDAP hash format."""
        match = re.match(r'^\{([^}]+)\}(.+)$', hash_input)
        if not match:
            raise ValueError("Invalid LDAP format")
        
        scheme = match.group(1).upper()
        hash_data = match.group(2)
        
        return {
            "format": "ldap",
            "algorithm": scheme,
            "components": {
                "scheme": scheme,
                "hash_data": hash_data,
                "is_salted": scheme in ['SSHA', 'SMD5'],
                "full_hash": hash_input
            }
        }

    def _parse_mysql_format(self, hash_input: str) -> Dict[str, Any]:
        """Parse MySQL password hash format."""
        return {
            "format": "mysql",
            "algorithm": "MySQL 4.1+ (SHA-1 based)",
            "components": {
                "hash": hash_input[1:],  # Remove asterisk
                "full_hash": hash_input,
                "version": "4.1+"
            }
        }

    def _parse_postgresql_format(self, hash_input: str) -> Dict[str, Any]:
        """Parse PostgreSQL MD5 hash format."""
        return {
            "format": "postgresql",
            "algorithm": "PostgreSQL MD5",
            "components": {
                "hash": hash_input[3:],  # Remove 'md5' prefix
                "full_hash": hash_input,
                "note": "Hash of password+username concatenated"
            }
        }

    def _parse_phpass_format(self, hash_input: str) -> Dict[str, Any]:
        """Parse phpBB/WordPress phpass format."""
        if len(hash_input) < 12:
            raise ValueError("Invalid phpass format")
            
        identifier = hash_input[:3]
        cost_char = hash_input[3]
        salt = hash_input[4:12]
        hash_part = hash_input[12:]
        
        return {
            "format": "phpass",
            "algorithm": "phpBB3/WordPress phpass",
            "components": {
                "identifier": identifier,
                "cost": ord(cost_char),
                "salt": salt,
                "hash": hash_part,
                "full_hash": hash_input
            }
        }

    def _parse_drupal_format(self, hash_input: str) -> Dict[str, Any]:
        """Parse Drupal hash format."""
        if len(hash_input) < 12:
            raise ValueError("Invalid Drupal format")
            
        cost_char = hash_input[3]
        salt = hash_input[4:12]
        hash_part = hash_input[12:]
        
        return {
            "format": "drupal",
            "algorithm": "Drupal SHA-512",
            "components": {
                "cost": 1 << (ord(cost_char) - ord('.')),
                "salt": salt,
                "hash": hash_part,
                "full_hash": hash_input
            }
        }

    def _parse_specific_format(self, hash_input: str, format_name: str) -> Dict[str, Any]:
        """Parse hash assuming specific format."""
        format_parsers = {
            "unix_crypt": self._parse_unix_crypt,
            "ldap": self._parse_ldap_format,
            "mysql": self._parse_mysql_format,
            "postgresql": self._parse_postgresql_format,
            "wordpress": self._parse_phpass_format,
            "drupal": self._parse_drupal_format
        }
        
        parser = format_parsers.get(format_name)
        if parser:
            return parser(hash_input)
        else:
            return {
                "format": format_name,
                "algorithm": "unknown",
                "components": {"hash": hash_input}
            }

    def _convert_to_format(self, parsed: Dict[str, Any], target_format: str) -> str:
        """Convert parsed hash to target format."""
        if target_format == "raw":
            return parsed["components"].get("hash", parsed["components"].get("full_hash", ""))
        
        elif target_format == "hex":
            if parsed["format"] == "ldap":
                # LDAP uses base64, decode to hex
                hash_data = parsed["components"].get("hash_data", "")
                try:
                    decoded = base64.b64decode(hash_data)
                    return decoded.hex()
                except Exception:
                    return hash_data
            else:
                hash_data = parsed["components"].get("hash", "")
                return hash_data
        
        elif target_format == "base64":
            hash_data = parsed["components"].get("hash", "")
            if all(c in string.hexdigits for c in hash_data.lower()) and len(hash_data) % 2 == 0:
                # Convert hex to base64
                try:
                    decoded = bytes.fromhex(hash_data)
                    return base64.b64encode(decoded).decode()
                except Exception:
                    return hash_data
            return hash_data
        
        elif target_format == "hashcat":
            return self._convert_to_hashcat(parsed)
        
        elif target_format == "john":
            return self._convert_to_john(parsed)
        
        else:
            return parsed["components"].get("full_hash", parsed["components"].get("hash", ""))

    def _convert_to_hashcat(self, parsed: Dict[str, Any]) -> str:
        """Convert to Hashcat format."""
        format_type = parsed["format"]
        components = parsed["components"]
        
        if format_type == "unix_crypt":
            return components["full_hash"]
        elif format_type == "ldap":
            return components["full_hash"]
        elif format_type == "mysql":
            return components["full_hash"]
        elif format_type == "phpass":
            return components["full_hash"]
        else:
            return components.get("hash", components.get("full_hash", ""))

    def _convert_to_john(self, parsed: Dict[str, Any]) -> str:
        """Convert to John the Ripper format."""
        format_type = parsed["format"]
        components = parsed["components"]
        
        if format_type == "unix_crypt":
            return components["full_hash"]
        elif format_type == "ldap":
            scheme = components["scheme"]
            if scheme == "SHA":
                return f"{{SHA}}{components['hash_data']}"
            return components["full_hash"]
        elif format_type == "mysql":
            return f"*{components['hash']}"
        else:
            return components.get("hash", components.get("full_hash", ""))

    def _get_conversion_notes(self, source_format: str, target_format: str) -> List[str]:
        """Get notes about the conversion."""
        notes = []
        
        if source_format == "ldap" and target_format == "hex":
            notes.append("LDAP format base64 decoded to hexadecimal")
        
        if source_format == "mysql" and target_format == "raw":
            notes.append("MySQL format asterisk prefix removed")
        
        if source_format == "postgresql" and target_format == "raw":
            notes.append("PostgreSQL 'md5' prefix removed")
            notes.append("Note: This is MD5(password + username)")
        
        if target_format == "hashcat":
            notes.append("Format suitable for Hashcat input")
        
        if target_format == "john":
            notes.append("Format suitable for John the Ripper")
        
        return notes

    def _get_recommended_tools(self, hash_format: str) -> List[str]:
        """Get recommended cracking tools for the format."""
        recommendations = []
        
        if hash_format in ["unix_crypt", "phpass", "drupal"]:
            recommendations.extend([
                "hashcat (supports most Unix crypt formats)",
                "john (good for older crypt formats)"
            ])
        
        elif hash_format == "ldap":
            recommendations.extend([
                "hashcat -m 101 (SHA + salt)",
                "john --format=ldap-sha",
                "ldapcrack for specialized attacks"
            ])
        
        elif hash_format == "mysql":
            recommendations.extend([
                "hashcat -m 300 (MySQL4.1/MySQL5)",
                "john --format=mysql-sha1"
            ])
        
        elif hash_format == "postgresql":
            recommendations.extend([
                "hashcat -m 112 (PostgreSQL)",
                "john --format=postgres"
            ])
        
        else:
            recommendations.append("Use Hash Workspace tool for identification")
        
        return recommendations
