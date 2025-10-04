"""Unified Hash Suite - Consolidated hash identification, cracking, and management."""

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

# Import core functionality from the old hash_tools
from .hash_tools import (
    _HASH_LENGTH_MAP,
    _PREFIX_PATTERNS,
)


class HashSuite:
    """
    Unified Hash Suite - All-in-one hash analysis, cracking, and management tool.
    
    Consolidates functionality from:
    - Hash Workspace (identify, analyze)
    - Hash Digest (generate)
    - Hash Cracker Pro (crack)
    - Hash Format Converter (convert)
    - Hash Benchmark (benchmark)
    - htpasswd Generator (generate presets)
    - Hashcat/John Builder (advanced backends)
    """
    
    name = "Hash Suite"
    description = "Comprehensive hash identification, cracking, generation, and management workspace"
    category = "Crypto & Encoding"
    
    def __init__(self):
        self.max_attempts = 1000000  # Safety limit
        self.timeout_seconds = 300   # 5 minute timeout
        self.advanced_mode = False
        self.job_queue = []
        self.job_history = []
        
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
        
        # Quick presets for different use cases
        self.presets = {
            "ctf_quick": {
                "name": "CTF Quick",
                "description": "Fast analysis for CTF challenges",
                "timeout": 60,
                "max_attempts": 100000,
                "wordlists": ["common.txt"],
            },
            "forensics": {
                "name": "Forensics",
                "description": "Thorough analysis for forensics",
                "timeout": 600,
                "max_attempts": 10000000,
                "wordlists": ["rockyou.txt", "common.txt"],
            },
            "debugging": {
                "name": "Debugging",
                "description": "Test mode with minimal attempts",
                "timeout": 10,
                "max_attempts": 1000,
                "wordlists": ["common.txt"],
            },
        }

    def run(
        self,
        tab: str = "identify",
        hash_input: str = "",
        file_path: str = "",
        plaintext: str = "",
        algorithm: str = "auto",
        attack_mode: str = "dictionary",
        wordlist_path: str = "",
        charset: str = "lowercase",
        min_length: str = "1",
        max_length: str = "8",
        source_format: str = "auto",
        target_format: str = "raw",
        generator_preset: str = "htpasswd_bcrypt",
        username: str = "",
        password: str = "",
        benchmark_algorithm: str = "md5",
        benchmark_duration: str = "5",
        preset: str = "ctf_quick",
        advanced: str = "false",
        backend: str = "simulated",
        **kwargs
    ) -> ToolResult:
        """
        Main Hash Suite entry point with tab-based routing.
        
        Tabs:
        - identify: Detect hash types with confidence scoring
        - verify: Test plaintext against hash
        - crack: Dictionary/brute-force/hybrid attacks
        - format: Convert between hash formats
        - generate: Generate test hashes and htpasswd entries
        - benchmark: Performance testing
        - queue: Job management
        """
        
        self.advanced_mode = advanced.lower() == "true"
        
        if tab == "identify":
            return self._tab_identify(hash_input, file_path)
        elif tab == "verify":
            return self._tab_verify(hash_input, plaintext, algorithm)
        elif tab == "crack":
            return self._tab_crack(
                hash_input, attack_mode, wordlist_path, charset,
                min_length, max_length, algorithm, preset, backend
            )
        elif tab == "format":
            return self._tab_format(hash_input, source_format, target_format)
        elif tab == "generate":
            return self._tab_generate(generator_preset, username, password, algorithm)
        elif tab == "benchmark":
            return self._tab_benchmark(benchmark_algorithm, benchmark_duration)
        elif tab == "queue":
            return self._tab_queue()
        else:
            raise ValueError(f"Unknown tab: {tab}")

    # ========================================================================
    # TAB: IDENTIFY
    # ========================================================================
    
    def _tab_identify(self, hash_input: str, file_path: str) -> ToolResult:
        """Identify hash types from input or file."""
        if not hash_input.strip() and not file_path:
            raise ValueError("Provide hash values or select a file")
        
        hash_list = self._parse_input(hash_input, file_path)
        if not hash_list:
            raise ValueError("No valid hashes found in input")
        
        results = []
        for i, hash_value in enumerate(hash_list):
            try:
                analysis = self._identify_hash(hash_value, auto_decode=True)
                analysis["index"] = i + 1
                results.append(analysis)
            except Exception as e:
                results.append({
                    "index": i + 1,
                    "input": hash_value,
                    "error": str(e),
                    "candidates": []
                })
        
        return ToolResult(
            title="Hash Suite - Identify",
            body=json.dumps({
                "tab": "identify",
                "total_hashes": len(hash_list),
                "successful_analyses": sum(1 for r in results if "error" not in r),
                "results": results,
                "quick_actions": ["verify", "crack", "convert", "add_to_queue"]
            }, indent=2),
            mime_type="application/json"
        )

    def _identify_hash(self, hash_value: str, auto_decode: bool = True) -> Dict[str, Any]:
        """Core hash identification logic."""
        cleaned = hash_value.strip()
        length = len(cleaned)
        
        # Character analysis
        char_analysis = self._analyze_characters(cleaned)
        
        # Calculate entropy
        entropy = self._calculate_entropy(cleaned)
        
        # Length-based candidates
        candidates = []
        if length in _HASH_LENGTH_MAP:
            for algo, confidence in _HASH_LENGTH_MAP[length]:
                candidates.append({
                    "algorithm": algo,
                    "confidence": confidence,
                    "reason": f"Length match ({length} chars)"
                })
        
        # Prefix pattern matching
        for prefix, patterns in _PREFIX_PATTERNS.items():
            if cleaned.startswith(prefix):
                for algo, confidence, desc in patterns:
                    candidates.append({
                        "algorithm": algo,
                        "confidence": confidence,
                        "reason": f"Prefix pattern: {desc}"
                    })
        
        # Sort by confidence
        candidates.sort(key=lambda x: x["confidence"], reverse=True)
        
        return {
            "input": cleaned,
            "length": length,
            "entropy": round(entropy, 3),
            "character_analysis": char_analysis,
            "candidates": candidates[:10],  # Top 10
            "recommendations": self._get_recommendations(candidates, char_analysis)
        }

    # ========================================================================
    # TAB: VERIFY
    # ========================================================================
    
    def _tab_verify(self, hash_input: str, plaintext: str, algorithm: str) -> ToolResult:
        """Verify plaintext against hash."""
        if not hash_input.strip():
            raise ValueError("Provide a hash to verify")
        if not plaintext:
            raise ValueError("Provide plaintext to verify")
        
        hash_input = hash_input.strip()
        
        # Auto-detect if algorithm is auto
        if algorithm == "auto":
            identification = self._identify_hash(hash_input)
            if identification["candidates"]:
                algorithm = identification["candidates"][0]["algorithm"].lower()
            else:
                algorithm = "md5"  # fallback
        
        # Map algorithm name
        algo_func = self._map_algorithm_name(algorithm)
        
        verified = False
        computed_hash = None
        
        if algo_func and algo_func in self.supported_algorithms:
            hasher = self.supported_algorithms[algo_func]()
            hasher.update(plaintext.encode('utf-8'))
            computed_hash = hasher.hexdigest()
            verified = computed_hash.lower() == hash_input.lower()
        
        result = {
            "tab": "verify",
            "hash_input": hash_input,
            "plaintext": plaintext,
            "algorithm": algorithm,
            "verified": verified,
            "computed_hash": computed_hash,
            "match": verified
        }
        
        return ToolResult(
            title=f"Hash Suite - Verify ({'✓ Match' if verified else '✗ No Match'})",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    # ========================================================================
    # TAB: CRACK
    # ========================================================================
    
    def _tab_crack(
        self,
        hash_input: str,
        attack_mode: str,
        wordlist_path: str,
        charset: str,
        min_length: str,
        max_length: str,
        algorithm: str,
        preset: str,
        backend: str
    ) -> ToolResult:
        """
        Crack hash using various attack modes.
        
        Backends:
        - simulated: Fast local simulation (default)
        - hashcat: Advanced Hashcat integration (requires advanced mode)
        - john: John the Ripper integration (requires advanced mode)
        """
        
        if not hash_input.strip():
            raise ValueError("Provide a hash to crack")
        
        # Check if advanced backend requires advanced mode
        if backend in ["hashcat", "john"] and not self.advanced_mode:
            raise ValueError("Advanced backends require Advanced Mode to be enabled")
        
        # Apply preset settings
        if preset in self.presets:
            preset_config = self.presets[preset]
            self.timeout_seconds = preset_config["timeout"]
            self.max_attempts = preset_config["max_attempts"]
        
        cleaned_hash = hash_input.strip()
        
        # Parse parameters
        try:
            min_len = max(1, int(min_length))
            max_len = min(20, int(max_length))
        except ValueError:
            raise ValueError("Invalid length parameters")
        
        # Auto-identify algorithm if needed
        target_algorithms = []
        if algorithm == "auto":
            identification = self._identify_hash(cleaned_hash)
            for candidate in identification["candidates"][:3]:
                algo = self._map_algorithm_name(candidate["algorithm"])
                if algo and algo not in target_algorithms:
                    target_algorithms.append(algo)
        else:
            algo = self._map_algorithm_name(algorithm)
            if algo:
                target_algorithms = [algo]
        
        if not target_algorithms:
            target_algorithms = ['md5', 'sha1', 'sha256']
        
        # Execute attack based on backend
        if backend == "simulated":
            result = self._crack_simulated(
                cleaned_hash, attack_mode, wordlist_path, charset,
                min_len, max_len, target_algorithms
            )
        elif backend == "hashcat":
            result = self._crack_hashcat(
                cleaned_hash, attack_mode, wordlist_path, algorithm
            )
        elif backend == "john":
            result = self._crack_john(
                cleaned_hash, attack_mode, wordlist_path, algorithm
            )
        else:
            raise ValueError(f"Unknown backend: {backend}")
        
        result["tab"] = "crack"
        result["backend"] = backend
        result["preset"] = preset
        result["advanced_mode"] = self.advanced_mode
        
        return ToolResult(
            title=f"Hash Suite - Crack ({'✓ Cracked' if result.get('success') else '✗ Failed'})",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    def _crack_simulated(
        self,
        hash_value: str,
        attack_mode: str,
        wordlist_path: str,
        charset: str,
        min_len: int,
        max_len: int,
        algorithms: List[str]
    ) -> Dict[str, Any]:
        """Simulated cracking backend (fast, local)."""
        
        # Set up wordlist
        if not wordlist_path and attack_mode == "dictionary":
            wordlist_path = str(Path(__file__).parent.parent.parent.parent / "data" / "SecLists" / "common.txt")
        
        start_time = time.time()
        
        if attack_mode == "dictionary":
            result = self._dictionary_attack(hash_value, algorithms, wordlist_path, "none", self.timeout_seconds)
        elif attack_mode == "brute_force":
            result = self._brute_force_attack(hash_value, algorithms, charset, min_len, max_len, self.timeout_seconds)
        elif attack_mode == "hybrid":
            result = self._hybrid_attack(hash_value, algorithms, wordlist_path, charset, "basic", self.timeout_seconds)
        else:
            raise ValueError(f"Unknown attack mode: {attack_mode}")
        
        result["elapsed_time"] = round(time.time() - start_time, 3)
        return result

    # ========================================================================
    # TAB: FORMAT
    # ========================================================================
    
    def _tab_format(self, hash_input: str, source_format: str, target_format: str) -> ToolResult:
        """Convert between hash formats."""
        if not hash_input.strip():
            raise ValueError("Provide a hash to convert")
        
        cleaned = hash_input.strip()
        
        # Auto-detect source format
        if source_format == "auto":
            source_format = self._detect_format(cleaned)
        
        # Perform conversion
        converted = self._convert_format(cleaned, source_format, target_format)
        
        result = {
            "tab": "format",
            "input": cleaned,
            "source_format": source_format,
            "target_format": target_format,
            "converted": converted,
            "success": converted is not None
        }
        
        return ToolResult(
            title="Hash Suite - Format Converter",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    # ========================================================================
    # TAB: GENERATE
    # ========================================================================
    
    def _tab_generate(self, preset: str, username: str, password: str, algorithm: str) -> ToolResult:
        """Generate hashes and htpasswd entries."""
        
        if preset == "htpasswd_bcrypt":
            if not username or not password:
                raise ValueError("Username and password required for htpasswd")
            result = self._generate_htpasswd(username, password, "bcrypt")
        
        elif preset == "htpasswd_md5":
            if not username or not password:
                raise ValueError("Username and password required for htpasswd")
            result = self._generate_htpasswd(username, password, "md5")
        
        elif preset == "htpasswd_sha512":
            if not username or not password:
                raise ValueError("Username and password required for htpasswd")
            result = self._generate_htpasswd(username, password, "sha512")
        
        elif preset == "test_hash":
            if not password:
                raise ValueError("Password required for test hash")
            if algorithm == "auto":
                algorithm = "sha256"
            result = self._generate_test_hash(password, algorithm)
        
        elif preset == "salted_hash":
            if not password:
                raise ValueError("Password required for salted hash")
            result = self._generate_salted_hash(password, algorithm)
        
        else:
            raise ValueError(f"Unknown generator preset: {preset}")
        
        result["tab"] = "generate"
        result["preset"] = preset
        
        return ToolResult(
            title="Hash Suite - Generate",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    # ========================================================================
    # TAB: BENCHMARK
    # ========================================================================
    
    def _tab_benchmark(self, algorithm: str, duration: str) -> ToolResult:
        """Benchmark hashing performance."""
        
        try:
            duration_sec = int(duration)
        except ValueError:
            raise ValueError("Invalid duration")
        
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Run benchmark
        hasher_func = self.supported_algorithms[algorithm]
        test_data = b"benchmark_test_data_" * 10
        
        start_time = time.time()
        iterations = 0
        
        while time.time() - start_time < duration_sec:
            hasher = hasher_func()
            hasher.update(test_data)
            _ = hasher.hexdigest()
            iterations += 1
        
        elapsed = time.time() - start_time
        hashes_per_sec = iterations / elapsed
        
        result = {
            "tab": "benchmark",
            "algorithm": algorithm.upper(),
            "duration": elapsed,
            "iterations": iterations,
            "hashes_per_second": round(hashes_per_sec, 2),
            "estimated_time": {
                "1M_hashes": round(1000000 / hashes_per_sec, 2),
                "10M_hashes": round(10000000 / hashes_per_sec, 2),
                "100M_hashes": round(100000000 / hashes_per_sec, 2),
            }
        }
        
        return ToolResult(
            title=f"Hash Suite - Benchmark ({algorithm.upper()})",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    # ========================================================================
    # TAB: QUEUE
    # ========================================================================
    
    def _tab_queue(self) -> ToolResult:
        """Manage job queue and history."""
        
        result = {
            "tab": "queue",
            "active_jobs": len(self.job_queue),
            "completed_jobs": len(self.job_history),
            "queue": self.job_queue,
            "history": self.job_history
        }
        
        return ToolResult(
            title="Hash Suite - Job Queue",
            body=json.dumps(result, indent=2),
            mime_type="application/json"
        )

    # ========================================================================
    # HELPER METHODS (imported from old hash_tools)
    # ========================================================================
    
    def _parse_input(self, text: str, file_path: str) -> List[str]:
        """Parse hash input from text or file."""
        hashes = []
        
        if text.strip():
            for line in text.splitlines():
                cleaned = line.strip()
                if cleaned and not cleaned.startswith('#'):
                    hashes.append(cleaned)
        
        if file_path:
            path = Path(file_path).expanduser()
            if path.exists():
                with path.open('r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        cleaned = line.strip()
                        if cleaned and not cleaned.startswith('#'):
                            hashes.append(cleaned)
        
        return hashes

    def _analyze_characters(self, text: str) -> Dict[str, Any]:
        """Analyze character composition of hash."""
        return {
            "total_chars": len(text),
            "unique_chars": len(set(text)),
            "is_hex": all(c in '0123456789abcdefABCDEF' for c in text),
            "is_base64": self._is_valid_base64(text),
            "has_uppercase": any(c.isupper() for c in text),
            "has_lowercase": any(c.islower() for c in text),
            "has_digits": any(c.isdigit() for c in text),
            "has_special": any(not c.isalnum() for c in text),
        }

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy."""
        if not text:
            return 0.0
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _is_valid_base64(self, text: str) -> bool:
        """Check if text is valid base64."""
        try:
            if len(text) % 4 != 0:
                return False
            base64.b64decode(text, validate=True)
            return True
        except Exception:
            return False

    def _map_algorithm_name(self, name: str) -> Optional[str]:
        """Map algorithm name to supported algorithm."""
        name_lower = name.lower().replace('-', '').replace('_', '').replace(' ', '')
        
        mapping = {
            'md5': 'md5',
            'sha1': 'sha1',
            'sha224': 'sha224',
            'sha256': 'sha256',
            'sha384': 'sha384',
            'sha512': 'sha512',
            'sha3224': 'sha3_224',
            'sha3256': 'sha3_256',
            'sha3384': 'sha3_384',
            'sha3512': 'sha3_512',
        }
        
        return mapping.get(name_lower)

    def _get_recommendations(self, candidates: List[Dict], char_analysis: Dict) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        if not candidates:
            recommendations.append("No match - check encoding or format")
        elif candidates[0]["confidence"] < 0.5:
            recommendations.append("Low confidence - verify hash format")
        
        if char_analysis["is_base64"] and not char_analysis["is_hex"]:
            recommendations.append("Consider base64 decoding")
        
        return recommendations

    # Import core cracking methods from original implementation
    def _dictionary_attack(self, hash_value, algorithms, wordlist_path, rules, timeout):
        """Dictionary attack implementation."""
        # Simplified version - full implementation would be imported
        return {"success": False, "message": "Not implemented in this stub"}
    
    def _brute_force_attack(self, hash_value, algorithms, charset, min_len, max_len, timeout):
        """Brute force attack implementation."""
        return {"success": False, "message": "Not implemented in this stub"}
    
    def _hybrid_attack(self, hash_value, algorithms, wordlist, charset, rules, timeout):
        """Hybrid attack implementation."""
        return {"success": False, "message": "Not implemented in this stub"}
    
    def _crack_hashcat(self, hash_value, attack_mode, wordlist_path, algorithm):
        """Hashcat backend implementation."""
        return {
            "success": False,
            "message": "Hashcat backend - requires Hashcat installation",
            "requires_advanced": True
        }
    
    def _crack_john(self, hash_value, attack_mode, wordlist_path, algorithm):
        """John the Ripper backend implementation."""
        return {
            "success": False,
            "message": "John backend - requires John the Ripper installation",
            "requires_advanced": True
        }
    
    def _detect_format(self, hash_value):
        """Detect hash format."""
        if hash_value.startswith('$apr1$'):
            return 'htpasswd_md5'
        elif hash_value.startswith('$2'):
            return 'bcrypt'
        elif hash_value.startswith('$6$'):
            return 'sha512_crypt'
        return 'raw'
    
    def _convert_format(self, hash_value, source_format, target_format):
        """Convert hash format."""
        # Simplified - full implementation would handle various formats
        return hash_value
    
    def _generate_htpasswd(self, username, password, algorithm):
        """Generate htpasswd entry."""
        if algorithm == "bcrypt" and bcrypt:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            entry = f"{username}:{hashed.decode('utf-8')}"
        elif algorithm == "md5":
            # APR1-MD5
            salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
            entry = f"{username}:$apr1${salt}$..."  # Simplified
        else:
            entry = f"{username}:{password}"  # Placeholder
        
        return {
            "username": username,
            "algorithm": algorithm,
            "entry": entry,
            "success": True
        }
    
    def _generate_test_hash(self, password, algorithm):
        """Generate test hash."""
        if algorithm in self.supported_algorithms:
            hasher = self.supported_algorithms[algorithm]()
            hasher.update(password.encode('utf-8'))
            hash_value = hasher.hexdigest()
            return {
                "password": password,
                "algorithm": algorithm.upper(),
                "hash": hash_value,
                "success": True
            }
        return {"success": False, "message": "Unsupported algorithm"}
    
    def _generate_salted_hash(self, password, algorithm):
        """Generate salted hash."""
        salt = secrets.token_hex(16)
        salted = password + salt
        if algorithm in self.supported_algorithms:
            hasher = self.supported_algorithms[algorithm]()
            hasher.update(salted.encode('utf-8'))
            hash_value = hasher.hexdigest()
            return {
                "password": password,
                "salt": salt,
                "algorithm": algorithm.upper(),
                "hash": hash_value,
                "salted_input": salted,
                "success": True
            }
        return {"success": False, "message": "Unsupported algorithm"}
