"""JWT decoding and signing helper."""

from __future__ import annotations

import base64
import json
import hmac
import hashlib
from typing import Dict, Optional

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
    ) -> ToolResult:
        token = token.strip()
        if not token:
            raise ValueError("Token is required")

        header_b64, payload_b64, signature_b64 = _split_token(token)
        header = self._decode_segment(header_b64)
        payload = self._decode_segment(payload_b64)

        lines = ["Decoded header:", json.dumps(header, indent=2), "", "Decoded payload:", json.dumps(payload, indent=2)]

        chosen_alg = override_alg.strip().upper() or header.get("alg", "")
        verify_flag = verify.strip().lower() in {"1", "true", "yes", "on"}

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
