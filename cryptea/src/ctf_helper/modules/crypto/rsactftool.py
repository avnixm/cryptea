"""RsaCtfTool wrapper for automated RSA attacks."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, NamedTuple, Sequence

from ..base import ToolResult


def is_rsactftool_available() -> bool:
    return shutil.which("RsaCtfTool") is not None or shutil.which("rsactftool") is not None


class RsaCtfToolProfile(NamedTuple):
    """Declarative description for a preset attack profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[RsaCtfToolProfile] = (
    RsaCtfToolProfile(
        "auto",
        "Auto",
        "Automatic attack selection",
        ("--attack", "all"),
    ),
    RsaCtfToolProfile(
        "factordb",
        "FactorDB",
        "Check FactorDB for known factors",
        ("--attack", "factordb"),
    ),
    RsaCtfToolProfile(
        "wiener",
        "Wiener",
        "Wiener attack for small private exponents",
        ("--attack", "wiener"),
    ),
    RsaCtfToolProfile(
        "fermat",
        "Fermat",
        "Fermat factorization for close primes",
        ("--attack", "fermat"),
    ),
)


class RsaCtfToolTool:
    name = "RsaCtfTool"
    description = "Automated RSA attack tool for CTF challenges."
    category = "Crypto"

    def run(
        self,
        public_key: str = "",
        n_modulus: str = "",
        e_exponent: str = "",
        ciphertext: str = "",
        profile: str = "auto",
        attack: str = "",
        extra: str = "",
    ) -> ToolResult:
        # Check for both possible command names
        tool_name = "RsaCtfTool" if shutil.which("RsaCtfTool") else "rsactftool"
        if not is_rsactftool_available():
            raise RuntimeError("RsaCtfTool not found in PATH. Install RsaCtfTool locally.")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[0]  # auto

        args: List[str] = [tool_name]

        # Add profile args
        args.extend(selected_profile.args)

        # Public key file
        if public_key.strip():
            key_path = Path(public_key.strip()).expanduser()
            if not key_path.exists():
                raise FileNotFoundError(f"Public key file not found: {public_key}")
            args.extend(["--publickey", str(key_path)])
        
        # Or provide n and e directly
        if n_modulus.strip():
            args.extend(["-n", n_modulus.strip()])
        if e_exponent.strip():
            args.extend(["-e", e_exponent.strip()])

        # Ciphertext
        if ciphertext.strip():
            # Check if it's a file or raw ciphertext
            ct_path = Path(ciphertext.strip()).expanduser()
            if ct_path.exists():
                args.extend(["--uncipher", str(ct_path)])
            else:
                # Assume it's raw ciphertext
                args.extend(["--uncipher", ciphertext.strip()])

        # Override attack if specified
        if attack.strip():
            args = [a for i, a in enumerate(args) if not (a == "--attack" or (i > 0 and args[i-1] == "--attack"))]
            args.extend(["--attack", attack.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        if not public_key.strip() and not n_modulus.strip():
            raise ValueError("Either public_key file or n_modulus must be provided")

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append("")
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(f"RsaCtfTool failed: {proc.stderr.strip()}")

        return ToolResult(
            title="RsaCtfTool Analysis",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

