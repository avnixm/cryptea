"""Command builders for Hashcat and John the Ripper."""

from __future__ import annotations

import json
import shlex
from typing import Dict, List

from ..base import ToolResult


_ATTACK_MAP: Dict[str, str] = {
    "straight": "0",
    "combinator": "1",
    "bruteforce": "3",
    "hybrid_wordlist_mask": "6",
    "hybrid_mask_wordlist": "7",
}


class HashcatJobBuilderTool:
    name = "Hashcat/John Builder"
    description = "Compose common Hashcat or John cracking commands offline."
    category = "Crypto & Encoding"

    def run(
        self,
        tool: str = "hashcat",
        hash_file: str = "hashes.txt",
        mode: str = "0",
        attack: str = "straight",
        wordlist: str = "",
        mask: str = "",
        rules: str = "",
        extra_options: str = "",
        format_hint: str = "",
        potfile: str = "",
    ) -> ToolResult:
        tool_normalised = (tool or "hashcat").strip().lower()
        if tool_normalised not in {"hashcat", "john"}:
            raise ValueError("tool must be 'hashcat' or 'john'")

        if tool_normalised == "hashcat":
            command = self._build_hashcat_command(hash_file, mode, attack, wordlist, mask, rules, extra_options, potfile)
            notes = self._hashcat_notes(mode, attack)
        else:
            command = self._build_john_command(hash_file, format_hint, wordlist, mask, rules, extra_options, potfile)
            notes = ["Ensure the selected format matches the hash file signature."]

        payload = {
            "tool": tool_normalised,
            "command": command,
            "notes": notes,
        }
        return ToolResult(title=f"{tool_normalised.capitalize()} command", body=json.dumps(payload, indent=2), mime_type="application/json")

    def _build_hashcat_command(
        self,
        hash_file: str,
        mode: str,
        attack: str,
        wordlist: str,
        mask: str,
        rules: str,
        extra_options: str,
        potfile: str,
    ) -> str:
        cmd: List[str] = ["hashcat", "-m", mode]

        attack_code = _ATTACK_MAP.get(attack.strip().lower())
        if attack_code is None:
            raise ValueError(f"Unknown attack mode: {attack}")
        cmd.extend(["-a", attack_code])
        cmd.append(hash_file)

        if attack_code in {"0", "1", "6", "7"} and wordlist:
            cmd.append(wordlist)
        if attack_code in {"3", "6", "7"}:
            if not mask:
                raise ValueError("Mask is required for brute-force or hybrid attacks")
            cmd.append(mask)

        if rules:
            cmd.extend(["-r", rules])
        if potfile:
            cmd.extend(["--potfile-path", potfile])
        if extra_options:
            cmd.extend(extra_options.split())

        return " ".join(shlex.quote(part) for part in cmd)

    def _build_john_command(
        self,
        hash_file: str,
        format_hint: str,
        wordlist: str,
        mask: str,
        rules: str,
        extra_options: str,
        potfile: str,
    ) -> str:
        cmd: List[str] = ["john", hash_file]
        if format_hint:
            cmd.append(f"--format={format_hint}")
        if wordlist:
            cmd.append(f"--wordlist={wordlist}")
        if mask:
            cmd.append(f"--mask={mask}")
        if rules:
            cmd.append(f"--rules={rules}")
        if potfile:
            cmd.append(f"--pot={potfile}")
        if extra_options:
            cmd.extend(extra_options.split())
        return " ".join(shlex.quote(part) for part in cmd)

    def _hashcat_notes(self, mode: str, attack: str) -> List[str]:
        notes = [
            "Hashcat will respect ~/.hashcat/hashcat.potfile unless --potfile-path overrides it.",
            "Use --show after cracking to display successful candidates.",
        ]
        notes.append(f"Hash mode selected: {mode} (verify against hashcat --help | grep {mode}).")
        notes.append(f"Attack mode '{attack}' maps to -a {_ATTACK_MAP.get(attack, '?')}.")
        return notes