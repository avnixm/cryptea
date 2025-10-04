from __future__ import annotations

import base64
import hashlib
import json
import math
import sys
import wave
from pathlib import Path
from array import array

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ctf_helper.modules.crypto.decoder import DecoderWorkbenchTool
from ctf_helper.modules.crypto.hash_tools import (
    HashCrackerTool,
    HashDigestTool,
    HashWorkspaceTool,
    HtpasswdGeneratorTool,
)
from ctf_helper.modules.crypto.hashcat_helper import HashcatJobBuilderTool
from ctf_helper.modules.crypto.morse_decoder import MORSE_CODE_DICT, MorseDecoderTool
from ctf_helper.modules.crypto.rsa_toolkit import RSAToolkit
from ctf_helper.modules.crypto.xor_analyzer import XORKeystreamAnalyzer


def test_decoder_pipeline_rot13_from_base64() -> None:
    data = base64.b64encode(b"uryyb").decode("utf-8")
    tool = DecoderWorkbenchTool()
    result = tool.run(data=data, operations="base64_decode|rot13")
    payload = json.loads(result.body)
    assert payload["final"]["text"] == "hello"
    assert payload["steps"][-1]["operation"] == "rot13"


def test_hash_workspace_identifies_md5() -> None:
    """Test hash identification using Hash Workspace (replaces Hash Identifier Simple)."""
    digest = hashlib.md5(b"picoCTF").hexdigest()
    payload = json.loads(HashWorkspaceTool().run(hashes=digest, mode="identify").body)
    # The result has a 'results' list with hash analyses
    algorithms = [entry["algorithm"] for entry in payload["results"][0]["candidates"]]
    assert any("MD5" in algo for algo in algorithms)


def test_htpasswd_generator_md5_fixed_salt() -> None:
    tool = HtpasswdGeneratorTool()
    result = tool.run(username="alice", password="secret", algorithm="md5", salt="somesalt")
    payload = json.loads(result.body)
    assert payload["entry"].startswith("alice:$1$somesalt")


def test_hash_cracker_pro_dictionary_attack() -> None:
    """Test hash cracking using Hash Cracker Pro (replaces Hash Crack Helper)."""
    digest = hashlib.sha1(b"pico").hexdigest()
    
    # Create a temporary wordlist file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("test\npico\nhello\n")
        wordlist_path = f.name
    
    try:
        payload = json.loads(
            HashCrackerTool().run(
                hash_value=digest, 
                attack_mode="dictionary", 
                wordlist_path=wordlist_path,
                algorithm="sha1"
            ).body
        )
        assert payload["success"]
        assert payload["password"] == "pico"
        assert payload["algorithm"] == "SHA1"
    finally:
        Path(wordlist_path).unlink(missing_ok=True)


def test_hashcat_job_builder_wordlist() -> None:
    payload = json.loads(
        HashcatJobBuilderTool().run(
            tool="hashcat",
            hash_file="hashes.txt",
            mode="0",
            attack="straight",
            wordlist="/wordlists/rockyou.txt",
        ).body
    )
    assert "hashcat" in payload["command"]
    assert "-a 0" in payload["command"]
    assert "/wordlists/rockyou.txt" in payload["command"]


def test_hash_digest_tool_text() -> None:
    tool = HashDigestTool()
    result = tool.run(text="abc", algorithm="md5")
    assert result.body == hashlib.md5(b"abc").hexdigest()


def test_morse_decoder_handles_aliases_and_breakdown_toggle() -> None:
    tool = MorseDecoderTool()
    result = tool.run(morse=".... . .-.. .-.. --- // .-- --- .-. .-.. -..")
    assert "HELLO WORLD" in result.body
    assert "Unknown sequences: none" in result.body

    alias_result = tool.run(morse="·−· −·−·", dot_symbol="·", dash_symbol="−", show_breakdown="false")
    assert "RC" in alias_result.body
    assert "Breakdown" not in alias_result.body


def _write_morse_audio(path: Path, message: str, unit_seconds: float = 0.06) -> None:
    sample_rate = 8000
    tone_frequency = 700.0
    amplitude = 16000
    samples = array("h")
    phase = 0

    message = message.upper().strip()
    char_map = {value: code for code, value in MORSE_CODE_DICT.items() if len(value) == 1}
    words = [word for word in message.split(" ") if word]

    def add_tone(units: int) -> None:
        nonlocal phase
        total_samples = int(sample_rate * unit_seconds * units)
        for _ in range(total_samples):
            value = int(amplitude * math.sin(2 * math.pi * tone_frequency * phase / sample_rate))
            samples.append(value)
            phase += 1

    def add_silence(units: int) -> None:
        nonlocal phase
        total_samples = int(sample_rate * unit_seconds * units)
        samples.extend([0] * total_samples)
        phase += total_samples

    # Guard against empty messages
    if not words:
        add_silence(1)
    else:
        add_silence(1)
        for word_index, word in enumerate(words):
            for letter_index, letter in enumerate(word):
                code = char_map.get(letter)
                if not code:
                    raise ValueError(f"Unsupported character in test message: {letter}")
                for symbol_index, symbol in enumerate(code):
                    add_tone(1 if symbol == "." else 3)
                    if symbol_index < len(code) - 1:
                        add_silence(1)
                if letter_index < len(word) - 1:
                    add_silence(3)
            if word_index < len(words) - 1:
                add_silence(7)
        add_silence(1)

    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(samples.tobytes())


def test_morse_decoder_from_audio(tmp_path: Path) -> None:
    audio_path = tmp_path / "sos.wav"
    _write_morse_audio(audio_path, "SOS")
    tool = MorseDecoderTool()
    result = tool.run(audio_file=str(audio_path))
    assert "SOS" in result.body
    assert "Derived Morse" in result.body
    assert "Unknown sequences: none" in result.body


def test_rsa_toolkit_analyse_known_factors() -> None:
    p, q = 50021, 50023
    n = p * q
    e = 17
    plaintext = b"flag"
    message = int.from_bytes(plaintext, "big")
    ciphertext = pow(message, e, n)
    payload = json.loads(
        RSAToolkit().run(
            mode="analyse",
            n=str(n),
            e=str(e),
            ciphertext=str(ciphertext),
            known_factors=f"{p},{q}",
        ).body
    )
    assert payload["factored"]
    assert payload["plaintext"]["text"] == "flag"


def test_rsa_toolkit_crt_small_e() -> None:
    e = 3
    plaintext = int.from_bytes(b"ok", "big")
    primes = [(197, 199), (211, 223), (233, 239)]
    pairs = []
    for p, q in primes:
        n = p * q
        c = pow(plaintext, e, n)
        pairs.append(f"{c},{n}")
    instances = "\n".join(pairs)
    payload = json.loads(RSAToolkit().run(mode="crt", instances=instances, e=str(e)).body)
    assert payload["plaintext_text"] == "ok"


def test_xor_known_plaintext() -> None:
    keystream = bytes([0x10, 0x20, 0x30])
    plaintext = b"ABC"
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    payload = json.loads(
        XORKeystreamAnalyzer().run(
            mode="known_plaintext",
            ciphertext=ciphertext.hex(),
            known_plaintext="ABC",
        ).body
    )
    assert payload["keystream_hex"] == keystream.hex()
    assert payload["recovered_plaintext"].startswith("ABC")


def test_xor_pairwise_matrix() -> None:
    c1 = "001122"
    c2 = "aabbcc"
    payload = json.loads(
        XORKeystreamAnalyzer().run(
            mode="pairwise",
            ciphertexts=f"{c1}\n{c2}",
        ).body
    )
    pairs = {entry["pair"] for entry in payload["pairwise"]}
    assert "0-1" in pairs