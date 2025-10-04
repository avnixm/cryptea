"""Offline Morse code decoder tool."""

from __future__ import annotations

import re
import wave
from array import array
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from ..base import ToolResult

MORSE_CODE_DICT: Dict[str, str] = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    ".-.-.-": ".",
    "--..--": ",",
    "..--..": "?",
    ".----.": "'",
    "-.-.--": "!",
    "-..-.": "/",
    "-.--.": "(",
    "-.--.-": ")",
    ".-...": "&",
    "---...": ":",
    "-.-.-.": ";",
    "-...-": "=",
    ".-.-.": "+",
    "-....-": "-",
    "..--.-": "_",
    ".-..-.": '"',
    "...-..-": "$",
    ".--.-.": "@",
    "...---...": "SOS",
    ".-.-": "Ä",
    "---.": "Ö",
    "..--": "Ü",
    "..-..": "É",
    "--.--": "Ñ",
}

DOT_ALIASES = {"·", "•"}
DASH_ALIASES = {"–", "—", "−", "_"}


class MorseDecoderTool:
    name = "Morse Decoder"
    description = "Decode Morse code from text or audio with flexible separators and symbol normalisation."
    category = "Crypto & Encoding"

    def run(
        self,
        morse: str = "",
        letter_separators: str = "",
        word_separators: str = "",
        dot_symbol: str = ".",
        dash_symbol: str = "-",
        output_case: str = "upper",
        show_breakdown: str = "true",
        audio_file: str = "",
    ) -> ToolResult:
        morse_input = morse or ""
        audio_path = audio_file.strip()
        if audio_path:
            morse_input = self._morse_from_audio(audio_path)

        if not morse_input.strip():
            raise ValueError("Provide Morse code to decode")

        normalised = self._normalise_symbols(morse_input, dot_symbol or ".", dash_symbol or "-")
        words = self._split_words(normalised, letter_separators, word_separators)
        if not words:
            raise ValueError("No Morse symbols detected after normalisation")

        decoded_words, breakdown, unknown = self._decode(words)
        text = self._apply_case(" ".join(decoded_words), output_case)

        sections: List[str] = ["Decoded text:", text, ""]
        if audio_path:
            sections.extend(["Derived Morse:", normalised, ""])
        if unknown:
            unique_unknown = ", ".join(sorted(set(unknown)))
            sections.append(f"Unknown sequences: {unique_unknown}")
        else:
            sections.append("Unknown sequences: none")

        if self._truthy(show_breakdown) and breakdown:
            sections.extend(["", "Breakdown:"])
            sections.extend(breakdown)

        body = "\n".join(sections).rstrip()
        return ToolResult(title="Morse decode result", body=body)

    def _normalise_symbols(self, text: str, dot_symbol: str, dash_symbol: str) -> str:
        working = text.replace("\r\n", "\n").replace("\r", "\n")
        for alias in DOT_ALIASES:
            working = working.replace(alias, ".")
        for alias in DASH_ALIASES:
            working = working.replace(alias, "-")
        if dot_symbol and dot_symbol != ".":
            working = working.replace(dot_symbol, ".")
        if dash_symbol and dash_symbol != "-":
            working = working.replace(dash_symbol, "-")
        return working

    def _split_words(
        self,
        text: str,
        letter_separators: str,
        word_separators: str,
    ) -> List[List[str]]:
        sentinel = "\uFFFF"
        working = text

        explicit_word = set(self._parse_separators(word_separators))
        explicit_letter = set(self._parse_separators(letter_separators))

        for sep in explicit_word:
            working = working.replace(sep, sentinel)

        working = re.sub(r"(?:\s{2,}|(?:\s*/\s*)+|\|+)", sentinel, working)
        working = working.replace("\n", sentinel)

        for sep in explicit_letter:
            working = working.replace(sep, " ")

        working = working.replace("\t", " ")
        working = working.replace("\f", " ")
        working = working.replace("\v", " ")

        working = re.sub(r" +", " ", working)
        working = re.sub(rf"{re.escape(sentinel)}+", sentinel, working)

        chunks = [chunk.strip() for chunk in working.split(sentinel)]
        letters_per_word: List[List[str]] = []
        for chunk in chunks:
            if not chunk:
                continue
            letters = [token for token in chunk.split(" ") if token]
            if letters:
                letters_per_word.append(letters)
        return letters_per_word

    def _decode(self, words: Sequence[Sequence[str]]) -> Tuple[List[str], List[str], List[str]]:
        decoded_words: List[str] = []
        breakdown: List[str] = []
        unknown_sequences: List[str] = []

        for index, letters in enumerate(words, start=1):
            letter_results: List[str] = []
            breakdown.append(f"Word {index}:")
            for letter in letters:
                symbol = MORSE_CODE_DICT.get(letter)
                if symbol is None:
                    letter_results.append("?")
                    unknown_sequences.append(letter)
                    breakdown.append(f"  {letter:>8} -> ?")
                else:
                    letter_results.append(symbol)
                    breakdown.append(f"  {letter:>8} -> {symbol}")
            decoded_words.append("".join(letter_results))
            breakdown.append("")

        if breakdown and breakdown[-1] == "":
            breakdown.pop()
        return decoded_words, breakdown, unknown_sequences

    def _apply_case(self, text: str, mode: str) -> str:
        normalized = (mode or "upper").strip().lower()
        if normalized == "lower":
            return text.lower()
        if normalized in {"title", "capitalise", "capitalize"}:
            return text.title()
        return text.upper()

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _parse_separators(self, raw: str) -> Iterable[str]:
        if not raw or not raw.strip():
            return []
        parts = [part for part in re.split(r"[,\s]+", raw) if part]
        return parts

    # ------------------------------------------------------------------
    # Audio helpers
    # ------------------------------------------------------------------
    def _morse_from_audio(self, audio_file: str, window_seconds: float = 0.01) -> str:
        path = Path(audio_file)
        if not path.exists():
            raise ValueError(f"Audio file not found: {audio_file}")

        with wave.open(str(path), "rb") as wav:
            sample_width = wav.getsampwidth()
            channels = wav.getnchannels()
            frame_rate = wav.getframerate()
            frame_count = wav.getnframes()
            frames = wav.readframes(frame_count)

        if frame_count == 0:
            raise ValueError("Audio file is empty")

        mono = self._audio_to_mono(frames, sample_width, channels)
        if not mono:
            raise ValueError("Unable to read audio samples")

        max_amplitude = max(abs(sample) for sample in mono)
        if max_amplitude == 0:
            raise ValueError("Audio does not contain detectable tone")
        threshold = max_amplitude * 0.3

        window_size = max(1, int(frame_rate * window_seconds))
        window_duration = window_size / frame_rate

        windows: List[bool] = []
        for index in range(0, len(mono), window_size):
            chunk = mono[index:index + window_size]
            if not chunk:
                continue
            average = sum(abs(value) for value in chunk) / len(chunk)
            windows.append(average >= threshold)

        if not windows or not any(windows):
            raise ValueError("No Morse tone detected in audio")

        durations: List[Tuple[bool, float]] = []
        current_state = windows[0]
        count = 1
        for state in windows[1:]:
            if state == current_state:
                count += 1
            else:
                durations.append((current_state, count * window_duration))
                current_state = state
                count = 1
        durations.append((current_state, count * window_duration))

        # Drop leading silence to simplify processing
        while durations and durations[0][0] is False:
            durations.pop(0)

        if not durations:
            raise ValueError("Audio did not yield Morse segments")

        base_unit = self._infer_time_unit(durations)
        if base_unit <= 0:
            raise ValueError("Could not infer Morse timing from audio")

        words: List[List[str]] = []
        current_word: List[str] = []
        current_letter: List[str] = []

        def flush_letter() -> None:
            if current_letter:
                current_word.append(''.join(current_letter))
                current_letter.clear()

        def flush_word() -> None:
            flush_letter()
            if current_word:
                words.append(current_word.copy())
                current_word.clear()

        for is_tone, duration in durations:
            units = max(1, int(round(duration / base_unit)))
            if is_tone:
                symbol = '.' if units <= 2 else '-'
                current_letter.append(symbol)
            else:
                if units >= 6:
                    flush_word()
                elif units >= 3:
                    flush_letter()
                # units < 3 -> intra-letter spacing (do nothing)

        flush_word()
        if current_word:
            words.append(current_word.copy())
            current_word.clear()

        morse_words = [' '.join(word) for word in words if word]
        morse_string = '  '.join(morse_words).strip()
        return morse_string

    def _audio_to_mono(self, frames: bytes, sample_width: int, channels: int) -> List[float]:
        if sample_width == 1:
            samples = array('B')
            samples.frombytes(frames)
            centred = [sample - 128 for sample in samples]
        else:
            width_map = {2: 'h', 4: 'i'}
            kind = width_map.get(sample_width)
            if kind is None:
                raise ValueError("Unsupported audio format: expected 8-, 16-, or 32-bit PCM")
            samples = array(kind)
            samples.frombytes(frames)
            centred = list(samples)

        if channels == 1:
            return [float(value) for value in centred]

        if channels <= 0:
            raise ValueError("Invalid channel count in audio")

        mono: List[float] = []
        total_frames = len(centred) // channels
        for frame_index in range(total_frames):
            start = frame_index * channels
            window = centred[start:start + channels]
            mono.append(sum(window) / channels)
        return mono

    def _infer_time_unit(self, durations: Sequence[Tuple[bool, float]]) -> float:
        tone_durations = sorted(duration for state, duration in durations if state and duration > 0)
        silence_durations = sorted(duration for state, duration in durations if not state and duration > 0)

        candidates: List[float] = []
        if tone_durations:
            candidates.append(tone_durations[0])
        if silence_durations:
            candidates.append(silence_durations[0])

        if not candidates:
            return 0.0
        return min(candidates)
