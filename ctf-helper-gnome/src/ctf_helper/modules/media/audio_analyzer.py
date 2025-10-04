"""Offline-friendly audio analysis helpers."""

from __future__ import annotations

import json
import math
import struct
import wave
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from ..base import ToolResult


@dataclass(slots=True)
class AudioSummary:
    duration_seconds: float
    channels: int
    sample_rate: int
    sample_width: int
    rms: float
    peak: float
    clipping: bool


class AudioAnalyzerTool:
    """Summarise PCM audio and detect simple DTMF/Morse patterns."""

    name = "Audio Analyzer"
    description = "Summarise audio, detect DTMF tones, and approximate Morse beeps."
    category = "Stego & Media"

    def run(
        self,
        file_path: str,
        detect_dtmf: str = "true",
        detect_morse: str = "false",
        channel: str = "mixed",
        window_ms: str = "80",
    ) -> ToolResult:
        path = Path(file_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(path)

        window = max(20, int(float(window_ms or "80")))
        dtmf_enabled = self._truthy(detect_dtmf)
        morse_enabled = self._truthy(detect_morse)
        channel_mode = (channel or "mixed").strip().lower()

        summary, samples = self._load_samples(path, channel_mode)
        payload: Dict[str, object] = {
            "file": str(path.resolve()),
            "summary": asdict(summary),
        }

        if dtmf_enabled and samples:
            payload["dtmf_candidates"] = self._detect_dtmf(samples, summary.sample_rate, window)
        if morse_enabled and samples:
            morse = self._detect_morse(samples, summary.sample_rate)
            if morse:
                payload["morse"] = morse

        body = json.dumps(payload, indent=2)
        return ToolResult(title=f"Audio analysis for {path.name}", body=body, mime_type="application/json")

    # ------------------------------------------------------------------
    # Audio loading helpers
    # ------------------------------------------------------------------
    def _load_samples(self, path: Path, channel_mode: str) -> tuple[AudioSummary, Sequence[int]]:
        with wave.open(str(path), "rb") as wav:
            channels = wav.getnchannels()
            sample_width = wav.getsampwidth()
            sample_rate = wav.getframerate()
            frames = wav.getnframes()
            raw = wav.readframes(frames)

        if sample_width not in {1, 2}:
            raise ValueError("Only 8-bit and 16-bit PCM WAV files are supported")

        step = sample_width * channels
        total_frames = len(raw) // step if step else 0
        fmt_char = "b" if sample_width == 1 else "h"
        fmt = "<" + fmt_char * channels

        samples: List[int] = []
        for frame in struct.iter_unpack(fmt, raw[: total_frames * step]):
            if channel_mode == "left" and channels >= 1:
                value = frame[0]
            elif channel_mode == "right" and channels >= 2:
                value = frame[1]
            else:
                value = sum(frame) / len(frame)
            samples.append(int(round(value)))

        duration = len(samples) / sample_rate if sample_rate else 0.0
        rms = self._rms(samples)
        peak_val = max((abs(value) for value in samples), default=0)
        max_possible = float((1 << (sample_width * 8 - 1)) - 1)
        clipping = peak_val >= max_possible

        summary = AudioSummary(
            duration_seconds=round(duration, 6),
            channels=channels,
            sample_rate=sample_rate,
            sample_width=sample_width,
            rms=rms,
            peak=peak_val,
            clipping=clipping,
        )
        return summary, samples

    # ------------------------------------------------------------------
    # DTMF detection
    # ------------------------------------------------------------------
    def _detect_dtmf(self, samples: Sequence[int], sample_rate: int, window_ms: int) -> List[Dict[str, object]]:
        window_samples = max(int(sample_rate * window_ms / 1000), sample_rate // 20, 80)
        step = max(window_samples // 2, 40)
        low_freqs = [697, 770, 852, 941]
        high_freqs = [1209, 1336, 1477, 1633]
        digit_map = {
            (697, 1209): "1",
            (697, 1336): "2",
            (697, 1477): "3",
            (770, 1209): "4",
            (770, 1336): "5",
            (770, 1477): "6",
            (852, 1209): "7",
            (852, 1336): "8",
            (852, 1477): "9",
            (941, 1209): "*",
            (941, 1336): "0",
            (941, 1477): "#",
            (697, 1633): "A",
            (770, 1633): "B",
            (852, 1633): "C",
            (941, 1633): "D",
        }

        detections: List[Dict[str, object]] = []
        active: Optional[Dict[str, object]] = None
        total_samples = len(samples)

        for start in range(0, total_samples - window_samples + 1, step):
            window = samples[start : start + window_samples]
            if not window:
                continue
            max_abs = max(abs(value) for value in window)
            if max_abs < 40:
                if active:
                    detections.append(active)
                    active = None
                continue

            low_scores = {freq: self._goertzel(window, sample_rate, freq) for freq in low_freqs}
            high_scores = {freq: self._goertzel(window, sample_rate, freq) for freq in high_freqs}

            best_low = max(low_scores.items(), key=lambda item: item[1])
            best_high = max(high_scores.items(), key=lambda item: item[1])
            second_low = sorted((value for key, value in low_scores.items() if key != best_low[0]), reverse=True)
            second_high = sorted((value for key, value in high_scores.items() if key != best_high[0]), reverse=True)
            second_low_value = second_low[0] if second_low else 0.0
            second_high_value = second_high[0] if second_high else 0.0

            if best_low[1] < 1000 or best_high[1] < 1000:
                if active:
                    detections.append(active)
                    active = None
                continue
            if best_low[1] < second_low_value * 3 or best_high[1] < second_high_value * 3:
                if active:
                    detections.append(active)
                    active = None
                continue

            digit = digit_map.get((best_low[0], best_high[0]))
            if not digit:
                continue
            strength = min(best_low[1], best_high[1])
            start_time = start / sample_rate
            end_time = (start + window_samples) / sample_rate

            if active and active.get("digit") == digit:
                active["end"] = end_time
                previous_raw = active.get("strength")
                previous_strength = float(previous_raw) if isinstance(previous_raw, (int, float)) else 0.0
                active["strength"] = max(previous_strength, strength)
            else:
                if active:
                    detections.append(active)
                active = {
                    "digit": digit,
                    "start": start_time,
                    "end": end_time,
                    "low_freq": best_low[0],
                    "high_freq": best_high[0],
                    "strength": strength,
                }

        if active:
            detections.append(active)

        return detections

    def _goertzel(self, samples: Sequence[int], sample_rate: int, target_freq: int) -> float:
        k = int(0.5 + ((len(samples) * target_freq) / sample_rate))
        omega = (2.0 * math.pi * k) / len(samples)
        sine = math.sin(omega)
        cosine = math.cos(omega)
        coeff = 2 * cosine
        q0 = 0.0
        q1 = 0.0
        q2 = 0.0
        for sample in samples:
            q0 = coeff * q1 - q2 + sample
            q2 = q1
            q1 = q0
        real = q1 - q2 * cosine
        imag = q2 * sine
        return real * real + imag * imag

    # ------------------------------------------------------------------
    # Morse approximation
    # ------------------------------------------------------------------
    def _detect_morse(self, samples: Sequence[int], sample_rate: int) -> Dict[str, object]:
        if not samples:
            return {}
        chunk = max(sample_rate // 200, 20)
        prefix = self._prefix_squares(samples)
        windows: List[tuple[float, int]] = []
        for start in range(0, len(samples), chunk):
            end = min(len(samples), start + chunk)
            length = end - start
            if length <= 0:
                continue
            rms = self._window_rms(prefix, start, end)
            windows.append((rms, length))
        if not windows:
            return {}

        peak = max(value for value, _ in windows)
        if peak < 20:
            return {}
        threshold = max(peak * 0.35, 20)

        segments: List[Dict[str, float]] = []
        state = windows[0][0] >= threshold
        length_acc = 0
        for rms_value, length in windows:
            tone = rms_value >= threshold
            if tone == state:
                length_acc += length
            else:
                segments.append({"tone": state, "duration": round(length_acc / sample_rate, 6)})
                state = tone
                length_acc = length
        if length_acc > 0:
            segments.append({"tone": state, "duration": round(length_acc / sample_rate, 6)})

        tone_segments = [seg["duration"] for seg in segments if seg["tone"]]
        if not tone_segments:
            return {}
        unit = min(tone_segments)
        if unit <= 0:
            return {}

        morse_symbols: List[str] = []
        decoded_characters: List[str] = []
        current_symbol = ""

        for segment in segments:
            if segment["tone"]:
                ratio = segment["duration"] / unit
                symbol = "." if ratio <= 1.5 else "-"
                current_symbol += symbol
            else:
                gap_ratio = segment["duration"] / unit
                if gap_ratio < 1.5:
                    continue
                if current_symbol:
                    morse_symbols.append(current_symbol)
                    decoded_characters.append(self._morse_lookup(current_symbol))
                    current_symbol = ""
                if gap_ratio >= 3.5:
                    decoded_characters.append(" ")

        if current_symbol:
            morse_symbols.append(current_symbol)
            decoded_characters.append(self._morse_lookup(current_symbol))

        decoded_text = "".join(decoded_characters).replace("  ", " ").strip()
        return {
            "unit_seconds": round(unit, 6),
            "symbols": morse_symbols,
            "decoded": decoded_text,
            "segments": segments,
        }

    def _morse_lookup(self, pattern: str) -> str:
        table = {
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
        }
        return table.get(pattern, "?")

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------
    def _rms(self, samples: Sequence[int]) -> float:
        if not samples:
            return 0.0
        mean = sum(value * value for value in samples) / len(samples)
        return math.sqrt(mean)

    def _prefix_squares(self, samples: Sequence[int]) -> List[float]:
        prefix: List[float] = [0.0]
        total = 0.0
        for value in samples:
            total += float(value) * float(value)
            prefix.append(total)
        return prefix

    def _window_rms(self, prefix: Sequence[float], start: int, end: int) -> float:
        length = end - start
        if length <= 0:
            return 0.0
        total = prefix[end] - prefix[start]
        if total <= 0:
            return 0.0
        return math.sqrt(total / length)

    def _truthy(self, value: str | bool | None) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
