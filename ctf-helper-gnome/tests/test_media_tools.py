from __future__ import annotations

import importlib
import json
import math
import os
import sys
import tempfile
import unittest
import wave
from array import array
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

AudioAnalyzerTool = importlib.import_module("ctf_helper.modules.media.audio_analyzer").AudioAnalyzerTool  # type: ignore[attr-defined]
ExifMetadataTool = importlib.import_module("ctf_helper.modules.media.exif_metadata").ExifMetadataTool  # type: ignore[attr-defined]
ImageStegoTool = importlib.import_module("ctf_helper.modules.media.image_stego").ImageStegoTool  # type: ignore[attr-defined]
QRScannerTool = importlib.import_module("ctf_helper.modules.media.qr_scanner").QRScannerTool  # type: ignore[attr-defined]
VideoFrameExporterTool = importlib.import_module("ctf_helper.modules.media.video_frame_exporter").VideoFrameExporterTool  # type: ignore[attr-defined]


@contextmanager
def temporary_environment(**updates: Optional[str]) -> Iterator[None]:
    original = {key: os.environ.get(key) for key in updates}
    try:
        for key, value in updates.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class MediaToolsTest(unittest.TestCase):
    def test_image_stego_uses_wrappers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            image_path = base / "sample.png"
            image_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"data" * 5)

            zsteg_script = base / "zsteg"
            zsteg_script.write_text(
                """#!/usr/bin/env python3
import sys
print('zsteg demo output for', sys.argv[-1])
""",
                encoding="utf-8",
            )
            zsteg_script.chmod(0o755)

            steghide_script = base / "steghide"
            steghide_script.write_text(
                """#!/usr/bin/env python3
import sys
args = ' '.join(sys.argv[1:])
if 'info' in args:
    print('steghide info: no embedded data')
else:
    print('steghide mode')
""",
                encoding="utf-8",
            )
            steghide_script.chmod(0o755)

            with temporary_environment(
                CTF_HELPER_ZSTEG=str(zsteg_script),
                CTF_HELPER_STEGHIDE=str(steghide_script),
                CTF_HELPER_STEGSOLVE=None,
            ):
                tool = ImageStegoTool()
                result = tool.run(str(image_path), steghide_extract="false")
                payload = json.loads(result.body)
                operations = payload["operations"]
                self.assertTrue(operations["zsteg"]["available"])
                self.assertEqual(operations["steghide"]["available"], True)
                self.assertIn("steghide info", operations["steghide"]["info"])

    def test_exif_metadata_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            target = base / "plain.bin"
            target.write_bytes(b"a" * 32)

            with temporary_environment(CTF_HELPER_EXIFTOOL=None):
                tool = ExifMetadataTool()
                result = tool.run(str(target), prefer_exiftool="false")
                payload = json.loads(result.body)
                sources = {entry["source"] for entry in payload["sources"]}
                self.assertIn("filesystem", sources)
                self.assertEqual(payload["gps"], {})

    def test_audio_analyzer_detects_dtmf(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            audio_path = base / "tone.wav"
            self._write_dtmf_wav(audio_path, digit="5", duration=0.5)

            tool = AudioAnalyzerTool()
            result = tool.run(str(audio_path), detect_morse="false")
            payload = json.loads(result.body)
            digits = [entry["digit"] for entry in payload.get("dtmf_candidates", [])]
            self.assertIn("5", digits)
            self.assertEqual(payload["summary"]["sample_rate"], 8000)

    def test_video_frame_exporter_stub(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            video_path = base / "clip.mp4"
            video_path.write_bytes(b"fake")
            output_dir = base / "frames"

            ffmpeg_script = base / "ffmpeg"
            ffmpeg_script.write_text(
                """#!/usr/bin/env python3
import pathlib
import sys
pattern = pathlib.Path(sys.argv[-1].replace('%06d', '000001'))
pattern.parent.mkdir(parents=True, exist_ok=True)
pattern.write_bytes(b'frame-data')
""",
                encoding="utf-8",
            )
            ffmpeg_script.chmod(0o755)

            with temporary_environment(CTF_HELPER_FFMPEG=str(ffmpeg_script)):
                tool = VideoFrameExporterTool()
                result = tool.run(
                    str(video_path),
                    output_dir=str(output_dir),
                    interval_seconds="1.5",
                    max_frames="1",
                    analyze_frames="true",
                )
                payload = json.loads(result.body)
                self.assertEqual(payload["frames_found"], 1)
                frame_info = payload["frames"][0]
                self.assertEqual(frame_info["file"], "frame_000001.png")
                self.assertGreater(frame_info["size_bytes"], 0)

    def test_qr_scanner_stub(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            image_dir = Path(base)
            sample_image = image_dir / "code.png"
            sample_image.write_bytes(b"fakeimage")

            zbar_script = base / "zbarimg"
            zbar_script.write_text(
                """#!/usr/bin/env python3
import pathlib
import sys
filename = pathlib.Path(sys.argv[-1])
print(f'QR-Code:payload:{filename.name}')
""",
                encoding="utf-8",
            )
            zbar_script.chmod(0o755)

            with temporary_environment(CTF_HELPER_ZBARIMG=str(zbar_script)):
                tool = QRScannerTool()
                result = tool.run(str(image_dir), recursive="true", include_raw_output="true")
                payload = json.loads(result.body)
                self.assertTrue(payload["available"])
                self.assertEqual(len(payload["results"]), 1)
                decoded = payload["results"][0]["decoded"][0]
                self.assertEqual(decoded["type"], "QR-Code")
                self.assertIn("payload", decoded["data"])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _write_dtmf_wav(self, path: Path, digit: str, duration: float) -> None:
        low_freqs = {
            "1": 697,
            "2": 697,
            "3": 697,
            "4": 770,
            "5": 770,
            "6": 770,
            "7": 852,
            "8": 852,
            "9": 852,
            "0": 941,
        }
        high_freqs = {
            "1": 1209,
            "2": 1336,
            "3": 1477,
            "4": 1209,
            "5": 1336,
            "6": 1477,
            "7": 1209,
            "8": 1336,
            "9": 1477,
            "0": 1336,
        }
        low = low_freqs.get(digit, 770)
        high = high_freqs.get(digit, 1336)
        rate = 8000
        total_samples = int(rate * duration)
        samples = array("h")
        for idx in range(total_samples):
            t = idx / rate
            value = int(16000 * (math.sin(2 * math.pi * low * t) + math.sin(2 * math.pi * high * t)) / 2)
            samples.append(value)
        with wave.open(str(path), "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(rate)
            wav_file.writeframes(samples.tobytes())


if __name__ == "__main__":
    unittest.main()
