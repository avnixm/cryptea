"""Directory discovery wrapper with SecLists support and offline fallback."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..base import ToolResult
from ...data_paths import user_data_dir


WORDLISTS: Dict[str, Dict[str, str]] = {
    "small": {
        "label": "SecLists small.txt",
        "bundled": "small.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/small.txt",
    },
    "common": {
        "label": "SecLists common.txt",
        "bundled": "common.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    },
    "big": {
        "label": "SecLists big.txt",
        "bundled": "big.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
    },
    "raft-large": {
        "label": "SecLists raft-large-words.txt",
        "bundled": "raft-large-words.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt",
    },
}

RESOURCE_PACKAGE = "ctf_helper.data.SecLists"


@lru_cache()
def _project_seclists_dir() -> Optional[Path]:
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "data" / "SecLists"
        if candidate.exists():
            return candidate
    return None


def _wordlists_dir() -> Path:
    path = user_data_dir() / "wordlists" / "seclists"
    path.mkdir(parents=True, exist_ok=True)
    return path


def available_wordlists() -> List[Tuple[str, Path, str]]:
    records: List[Tuple[str, Path, str]] = []
    directory = _wordlists_dir()
    for slug, meta in WORDLISTS.items():
        path = directory / f"{slug}.txt"
        if not path.exists():
            bundled = WORDLISTS[slug].get("bundled")
            if bundled:
                bundled_path = _extract_bundled_wordlist(bundled)
                if bundled_path is not None and bundled_path.exists():
                    path = bundled_path
        records.append((slug, path, meta["label"]))
    return records


def ensure_wordlist(slug: str, allow_download: bool) -> Path | None:
    if slug not in WORDLISTS:
        return None
    path = _wordlists_dir() / f"{slug}.txt"
    if path.exists():
        return path
    bundled = WORDLISTS[slug].get("bundled")
    if bundled:
        bundled_path = _extract_bundled_wordlist(bundled)
        if bundled_path is not None:
            return bundled_path
    if not allow_download:
        return None
    meta = WORDLISTS[slug]
    url = meta.get("url")
    if not url:
        return None
    try:
        with urllib.request.urlopen(url) as response:
            data = response.read()
        path.write_bytes(data)
        return path
    except (urllib.error.URLError, OSError):
        return None


def _extract_bundled_wordlist(filename: str) -> Optional[Path]:
    try:
        with resources.as_file(resources.files(RESOURCE_PACKAGE) / filename) as ref:
            return Path(ref)
    except (FileNotFoundError, ModuleNotFoundError):
        pass

    # Fallback: look for project data directory (e.g. data/SecLists) when running from source tree
    base = _project_seclists_dir()
    if base is not None:
        direct = base / filename
        if direct.exists():
            return direct
        nested = base / "Discovery" / "Web-Content" / filename
        if nested.exists():
            return nested
    return None


def find_wordlists() -> List[str]:
    found: List[str] = []
    for slug, path, _label in available_wordlists():
        if path.exists():
            found.append(str(path))
    # fall back to system SecLists if present
    legacy_dirs: List[Path] = [
        Path("/usr/share/seclists"),
        Path.home() / "SecLists",
    ]
    # include bundled SecLists shipped with the app when running from source
    base = _project_seclists_dir()
    if base is not None:
        legacy_dirs.append(base)
    for base in legacy_dirs:
        if not base.exists():
            continue
        for rel in [
            "Discovery/Web-Content/small.txt",
            "Discovery/Web-Content/common.txt",
            "Discovery/Web-Content/big.txt",
            "Discovery/Web-Content/raft-large-words.txt",
            "small.txt",
            "common.txt",
            "big.txt",
            "raft-large-words.txt",
        ]:
            candidate = base / rel
            if candidate.exists():
                found.append(str(candidate))
    # Deduplicate preserving order
    deduped: List[str] = []
    seen: set[str] = set()
    for entry in found:
        if entry not in seen:
            seen.add(entry)
            deduped.append(entry)
    return deduped


def run_external(binary: str, args: List[str]) -> str:
    proc = subprocess.run([binary] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.stdout or proc.stderr


def _record(http_status: int, url: str, size: Optional[int]) -> dict:
    return {
        "url": url,
        "status": http_status,
        "size": size if size is not None else 0,
        "path": urlparse(url).path or "/",
    }


def fallback_fuzz(target: str, wordlist: str) -> List[dict]:
    # Offline-safe fallback using file read of saved site or HEAD requests to localhost only
    results: List[dict] = []
    base = target.rstrip("/")
    wl = Path(wordlist)
    if not wl.exists():
        return results
    try:
        parsed = urlparse(base)
        for line in wl.read_text(errors="ignore").splitlines():
            path = line.strip().lstrip("/")
            if not path:
                continue
            # Only allow file presence check for saved sites under file:// path
            if base.startswith("file://"):
                local = Path(base.replace("file://", "")) / path
                if local.exists():
                    results.append({"path": "/" + path, "status": 200, "size": local.stat().st_size})
            elif parsed.scheme in {"http", "https"}:
                if len(results) >= 256:
                    break
                url = urljoin(base + "/", path)
                try:
                    request = urllib.request.Request(url, method="HEAD")
                    with urllib.request.urlopen(request, timeout=4) as response:
                        length = response.headers.get("Content-Length")
                        size = int(length) if length and length.isdigit() else None
                        results.append(_record(response.getcode(), url, size))
                        continue
                except urllib.error.HTTPError as err:
                    # Treat common redirected/forbidden codes as a positive signal
                    if err.code in {301, 302, 303, 307, 401, 403}:
                        length = err.headers.get("Content-Length")
                        size = int(length) if length and length.isdigit() else None
                        results.append(_record(err.code, url, size))
                        continue
                    if err.code == 405:  # Method not allowed for HEAD, retry with GET
                        try:
                            get_req = urllib.request.Request(url, method="GET")
                            with urllib.request.urlopen(get_req, timeout=6) as response:
                                length = response.headers.get("Content-Length")
                                size = int(length) if length and length.isdigit() else None
                                results.append(_record(response.getcode(), url, size))
                        except Exception:
                            continue
                        continue
                except Exception:
                    continue
    except Exception:
        return results
    return results


class DirDiscoveryTool:
    name = "Dir Discovery"
    description = "Run dirb/gobuster/ffuf with curated SecLists wordlists or offline fallback."
    category = "Web"

    def run(
        self,
        target: str,
        tool: str = "auto",
        wordlist: str = "",
        threads: str = "20",
        wordlist_choice: str = "common",
        download_missing: str = "true",
    ) -> ToolResult:
        wl_path = wordlist.strip()
        if not wl_path:
            allow_download = str(download_missing).strip().lower() in {"1", "true", "yes", "on"}
            selected = ensure_wordlist(wordlist_choice, allow_download)
            if selected is None:
                return ToolResult(
                    title="Dir Discovery",
                    body="Wordlist not available locally. Enable download or provide a custom path.",
                )
            wl_path = str(selected)

        if not Path(wl_path).exists():
            return ToolResult(title="Dir Discovery", body=f"Wordlist not found: {wl_path}")

        # prefer selected binary
        tools = [tool] if tool not in {"", "auto"} else ["ffuf", "gobuster", "dirb"]
        for candidate in tools:
            binary = shutil.which(candidate)
            if not binary:
                continue
            if candidate == "ffuf":
                out = run_external(binary, ["-u", f"{target}/FUZZ", "-w", wl_path, "-t", threads])
            elif candidate == "gobuster":
                out = run_external(binary, ["dir", "-u", target, "-w", wl_path, "-t", threads])
            else:  # dirb
                out = run_external(binary, [target, wl_path])
            return ToolResult(title=f"{candidate} results", body=out)

        # fallback
        rows = fallback_fuzz(target, wl_path)
        return ToolResult(title="Fallback results", body=json.dumps(rows, indent=2), mime_type="application/json")
