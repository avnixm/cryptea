"""Bulk Extractor wrapper for digital forensics extraction."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, NamedTuple, Sequence

from ..base import ToolResult


def is_bulk_extractor_available() -> bool:
    return shutil.which("bulk_extractor") is not None


class BulkExtractorProfile(NamedTuple):
    """Declarative description for a preset scan profile."""

    profile_id: str
    label: str
    description: str
    args: Sequence[str]


PROFILE_CHOICES: Sequence[BulkExtractorProfile] = (
    BulkExtractorProfile(
        "quick",
        "Quick",
        "Fast extraction of common artifacts",
        ("-q", "1"),
    ),
    BulkExtractorProfile(
        "default",
        "Default",
        "Standard extraction",
        (),
    ),
    BulkExtractorProfile(
        "full",
        "Full",
        "Comprehensive extraction with all scanners",
        ("-E", "all"),
    ),
)


class BulkExtractorTool:
    name = "Bulk Extractor"
    description = "Digital forensics tool for extracting features from disk images."
    category = "Forensics"

    def run(
        self,
        input_file: str,
        profile: str = "default",
        output_dir: str = "",
        scanners: str = "",
        extra: str = "",
    ) -> ToolResult:
        if not is_bulk_extractor_available():
            raise RuntimeError("bulk_extractor not found in PATH. Install bulk_extractor locally.")
        
        input_path = Path(input_file).expanduser()
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Find profile
        selected_profile = None
        for p in PROFILE_CHOICES:
            if p.profile_id == profile:
                selected_profile = p
                break
        
        if selected_profile is None:
            selected_profile = PROFILE_CHOICES[1]  # default

        # Output directory
        if output_dir.strip():
            out_path = Path(output_dir.strip()).expanduser()
        else:
            out_path = input_path.parent / f"bulk_extractor_output_{input_path.stem}"
        
        out_path.mkdir(parents=True, exist_ok=True)

        args: List[str] = ["bulk_extractor", "-o", str(out_path)]

        # Add profile args
        args.extend(selected_profile.args)

        # Override scanners if specified
        if scanners.strip():
            args = [a for i, a in enumerate(args) if not (a == "-E" or (i > 0 and args[i-1] == "-E"))]
            args.extend(["-E", scanners.strip()])

        # Extra arguments
        if extra.strip():
            args.extend(extra.split())

        # Input file at the end
        args.append(str(input_path))

        # Execute
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1800,  # 30 minute timeout
        )

        body_lines: List[str] = []
        body_lines.append(f"Command: {' '.join(args)}")
        body_lines.append(f"Output directory: {out_path}")
        body_lines.append("")
        
        if proc.stdout.strip():
            body_lines.append("Results:")
            body_lines.append(proc.stdout.strip())
        
        # Analyze and categorize artifacts
        artifacts = self._analyze_artifacts(out_path)
        if artifacts:
            body_lines.append("")
            body_lines.append("Artifact Analysis:")
            body_lines.append(json.dumps(artifacts, indent=2))
        
        # List output files
        if out_path.exists():
            output_files = list(out_path.glob("*.txt"))
            if output_files:
                body_lines.append("")
                body_lines.append("Output files:")
                for f in sorted(output_files):
                    body_lines.append(f"  - {f.name}")
        
        if proc.stderr.strip():
            body_lines.append("")
            body_lines.append("Errors/Warnings:")
            body_lines.append(proc.stderr.strip())

        if proc.returncode != 0:
            raise RuntimeError(f"Bulk Extractor failed: {proc.stderr.strip()}")

        return ToolResult(
            title=f"Bulk Extractor: {input_path.name}",
            body="\n".join(body_lines).strip(),
            mime_type="text/plain",
        )

    def _analyze_artifacts(self, output_dir: Path) -> Dict[str, object]:
        """Analyze and categorize extracted artifacts."""
        artifacts: Dict[str, object] = {
            "categories": {},
            "summary": {},
        }
        
        if not output_dir.exists():
            return artifacts
        
        # Parse artifact files
        artifact_files = {
            "email": "email.txt",
            "ccn": "ccn.txt",  # Credit cards
            "domain": "domain.txt",
            "exif": "exif.txt",
            "find": "find.txt",
            "gps": "gps.txt",
            "rfc822": "rfc822.txt",
            "telephone": "telephone.txt",
            "url": "url.txt",
            "webmail": "webmail.txt",
            "winpe": "winpe.txt",
        }
        
        category_stats: Dict[str, Dict[str, object]] = {}
        
        for category, filename in artifact_files.items():
            file_path = output_dir / filename
            if file_path.exists():
                try:
                    content = file_path.read_text(errors="ignore")
                    lines = [line.strip() for line in content.splitlines() if line.strip()]
                    count = len(lines)
                    
                    if count > 0:
                        category_stats[category] = {
                            "count": count,
                            "sample": lines[:10],  # First 10 entries
                        }
                        
                        # Additional analysis per category
                        if category == "ccn":
                            category_stats[category]["credit_cards"] = self._analyze_credit_cards(lines)
                        elif category == "email":
                            category_stats[category]["emails"] = self._analyze_emails(lines)
                        elif category == "url":
                            category_stats[category]["urls"] = self._analyze_urls(lines)
                        elif category == "domain":
                            category_stats[category]["domains"] = self._analyze_domains(lines)
                        
                except Exception:
                    pass
        
        artifacts["categories"] = category_stats
        artifacts["summary"] = {
            "total_categories": len(category_stats),
            "total_artifacts": sum(cat.get("count", 0) for cat in category_stats.values() if isinstance(cat, dict)),
        }
        
        return artifacts

    def _analyze_credit_cards(self, lines: List[str]) -> Dict[str, object]:
        """Analyze credit card numbers."""
        # Credit card patterns (simplified)
        card_types: Dict[str, int] = defaultdict(int)
        
        for line in lines:
            # Extract card number (first number-like sequence)
            match = re.search(r'\b\d{13,19}\b', line)
            if match:
                card_num = match.group()
                # Basic card type detection by first digit
                first_digit = card_num[0]
                if first_digit == '3':
                    card_types["American Express/Diners"] += 1
                elif first_digit == '4':
                    card_types["Visa"] += 1
                elif first_digit == '5':
                    card_types["Mastercard"] += 1
                elif first_digit == '6':
                    card_types["Discover"] += 1
        
        return {"by_type": dict(card_types), "total": len(lines)}

    def _analyze_emails(self, lines: List[str]) -> Dict[str, object]:
        """Analyze email addresses."""
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails: List[str] = []
        domains: Dict[str, int] = defaultdict(int)
        
        for line in lines:
            matches = email_pattern.findall(line)
            for email in matches:
                emails.append(email)
                domain = email.split('@')[1] if '@' in email else ""
                if domain:
                    domains[domain] += 1
        
        return {
            "unique_emails": len(set(emails)),
            "total_occurrences": len(emails),
            "top_domains": dict(sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]),
        }

    def _analyze_urls(self, lines: List[str]) -> Dict[str, object]:
        """Analyze URLs."""
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        urls: List[str] = []
        domains: Dict[str, int] = defaultdict(int)
        
        for line in lines:
            matches = url_pattern.findall(line)
            for url in matches:
                urls.append(url)
                # Extract domain
                try:
                    domain_match = re.search(r'https?://([^/]+)', url)
                    if domain_match:
                        domain = domain_match.group(1)
                        domains[domain] += 1
                except Exception:
                    pass
        
        return {
            "unique_urls": len(set(urls)),
            "total_occurrences": len(urls),
            "top_domains": dict(sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]),
        }

    def _analyze_domains(self, lines: List[str]) -> Dict[str, object]:
        """Analyze domain names."""
        domain_pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b')
        domains: List[str] = []
        
        for line in lines:
            matches = domain_pattern.findall(line)
            for match in matches:
                domain = match[0] + '.' + match[1] if match[0] else match[1]
                domains.append(domain.lower())
        
        domain_counts: Dict[str, int] = defaultdict(int)
        for domain in domains:
            domain_counts[domain] += 1
        
        return {
            "unique_domains": len(domain_counts),
            "total_occurrences": len(domains),
            "top_domains": dict(sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
        }

