"""Generate simple offline wordlists for brute-force attempts."""

from __future__ import annotations

import itertools
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Set

from ..base import ToolResult
from ...data_paths import user_data_dir


class WordlistGenerator:
    name = "Wordlist Generator"
    description = "Generate permutations of supplied tokens (offline)."
    category = "Misc"

    def run(
        self,
        tokens: str = "",
        min_length: str = "1",
        max_length: str = "3",
        generation_mode: str = "permutations",
        pattern: str = "",
        charset: str = "lowercase",
        custom_charset: str = "",
        mutations: str = "none",
        date_range: str = "",
        date_format: str = "YYYY",
        append_pattern: str = "",
        prepend_pattern: str = "",
        estimate_size: str = "true",
        save_to_file: str = "false",
        output_file: str = "",
    ) -> ToolResult:
        lines: List[str] = []
        
        # Pattern-based generation
        if pattern.strip():
            lines.extend(self._generate_from_pattern(pattern, date_range, date_format))
        
        # Token-based generation
        if tokens.strip():
            parts = [token.strip() for token in tokens.split(',') if token.strip()]
            if parts:
                if generation_mode == "permutations":
                    lines.extend(self._generate_permutations(parts, min_length, max_length))
                elif generation_mode == "combinations":
                    lines.extend(self._generate_combinations(parts, min_length, max_length))
                elif generation_mode == "sequential":
                    lines.extend(self._generate_sequential(parts, min_length, max_length))
        
        # Character set generation
        if charset != "none" and not tokens.strip() and not pattern.strip():
            char_set = self._get_charset(charset, custom_charset)
            if char_set:
                min_len = int(min_length) if min_length.strip() else 1
                max_len = int(max_length) if max_length.strip() else 3
                lines.extend(self._generate_from_charset(char_set, min_len, max_len))
        
        # Apply mutations
        if mutations != "none" and lines:
            lines = self._apply_mutations(lines, mutations)
        
        # Apply append/prepend patterns
        if append_pattern.strip():
            lines = [line + append_pattern for line in lines]
        if prepend_pattern.strip():
            lines = [prepend_pattern + line for line in lines]
        
        # Remove duplicates while preserving order
        seen: Set[str] = set()
        unique_lines: List[str] = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                unique_lines.append(line)
        lines = unique_lines
        
        # Size estimation
        body_lines: List[str] = []
        if self._is_truthy(estimate_size):
            body_lines.append(f"Estimated wordlist size: {len(lines):,} entries")
            body_lines.append("")
        
        # Save to file if requested
        if self._is_truthy(save_to_file) or output_file.strip():
            output_path = self._save_wordlist(lines, output_file)
            body_lines.append(f"Wordlist saved to: {output_path}")
            body_lines.append(f"Total entries: {len(lines):,}")
            body_lines.append("")
            body_lines.append("Preview (first 50 entries):")
            body_lines.append("\n".join(lines[:50]))
            if len(lines) > 50:
                body_lines.append(f"\n... and {len(lines) - 50:,} more entries")
        else:
            # Show all or preview
            if len(lines) > 1000:
                body_lines.append(f"Generated {len(lines):,} entries (showing first 1000):")
                body_lines.append("\n".join(lines[:1000]))
                body_lines.append(f"\n... and {len(lines) - 1000:,} more entries")
            else:
                body_lines.append("\n".join(lines))
        
        body = "\n".join(body_lines)
        return ToolResult(title="Generated wordlist", body=body)
    
    def _generate_from_pattern(self, pattern: str, date_range: str, date_format: str) -> List[str]:
        """Generate words from pattern templates."""
        results: List[str] = []
        
        # Date patterns
        if "YYYY" in pattern or "YY" in pattern or "MM" in pattern or "DD" in pattern:
            dates = self._generate_dates(date_range, date_format)
            for date_str in dates:
                result = pattern.replace("YYYY", date_str[:4] if len(date_str) >= 4 else date_str)
                result = result.replace("YY", date_str[-2:] if len(date_str) >= 2 else date_str)
                result = result.replace("MM", date_str[5:7] if len(date_str) >= 7 else "01")
                result = result.replace("DD", date_str[8:10] if len(date_str) >= 10 else "01")
                results.append(result)
        else:
            # Common patterns
            common_patterns = {
                "company": ["company", "corp", "inc", "llc"],
                "year": [str(y) for y in range(2020, 2025)],
                "season": ["spring", "summer", "fall", "winter"],
            }
            # Simple pattern replacement
            results.append(pattern)
        
        return results
    
    def _generate_dates(self, date_range: str, date_format: str) -> List[str]:
        """Generate date strings based on range and format."""
        dates: List[str] = []
        
        if not date_range.strip():
            # Default: last 5 years
            end_year = datetime.now().year
            start_year = end_year - 5
        else:
            # Parse range (e.g., "2020-2024")
            if "-" in date_range:
                try:
                    start_year, end_year = map(int, date_range.split("-"))
                except ValueError:
                    start_year = datetime.now().year - 5
                    end_year = datetime.now().year
            else:
                start_year = end_year = int(date_range) if date_range.isdigit() else datetime.now().year
        
        for year in range(start_year, end_year + 1):
            if date_format == "YYYY":
                dates.append(str(year))
            elif date_format == "YY":
                dates.append(str(year)[-2:])
            elif date_format == "MM-DD-YYYY":
                for month in range(1, 13):
                    for day in range(1, 29):  # Simplified
                        dates.append(f"{month:02d}-{day:02d}-{year}")
            elif date_format == "YYYY-MM-DD":
                for month in range(1, 13):
                    for day in range(1, 29):
                        dates.append(f"{year}-{month:02d}-{day:02d}")
        
        return dates[:1000]  # Limit to prevent huge lists
    
    def _generate_permutations(self, parts: List[str], min_len: int, max_len: int) -> List[str]:
        """Generate all permutations."""
        lines: List[str] = []
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(parts, repeat=length):
                lines.append(''.join(combo))
        return lines
    
    def _generate_combinations(self, parts: List[str], min_len: int, max_len: int) -> List[str]:
        """Generate combinations (order doesn't matter)."""
        lines: List[str] = []
        for length in range(min_len, min(max_len + 1, len(parts) + 1)):
            for combo in itertools.combinations(parts, length):
                lines.append(''.join(combo))
        return lines
    
    def _generate_sequential(self, parts: List[str], min_len: int, max_len: int) -> List[str]:
        """Generate sequential patterns."""
        lines: List[str] = []
        for length in range(min_len, max_len + 1):
            for i in range(len(parts) - length + 1):
                lines.append(''.join(parts[i:i+length]))
        return lines
    
    def _get_charset(self, charset: str, custom: str) -> str:
        """Get character set string."""
        charsets: Dict[str, str] = {
            "lowercase": "abcdefghijklmnopqrstuvwxyz",
            "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "digits": "0123456789",
            "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?",
            "alphanumeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "mixed": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*",
        }
        
        if charset == "custom" and custom.strip():
            return custom.strip()
        return charsets.get(charset.lower(), "")
    
    def _generate_from_charset(self, charset: str, min_len: int, max_len: int) -> List[str]:
        """Generate words from character set."""
        lines: List[str] = []
        # Limit to prevent huge wordlists
        max_combinations = 100000
        count = 0
        
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                if count >= max_combinations:
                    return lines
                lines.append(''.join(combo))
                count += 1
        
        return lines
    
    def _apply_mutations(self, lines: List[str], mutation_type: str) -> List[str]:
        """Apply mutations to wordlist."""
        results: List[str] = []
        
        for line in lines:
            results.append(line)  # Original
            
            if mutation_type in ["case", "all"]:
                # Case variations
                results.append(line.lower())
                results.append(line.upper())
                results.append(line.capitalize())
                if len(line) > 1:
                    results.append(line[0].upper() + line[1:].lower())
            
            if mutation_type in ["leet", "all"]:
                # Leet speak
                leet_map = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
                leet_line = line
                for char, replacement in leet_map.items():
                    leet_line = leet_line.replace(char, replacement)
                    leet_line = leet_line.replace(char.upper(), replacement)
                if leet_line != line:
                    results.append(leet_line)
            
            if mutation_type in ["append", "all"]:
                # Common append patterns
                common_appends = ["123", "!", "2024", "2023", "1"]
                for append in common_appends:
                    results.append(line + append)
            
            if mutation_type in ["prepend", "all"]:
                # Common prepend patterns
                common_prepends = ["!", "123", "2024"]
                for prepend in common_prepends:
                    results.append(prepend + line)
        
        return results
    
    def _save_wordlist(self, lines: List[str], output_file: str) -> Path:
        """Save wordlist to file."""
        if output_file.strip():
            output_path = Path(output_file.strip()).expanduser()
        else:
            output_dir = user_data_dir() / "wordlists" / "generated"
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = output_dir / f"wordlist_{timestamp}.txt"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path
    
    def _is_truthy(self, value: str) -> bool:
        return value.lower() in {"1", "true", "yes", "y", "on"}
