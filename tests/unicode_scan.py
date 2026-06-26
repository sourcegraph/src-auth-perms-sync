#!/usr/bin/env python3
"""Fail on non-ASCII characters in tracked text files.

Usage: uv run python tests/unicode_scan.py
Exit code 1 when any Unicode character outside ASCII is found.
"""

from __future__ import annotations

import subprocess
import sys
import unicodedata
from pathlib import Path


def findings_in_text(text: str) -> list[tuple[int, int, str]]:
    """Return (line, column, character) findings, 1-based."""
    findings: list[tuple[int, int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for column_number, character in enumerate(line, start=1):
            if not character.isascii():
                findings.append((line_number, column_number, character))
    return findings


def tracked_files(root: Path) -> list[Path]:
    """Return tracked files the gate should scan."""
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
        cwd=root,
    )
    return [root / name for name in listing.stdout.split("\0") if name]


def describe(character: str) -> str:
    name = unicodedata.name(character, f"U+{ord(character):04X}")
    return f"`{character}` ({name}, U+{ord(character):04X})"


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    finding_count = 0
    for path in tracked_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or vanished files are not lintable text
        for line_number, column_number, character in findings_in_text(text):
            print(
                f"{path.relative_to(root)}:{line_number}:{column_number} "
                f"non-ASCII character {describe(character)}"
            )
            finding_count += 1
    if finding_count:
        print(f"\nFound {finding_count} non-ASCII character(s).")
        return 1
    print("No non-ASCII characters found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
