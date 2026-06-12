#!/usr/bin/env python3
"""Fail on confusable Unicode characters in non-Python tracked files.

Ruff's RUF001-RUF003 rules catch confusable characters (en dash for
hyphen, multiplication sign for x, Cyrillic lookalike letters, ...) in
Python strings, comments, and docstrings. This script applies the same
policy to every other tracked text file: Markdown, YAML, TOML, and
GitHub Actions workflows.

The character set below mirrors ruff's curated subset of the Unicode
confusables list (UTS #39): characters that render like ASCII and sneak
in through copy-paste. Intentional prose characters that look nothing
like ASCII (em dash, arrows, box drawing, check marks) are NOT flagged.

Usage: uv run python tests/confusables.py
Exit code 1 when any confusable character is found.
"""

from __future__ import annotations

import subprocess
import sys
import unicodedata
from pathlib import Path

# char -> suggested ASCII replacement. Grouped by accident type.
CONFUSABLE_SUGGESTIONS: dict[str, str] = {
    # Quotes and apostrophes
    "\u2018": "'",  # left single quotation mark
    "\u2019": "'",  # right single quotation mark
    "\u201a": ",",  # single low-9 quotation mark
    "\u201b": "'",  # single high-reversed-9 quotation mark
    "\u201c": '"',  # left double quotation mark
    "\u201d": '"',  # right double quotation mark
    "\u201e": '"',  # double low-9 quotation mark
    "\u2032": "'",  # prime
    "\u2033": '"',  # double prime
    "\u00b4": "'",  # acute accent
    "\u02b9": "'",  # modifier letter prime
    "\u02bb": "'",  # modifier letter turned comma
    "\u02bc": "'",  # modifier letter apostrophe
    "\u02c8": "'",  # modifier letter vertical line
    # Dashes and minus signs (em dash is NOT confusable; it stays legal)
    "\u2010": "-",  # hyphen
    "\u2011": "-",  # non-breaking hyphen
    "\u2012": "-",  # figure dash
    "\u2013": "-",  # en dash
    "\u2212": "-",  # minus sign
    # Other punctuation and symbols
    "\u00d7": "x",  # multiplication sign
    "\u2044": "/",  # fraction slash
    "\u2215": "/",  # division slash
    "\u037e": ";",  # greek question mark
    "\u0387": ":",  # greek ano teleia
    "\u2236": ":",  # ratio
    "\u201f": '"',  # double high-reversed-9 quotation mark
    "\u02d0": ":",  # modifier letter triangular colon
    "\u0589": ":",  # armenian full stop
    "\u06d4": ".",  # arabic full stop
    "\u2024": ".",  # one dot leader
    "\u22c5": "*",  # dot operator
    "\u2219": "*",  # bullet operator
    # Spaces that render like a plain space
    "\u00a0": " ",  # no-break space
    "\u2000": " ",  # en quad
    "\u2001": " ",  # em quad
    "\u2002": " ",  # en space
    "\u2003": " ",  # em space
    "\u2004": " ",  # three-per-em space
    "\u2005": " ",  # four-per-em space
    "\u2006": " ",  # six-per-em space
    "\u2007": " ",  # figure space
    "\u2008": " ",  # punctuation space
    "\u2009": " ",  # thin space
    "\u200a": " ",  # hair space
    "\u202f": " ",  # narrow no-break space
    "\u205f": " ",  # medium mathematical space
    "\u3000": " ",  # ideographic space
    # Invisible characters: suggest deleting them
    "\u00ad": "",  # soft hyphen
    "\u061c": "",  # arabic letter mark
    "\u200b": "",  # zero width space
    "\u200c": "",  # zero width non-joiner
    "\u200d": "",  # zero width joiner
    "\u200e": "",  # left-to-right mark
    "\u200f": "",  # right-to-left mark
    "\u2028": "",  # line separator
    "\u2029": "",  # paragraph separator
    "\u202a": "",  # left-to-right embedding
    "\u202b": "",  # right-to-left embedding
    "\u202c": "",  # pop directional formatting
    "\u202d": "",  # left-to-right override
    "\u202e": "",  # right-to-left override (Trojan Source attacks)
    "\u2060": "",  # word joiner
    "\u2061": "",  # function application
    "\ufeff": "",  # zero width no-break space / BOM
    # Cyrillic letters that render like Latin
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0455": "s",
    "\u0456": "i",
    "\u0458": "j",
    "\u0410": "A",
    "\u0412": "B",
    "\u0415": "E",
    "\u041a": "K",
    "\u041c": "M",
    "\u041d": "H",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0422": "T",
    "\u0425": "X",
    "\u0405": "S",
    "\u0406": "I",
    "\u0408": "J",
    # Greek letters that render like Latin
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0396": "Z",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
    "\u03bf": "o",
    "\u03c5": "u",
}

# Fullwidth ASCII variants (U+FF01..U+FF5E) map to ASCII by fixed offset.
FULLWIDTH_FIRST = 0xFF01
FULLWIDTH_LAST = 0xFF5E
FULLWIDTH_TO_ASCII_OFFSET = 0xFEE0

# Ruff (RUF001-RUF003 with PLC2401/PLC2403 available) owns Python files.
RUFF_OWNED_SUFFIXES = {".py"}


def suggestion_for(character: str) -> str | None:
    """Return the ASCII replacement for a confusable character, else None."""
    known = CONFUSABLE_SUGGESTIONS.get(character)
    if known is not None:
        return known
    if FULLWIDTH_FIRST <= ord(character) <= FULLWIDTH_LAST:
        return chr(ord(character) - FULLWIDTH_TO_ASCII_OFFSET)
    return None


def findings_in_text(text: str) -> list[tuple[int, int, str, str]]:
    """Return (line, column, character, suggestion) findings, 1-based."""
    findings: list[tuple[int, int, str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for column_number, character in enumerate(line, start=1):
            suggestion = suggestion_for(character)
            if suggestion is not None:
                findings.append((line_number, column_number, character, suggestion))
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
    return [
        root / name
        for name in listing.stdout.split("\0")
        if name and Path(name).suffix not in RUFF_OWNED_SUFFIXES
    ]


def describe(character: str) -> str:
    name = unicodedata.name(character, f"U+{ord(character):04X}")
    return f"`{character}` ({name})"


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    finding_count = 0
    for path in tracked_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary or vanished files are not lintable text
        for line_number, column_number, character, suggestion in findings_in_text(text):
            replacement = f"`{suggestion}`" if suggestion else "deleting it"
            print(
                f"{path.relative_to(root)}:{line_number}:{column_number} "
                f"confusable {describe(character)} - did you mean {replacement}?"
            )
            finding_count += 1
    if finding_count:
        print(f"\nFound {finding_count} confusable character(s).")
        return 1
    print("No confusable characters found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
