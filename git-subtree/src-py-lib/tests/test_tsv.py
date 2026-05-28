"""Tests for aligned TSV writing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import src_py_lib as src
from src_py_lib.utils.tsv import display_width, format_tsv_value, pad_display


class TSVTest(unittest.TestCase):
    def test_format_tsv_value_sanitizes_and_truncates_non_url_fields(self) -> None:
        self.assertEqual(
            format_tsv_value("hello\rthere\nfriend\tnow", "note"),
            "hello there friend now",
        )
        self.assertEqual(
            format_tsv_value("abcdef", "note", max_column_width=3),
            "abc",
        )
        self.assertEqual(
            format_tsv_value("https://example.test/abcdef", "url", max_column_width=3),
            "https://example.test/abcdef",
        )
        self.assertEqual(
            format_tsv_value("https://example.test/abcdef", "project_url", max_column_width=3),
            "https://example.test/abcdef",
        )

    def test_display_width_handles_wide_and_combining_characters(self) -> None:
        self.assertEqual(display_width("a"), 1)
        self.assertEqual(display_width("測"), 2)
        self.assertEqual(display_width("e\u0301"), 1)
        self.assertEqual(pad_display("測", 4), "測  ")

    def test_write_tsv_creates_aligned_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "nested" / "table.tsv"

            src.write_tsv(
                output_file,
                [
                    {"name": "al", "n": 1},
                    {"name": "bob", "n": 2},
                ],
            )

            self.assertEqual(
                output_file.read_text(encoding="utf-8"),
                "name\tn\nal  \t1\nbob \t2\n",
            )

    def test_write_tsv_writes_empty_file_for_empty_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "table.tsv"

            src.write_tsv(output_file, [])

            self.assertEqual(output_file.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
