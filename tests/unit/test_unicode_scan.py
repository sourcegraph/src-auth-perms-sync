from __future__ import annotations

import unittest

from tests import unicode_scan


class UnicodeScanTests(unittest.TestCase):
    def test_ascii_text_has_no_findings(self) -> None:
        self.assertEqual(unicode_scan.findings_in_text("plain - ascii 'text' x 2\n"), [])

    def test_non_ascii_characters_are_flagged(self) -> None:
        findings = unicode_scan.findings_in_text("first line\na \u2014 b \u2192 c\n")
        self.assertEqual(findings, [(2, 3, "\u2014"), (2, 7, "\u2192")])

    def test_invisible_character_is_flagged(self) -> None:
        findings = unicode_scan.findings_in_text("zero\u200bwidth")
        self.assertEqual(findings, [(1, 5, "\u200b")])


if __name__ == "__main__":
    unittest.main()
