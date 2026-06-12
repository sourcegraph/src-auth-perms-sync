from __future__ import annotations

import unittest

from tests import confusables


class ConfusablesTests(unittest.TestCase):
    def test_ascii_text_has_no_findings(self) -> None:
        self.assertEqual(confusables.findings_in_text("plain - ascii 'text' x 2\n"), [])

    def test_prose_characters_are_not_flagged(self) -> None:
        # Em dash, arrows, box drawing, and check marks look nothing like
        # ASCII; the gate must leave them alone.
        self.assertEqual(confusables.findings_in_text("a \u2014 b \u2192 c \u2713 \u2502"), [])

    def test_en_dash_is_flagged_with_position_and_suggestion(self) -> None:
        findings = confusables.findings_in_text("first line\nan \u2013 here\n")
        self.assertEqual(findings, [(2, 4, "\u2013", "-")])

    def test_invisible_character_suggests_deletion(self) -> None:
        findings = confusables.findings_in_text("zero\u200bwidth")
        self.assertEqual(findings, [(1, 5, "\u200b", "")])

    def test_fullwidth_letters_map_to_ascii(self) -> None:
        self.assertEqual(confusables.suggestion_for("\uff43"), "c")
        self.assertEqual(confusables.suggestion_for("\uff01"), "!")

    def test_cyrillic_lookalike_is_flagged(self) -> None:
        findings = confusables.findings_in_text("p\u0430ssword")
        self.assertEqual(findings, [(1, 2, "\u0430", "a")])


if __name__ == "__main__":
    unittest.main()
