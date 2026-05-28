from __future__ import annotations

import unittest

from auth_perms_sync.shared import id_codec


class IdCodecTests(unittest.TestCase):
    def test_external_service_id_decodes(self) -> None:
        self.assertEqual(42, id_codec.decode_external_service_id("RXh0ZXJuYWxTZXJ2aWNlOjQy"))

    def test_repository_id_round_trips(self) -> None:
        self.assertEqual("UmVwb3NpdG9yeTo5OQ==", id_codec.encode_repository_id(99))
        self.assertEqual(99, id_codec.decode_repository_id("UmVwb3NpdG9yeTo5OQ=="))

    def test_decode_rejects_invalid_base64(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a valid base64"):
            id_codec.decode_repository_id("not base64")

    def test_decode_rejects_wrong_node_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a Repository Node ID"):
            id_codec.decode_repository_id("RXh0ZXJuYWxTZXJ2aWNlOjQy")

    def test_decode_rejects_non_integer_suffix(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-integer suffix"):
            id_codec.decode_external_service_id("RXh0ZXJuYWxTZXJ2aWNlOmFiYw==")
