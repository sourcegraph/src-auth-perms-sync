from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from src_auth_perms_sync.permissions import maps


class MapsTests(unittest.TestCase):
    def test_create_maps_yaml_if_missing_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            maps_path = Path(directory_name) / "nested" / "maps.yaml"

            self.assertTrue(maps.create_maps_yaml_if_missing(maps_path))
            created_content = maps_path.read_text()
            self.assertIn("maps:", created_content)
            maps_path.write_text("maps: []\n")

            self.assertFalse(maps.create_maps_yaml_if_missing(maps_path))
            self.assertEqual("maps: []\n", maps_path.read_text())

    def test_default_maps_yaml_is_valid_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            maps_path = Path(directory_name) / "maps.yaml"

            maps.create_maps_yaml_if_missing(maps_path)

            self.assertEqual({"maps": [{"name": "Map 1"}]}, yaml.safe_load(maps_path.read_text()))

    def test_count_users_per_provider_counts_each_user_once_per_provider(self) -> None:
        users = [
            {
                "id": "user-1",
                "username": "alice",
                "builtinAuth": True,
                "externalAccounts": {
                    "nodes": [
                        {
                            "serviceType": "saml",
                            "serviceID": "https://idp.example.com",
                            "clientID": "sourcegraph",
                        },
                        {
                            "serviceType": "saml",
                            "serviceID": "https://idp.example.com",
                            "clientID": "sourcegraph",
                        },
                    ]
                },
            },
            {
                "id": "user-2",
                "username": "bob",
                "builtinAuth": False,
                "externalAccounts": {
                    "nodes": [
                        {
                            "serviceType": "github",
                            "serviceID": "https://github.com/",
                            "clientID": "github-client",
                        }
                    ]
                },
            },
        ]

        counts = maps.count_users_per_provider(users)

        self.assertEqual(1, counts[maps.BUILTIN_PROVIDER_KEY])
        self.assertEqual(1, counts[("saml", "https://idp.example.com", "sourcegraph")])
        self.assertEqual(1, counts[("github", "https://github.com/", "github-client")])
