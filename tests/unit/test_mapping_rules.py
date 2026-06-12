"""In-memory mapping rules: resolution, validation, and audit serialization.

Module callers can pass parsed mapping rules to `Set` instead of a maps
YAML file. These tests pin the contract: in-memory rules go through the
same structural validation as file-loaded rules, the maps file is ignored
when rules are provided, and the audit serializer round-trips losslessly.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import cast

import yaml

from src_auth_perms_sync.permissions import maps as permissions_maps
from src_auth_perms_sync.permissions import types as permission_types
from src_auth_perms_sync.permissions.workflow import (
    load_mapping_rules,
    resolve_mapping_rules,
)

VALID_RULES: list[permission_types.MappingRule] = [
    {
        "name": "Engineering",
        "users": {"usernameRegexes": ["^eng-.*$"]},
        "repos": {"nameRegexes": ["^github\\.example\\.com/eng/.*$"]},
    },
    {
        "name": "Auditors get the ledger repos",
        "users": {"emails": ["auditor@example.com"]},
        "repos": {"names": ["github.example.com/finance/ledger"]},
    },
]


def write_maps_yaml(path: Path, rules: list[permission_types.MappingRule]) -> None:
    path.write_text(yaml.safe_dump({"maps": rules}))


class ResolveMappingRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.maps_path = Path(self._temporary_directory.name) / "maps.yaml"

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def test_none_loads_rules_from_the_maps_file(self) -> None:
        write_maps_yaml(self.maps_path, VALID_RULES)
        self.assertEqual(VALID_RULES, resolve_mapping_rules(None, self.maps_path))

    def test_provided_rules_are_returned_and_the_maps_file_is_ignored(self) -> None:
        decoy_rules: list[permission_types.MappingRule] = [
            {
                "name": "Decoy that must not be used",
                "users": {"usernameRegexes": [".*"]},
                "repos": {"nameRegexes": [".*"]},
            }
        ]
        write_maps_yaml(self.maps_path, decoy_rules)
        self.assertEqual(VALID_RULES, resolve_mapping_rules(VALID_RULES, self.maps_path))

    def test_provided_rules_work_without_any_maps_file(self) -> None:
        self.assertFalse(self.maps_path.exists())
        self.assertEqual(VALID_RULES, resolve_mapping_rules(VALID_RULES, self.maps_path))

    def test_provided_empty_rules_return_empty_without_reading_the_file(self) -> None:
        self.assertEqual([], resolve_mapping_rules([], self.maps_path))

    def test_provided_rules_get_the_same_structural_validation_as_yaml(self) -> None:
        invalid_rules = [{"name": "Broken", "users": {"unknownField": ["x"]}}]
        with self.assertRaises(SystemExit):
            resolve_mapping_rules(
                cast("list[permission_types.MappingRule]", invalid_rules),
                self.maps_path,
            )

    def test_provided_rules_missing_repos_section_are_rejected(self) -> None:
        invalid_rules = [{"name": "No repos", "users": {"usernames": ["alice"]}}]
        with self.assertRaises(SystemExit):
            resolve_mapping_rules(
                cast("list[permission_types.MappingRule]", invalid_rules),
                self.maps_path,
            )

    def test_provided_non_mapping_entries_are_rejected(self) -> None:
        invalid_rules = ["just a string"]
        with self.assertRaises(SystemExit):
            resolve_mapping_rules(
                cast("list[permission_types.MappingRule]", invalid_rules),
                self.maps_path,
            )


class DumpMappingRulesYamlTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.output_path = Path(self._temporary_directory.name) / "run" / "maps.yaml"

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def test_round_trips_through_the_standard_loader_with_validation(self) -> None:
        permissions_maps.dump_mapping_rules_yaml(self.output_path, VALID_RULES)
        self.assertEqual(VALID_RULES, load_mapping_rules(self.output_path))

    def test_writes_the_maps_top_level_key_and_creates_parent_directories(self) -> None:
        permissions_maps.dump_mapping_rules_yaml(self.output_path, VALID_RULES)
        self.assertEqual({"maps": VALID_RULES}, yaml.safe_load(self.output_path.read_text()))

    def test_empty_rules_serialize_to_an_empty_maps_list(self) -> None:
        permissions_maps.dump_mapping_rules_yaml(self.output_path, [])
        self.assertEqual({"maps": []}, yaml.safe_load(self.output_path.read_text()))
