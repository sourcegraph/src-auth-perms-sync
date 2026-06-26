"""Assert every tests.yaml case that runs locally, and validate the registry.

Live and performance execution happens in tests/run.py; here, all local-mode
cases run without any network - state cases against an in-memory instance,
replay cases through the real argument parser - and every registry entry is
structurally validated, including the live/performance ones.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import cast

import yaml

from src_auth_perms_sync import cli
from src_auth_perms_sync.permissions import types as permission_types
from src_auth_perms_sync.permissions.workflow import load_mapping_rules
from tests.e2e.case_runner import (
    FIXTURES_DIR,
    case_cli_arguments,
    case_modes,
    case_runners,
    is_replay_case,
    load_e2e_cases,
    required_case_files,
    run_fixture_case,
    run_local_replay_case,
)


class LocalCaseTests(unittest.TestCase):
    maxDiff = None

    def test_registry_matches_fixture_directories(self) -> None:
        """Every fixture directory must be registered; directories are optional."""
        case_names = set(load_e2e_cases())
        directory_names = {path.name for path in FIXTURES_DIR.iterdir() if path.is_dir()}
        unregistered = directory_names - case_names
        self.assertFalse(
            unregistered,
            f"fixture directories without a tests.yaml entry: {sorted(unregistered)}",
        )

    def test_registry_cases_are_runnable(self) -> None:
        """Every case declares a runner, known modes, and the files it needs."""
        known_field_names = set(cli.Config.model_fields)
        for case_name, case in load_e2e_cases().items():
            with self.subTest(case=case_name):
                self.assertTrue(case_runners(case), "case needs args or a cliCommand")
                self.assertFalse(
                    "args" in case and "cliCommand" in case,
                    "declare args (state case) OR cliCommand (replay case), not both",
                )
                self.assertTrue(
                    set(case_modes(case)) <= {"local", "live", "performance"},
                    f"unknown mode in {case_modes(case)}",
                )
                for file_name in sorted(required_case_files(case)):
                    path = FIXTURES_DIR / case_name / file_name
                    self.assertTrue(path.is_file(), f"case requires {path}")
                args = case.get("args", {})
                if args:
                    self.assertIn("command", args, "args needs a command key")
                    unknown_fields = set(args) - {"command"} - known_field_names
                    self.assertFalse(
                        unknown_fields, f"args keys are not Config fields: {unknown_fields}"
                    )
                argv = (
                    case_cli_arguments(case, case_name)
                    if ("args" in case or case.get("cliCommand"))
                    else []
                )
                for placeholder, meaning in (
                    ("{user}", "the live --user"),
                    ("{today}", "the run date (UTC)"),
                ):
                    if any(placeholder in token for token in argv):
                        self.assertNotIn(
                            "local",
                            case_modes(case),
                            f"{placeholder} resolves to {meaning}; local mode cannot use it",
                        )
                if argv[:1] == ["restore"] and {"live", "performance"} & set(case_modes(case)):
                    self.assertNotIn(
                        "--apply",
                        argv,
                        "instance-mode registry cases must not run a bare restore --apply; "
                        "live restores are managed by the seeded set-apply cycle "
                        "(local-only cases may restore --apply against the fake)",
                    )

    def test_local_replay_cases(self) -> None:
        """Replay-style cases assert parser exit codes and output substrings."""
        for case_name, case in load_e2e_cases().items():
            if "local" not in case_modes(case) or not is_replay_case(case):
                continue
            with self.subTest(case=case_name):
                self.assertEqual("", run_local_replay_case(case_name))

    def test_in_memory_mapping_rules_match_maps_file(self) -> None:
        """In-memory rules must drive set exactly like the same rules from YAML.

        The same fixture case runs through the import API three ways: from
        its maps.yaml file, from the equivalent parsed rules in memory (no
        maps file passed at all), and from in-memory rules with no_files.
        All three must plan identical mutations and end in identical
        instance state. The files-enabled in-memory run must write the
        rules it actually used into the run directory as the audit copy,
        and the no_files run must write nothing.
        """
        for case_name in ("full-overwrite-dry-run", "full-overwrite-unions"):
            with self.subTest(case=case_name):
                mapping_rules = load_mapping_rules(FIXTURES_DIR / case_name / "maps.yaml")
                self.assertTrue(mapping_rules, "fixture case must define mapping rules")

                from_file = run_fixture_case(case_name, "import")
                from_memory = run_fixture_case(case_name, "import", mapping_rules=mapping_rules)
                from_memory_no_files = run_fixture_case(
                    case_name,
                    "import",
                    mapping_rules=mapping_rules,
                    no_files=True,
                )

                self.assertIsNone(from_file.failure)
                self.assertIsNone(from_memory.failure)
                self.assertIsNone(from_memory_no_files.failure)
                self.assertEqual(from_file.actual_mutations, from_memory.actual_mutations)
                self.assertEqual(from_file.actual_state, from_memory.actual_state)
                self.assertEqual(from_file.actual_mutations, from_memory_no_files.actual_mutations)
                self.assertEqual(from_file.actual_state, from_memory_no_files.actual_state)

                audit_copies = [
                    name for name in from_memory.artifact_file_names if name.endswith("maps.yaml")
                ]
                self.assertTrue(
                    audit_copies,
                    "in-memory run with files enabled must write the rules audit copy",
                )
                self.assertEqual(
                    (),
                    from_memory_no_files.artifact_file_names,
                    "in-memory run with no_files must write nothing",
                )

    def test_in_memory_mapping_rules_audit_copy_contains_rules_used(self) -> None:
        """The audit maps.yaml must contain exactly the in-memory rules used."""
        case_name = "full-overwrite-dry-run"
        mapping_rules = load_mapping_rules(FIXTURES_DIR / case_name / "maps.yaml")

        with tempfile.TemporaryDirectory(prefix="rules-audit-") as temp_directory:
            audit_directory = Path(temp_directory)
            result = run_fixture_case(
                case_name,
                "import",
                mapping_rules=mapping_rules,
                preserve_artifacts_into=audit_directory,
            )
            self.assertIsNone(result.failure)
            audit_copies = sorted(audit_directory.rglob("maps.yaml"))
            self.assertEqual(1, len(audit_copies), "expected exactly one rules audit copy")
            audit_content = yaml.safe_load(audit_copies[0].read_text())
            self.assertEqual({"maps": mapping_rules}, audit_content)

    def test_in_memory_mapping_rules_reject_invalid_structure(self) -> None:
        """Structurally invalid in-memory rules fail fast, before any mutation."""
        case_name = "full-overwrite-unions"
        invalid_rules = [{"name": "Broken", "users": {"unknownField": ["x"]}}]
        result = run_fixture_case(
            case_name,
            "import",
            mapping_rules=cast("list[permission_types.MappingRule]", invalid_rules),
        )
        self.assertIsNotNone(result.failure)
        self.assertEqual(0, result.actual_mutations, "invalid rules must mutate nothing")

    def test_no_files_set_dry_run_matches_files_enabled(self) -> None:
        """no_files must not change a set dry-run's decisions, and writes nothing.

        The same fixture case runs twice through the import API - once with
        files enabled and once with no_files - and must plan identical
        mutations and end in identical instance state, while the no_files
        run's temporary artifacts directory stays completely empty.
        """
        case_name = "full-overwrite-dry-run"
        with_files = run_fixture_case(case_name, "import")
        without_files = run_fixture_case(case_name, "import", no_files=True)
        self.assertIsNone(with_files.failure)
        self.assertIsNone(without_files.failure)
        self.assertEqual(with_files.actual_mutations, without_files.actual_mutations)
        self.assertEqual(with_files.actual_state, without_files.actual_state)
        self.assertTrue(
            with_files.artifact_file_names,
            "the files-enabled run should write run artifacts (maps copy / snapshots)",
        )
        self.assertEqual(
            (),
            without_files.artifact_file_names,
            "no_files run must leave its artifacts directory empty",
        )

    def test_local_state_cases(self) -> None:
        for case_name, case in load_e2e_cases().items():
            if "local" not in case_modes(case) or is_replay_case(case):
                continue
            for runner in case_runners(case):
                with self.subTest(case=case_name, runner=runner):
                    result = run_fixture_case(case_name, runner)
                    if not result.expected_errors:
                        self.assertIsNone(result.command_failure)
                        self.assertEqual(result.expected_state, result.actual_state)
                    self.assertIsNone(result.failure)


if __name__ == "__main__":
    unittest.main(verbosity=2)
