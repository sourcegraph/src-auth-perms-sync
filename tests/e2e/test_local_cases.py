"""Assert every tests.yaml case that runs locally, and validate the registry.

Live and performance execution happens in tests/run.py; here, all local-mode
cases run without any network — state cases against an in-memory instance,
replay cases through the real argument parser — and every registry entry is
structurally validated, including the live/performance ones.
"""

from __future__ import annotations

import shlex
import unittest

from tests.e2e.case_runner import (
    FIXTURES_DIR,
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
        for case_name, case in load_e2e_cases().items():
            with self.subTest(case=case_name):
                self.assertTrue(case_runners(case), "case needs cliCommand or importConfig")
                self.assertTrue(
                    set(case_modes(case)) <= {"local", "live", "performance"},
                    f"unknown mode in {case_modes(case)}",
                )
                for file_name in sorted(required_case_files(case)):
                    path = FIXTURES_DIR / case_name / file_name
                    self.assertTrue(path.is_file(), f"case requires {path}")
                cli_command = case.get("cliCommand", "")
                if "{user}" in cli_command:
                    self.assertNotIn(
                        "local",
                        case_modes(case),
                        "{user} resolves to the live --user; local mode cannot use it",
                    )
                argv = shlex.split(cli_command)
                if argv[:1] == ["restore"]:
                    self.assertNotIn(
                        "--apply",
                        argv,
                        "registry cases must not run a bare restore --apply; restores "
                        "are managed by the seeded set-apply cycle",
                    )

    def test_local_replay_cases(self) -> None:
        """Replay-style cases assert parser exit codes and output substrings."""
        for case_name, case in load_e2e_cases().items():
            if "local" not in case_modes(case) or not is_replay_case(case):
                continue
            with self.subTest(case=case_name):
                self.assertEqual("", run_local_replay_case(case_name))

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
