"""Module-mode (importable API) guarantees for host applications.

Customers embed `src_auth_perms_sync.Get/Set/...` inside their own services:
failures must surface as falsy result objects (never exceptions or process
exits), the host's stdlib logging configuration must stay untouched, and
structured events must reach a caller-supplied sink.
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

import src_py_lib as src

import src_auth_perms_sync
from src_auth_perms_sync import cli


def make_config(**updates: object) -> cli.Config:
    base_config = cli.Config(
        src_endpoint="https://invalid.invalid",
        src_access_token="dummy",
        max_attempts=1,
        http_timeout_seconds=1.0,
        parallelism=1,
        sample_interval=0.0,
    )
    return base_config.model_copy(update=updates)


class ModuleApiTests(unittest.TestCase):
    """Every test runs in a throwaway cwd: module runs default their
    artifacts directory to `<cwd>/src-auth-perms-sync-runs`."""

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.working_directory = Path(self._temporary_directory.name)
        self._previous_working_directory = Path.cwd()
        os.chdir(self.working_directory)
        # Silence the lastResort stderr printout for the expected
        # "run failed" log without touching the root logger.
        self._null_handler = logging.NullHandler()
        logging.getLogger("src_auth_perms_sync").addHandler(self._null_handler)

    def tearDown(self) -> None:
        logging.getLogger("src_auth_perms_sync").removeHandler(self._null_handler)
        os.chdir(self._previous_working_directory)
        self._temporary_directory.cleanup()

    def test_get_with_unreachable_endpoint_returns_falsy_without_raising(self) -> None:
        root_logger = logging.getLogger()
        handlers_before = list(root_logger.handlers)
        level_before = root_logger.level

        result = src_auth_perms_sync.Get(make_config())

        self.assertIsInstance(result, cli.GetResult)
        self.assertFalse(result)
        self.assertFalse(result.succeeded)
        self.assertEqual(handlers_before, list(root_logger.handlers))
        self.assertEqual(level_before, root_logger.level)

    def test_get_result_and_command_result_truthiness_mirror_succeeded(self) -> None:
        self.assertTrue(bool(cli.GetResult(succeeded=True)))
        self.assertFalse(bool(cli.GetResult(succeeded=False)))
        self.assertTrue(bool(cli.CommandResult(succeeded=True)))
        self.assertFalse(bool(cli.CommandResult(succeeded=False)))

    def test_set_with_no_files_apply_without_no_backup_returns_falsy(self) -> None:
        config = make_config(no_files=True, apply=True, no_backup=False, full=True)

        with contextlib.redirect_stderr(io.StringIO()) as captured_stderr:
            result = src_auth_perms_sync.Set(config)

        self.assertIsInstance(result, cli.CommandResult)
        self.assertFalse(result)
        self.assertIn(
            "--no-files with --apply also requires --no-backup",
            captured_stderr.getvalue(),
        )
        # Validation fails before any path resolution, so nothing is created.
        self.assertEqual([], list(self.working_directory.iterdir()))

    def test_event_sink_receives_run_start_and_error_end_events(self) -> None:
        sink = src.InMemoryEventSink()
        config = make_config(no_files=True)

        result = src_auth_perms_sync.Get(config, event_sink=sink)

        self.assertFalse(result)
        # --no-files: the failed run still left the host filesystem untouched.
        self.assertEqual([], list(self.working_directory.iterdir()))

        run_events = [event for event in sink.events if event.get("event_name") == "run"]
        phases = [self.event_attributes(event).get("phase") for event in run_events]
        self.assertIn("start", phases)
        self.assertIn("end", phases)
        run_end_attributes = self.event_attributes(
            next(
                event for event in run_events if self.event_attributes(event).get("phase") == "end"
            )
        )
        self.assertEqual("error", run_end_attributes.get("status"))

    def event_attributes(self, event: dict[str, Any]) -> dict[str, Any]:
        attributes = event.get("attributes")
        self.assertIsInstance(attributes, dict)
        return cast("dict[str, Any]", attributes)


if __name__ == "__main__":
    unittest.main()
