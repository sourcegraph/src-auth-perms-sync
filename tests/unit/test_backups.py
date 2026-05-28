from __future__ import annotations

import unittest
from pathlib import Path

from src_auth_perms_sync.shared import backups


class BackupPathTests(unittest.TestCase):
    def test_endpoint_directory_name_uses_hostname_and_port(self) -> None:
        self.assertEqual(
            "sourcegraph.example.com",
            backups.endpoint_directory_name("https://Sourcegraph.example.com"),
        )
        self.assertEqual(
            "sourcegraph.example.com-3443",
            backups.endpoint_directory_name("https://sourcegraph.example.com:3443"),
        )

    def test_endpoint_artifacts_directory_uses_current_directory(self) -> None:
        self.assertEqual(
            Path("/tmp/work") / backups.ARTIFACTS_DIR_NAME / "sourcegraph.example.com",
            backups.endpoint_artifacts_directory(
                "https://sourcegraph.example.com", Path("/tmp/work")
            ),
        )

    def test_endpoint_artifact_path_scopes_relative_paths(self) -> None:
        self.assertEqual(
            Path.cwd() / backups.ARTIFACTS_DIR_NAME / "sourcegraph.example.com" / "maps.yaml",
            backups.endpoint_artifact_path("https://sourcegraph.example.com", Path("maps.yaml")),
        )
        self.assertEqual(
            Path("/tmp/maps.yaml"),
            backups.endpoint_artifact_path(
                "https://sourcegraph.example.com", Path("/tmp/maps.yaml")
            ),
        )

    def test_backup_path_uses_safe_endpoint_source_command_and_state(self) -> None:
        self.assertEqual(
            Path.cwd()
            / backups.ARTIFACTS_DIR_NAME
            / "sourcegraph.example.com"
            / backups.RUNS_DIR_NAME
            / "2026-05-23-set_user"
            / "before.json",
            backups.backup_path(
                "repo/1",
                "2026-05-23",
                "https://sourcegraph.example.com",
                "set:user",
                "before",
            ),
        )

    def test_backup_path_copies_source_file_with_original_name(self) -> None:
        self.assertEqual(
            Path.cwd()
            / backups.ARTIFACTS_DIR_NAME
            / "sourcegraph.example.com"
            / backups.RUNS_DIR_NAME
            / "2026-05-23-get"
            / "maps.yaml",
            backups.backup_path(
                "maps.yaml",
                "2026-05-23",
                "https://sourcegraph.example.com",
                "get",
                suffix="yaml",
            ),
        )

    def test_backup_path_uses_current_run_artifacts_context(self) -> None:
        run_directory = backups.artifact_run_directory(
            "2026-05-23",
            "https://sourcegraph.example.com",
            "get",
        )

        with backups.run_artifacts_context(run_directory, "2026-05-23"):
            self.assertEqual(
                run_directory / "before.json",
                backups.backup_path(
                    "ignored.yaml",
                    "unused-timestamp",
                    "https://unused.example.com",
                    "unused-command",
                    "before",
                ),
            )

    def test_safe_filename_part_falls_back_for_empty_values(self) -> None:
        self.assertEqual("unknown", backups.safe_filename_part("///"))
        self.assertEqual("a_b-c.d", backups.safe_filename_part("a/b-c.d"))
