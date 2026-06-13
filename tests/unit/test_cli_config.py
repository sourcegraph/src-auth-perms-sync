from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest import mock

import src_py_lib as src
from src_py_lib.utils import config as shared_config

import src_auth_perms_sync
from src_auth_perms_sync import cli
from src_auth_perms_sync.permissions import command as permissions_command
from src_auth_perms_sync.permissions import types as permission_types
from src_auth_perms_sync.shared import backups


def make_config(**updates: object) -> cli.Config:
    base_config = cli.Config(
        src_endpoint="https://sourcegraph.example.com",
        src_access_token="secret",
    )
    return base_config.model_copy(update=updates)


def load_config_from_env(**env: str) -> cli.Config:
    return shared_config.load_config(
        cli.Config,
        env_file=None,
        env={
            "SRC_ENDPOINT": "https://sourcegraph.example.com",
            "SRC_ACCESS_TOKEN": "secret",
            **env,
        },
        resolve_op_refs=False,
    )


def make_run_paths() -> backups.RunPaths:
    return backups.RunPaths(
        timestamp="2026-06-12-00-00-00",
        artifacts_dir=Path("artifacts"),
        endpoint_directory=Path("artifacts/sourcegraph.example.com"),
        maps_path=Path("maps.yaml"),
        code_hosts_path=Path("code-hosts.yaml"),
        auth_providers_path=Path("auth-providers.yaml"),
        run_directory=Path("artifacts/sourcegraph.example.com/runs/run"),
    )


class CliConfigTests(unittest.TestCase):
    def test_resolve_command_uses_explicit_command_name(self) -> None:
        command = cli.resolve_command("get", make_config())

        self.assertEqual("get", command.name)
        self.assertEqual("get", command.log_name)
        self.assertEqual("get", command.artifact_name)
        self.assertEqual(
            "set",
            cli.resolve_command("set", make_config(maps_path=Path("maps.yaml"), full=True)).name,
        )
        self.assertEqual(
            "restore",
            cli.resolve_command("restore", make_config(restore_path=Path("snapshot.json"))).name,
        )
        self.assertEqual(
            "sync_saml_orgs",
            cli.resolve_command("sync_saml_orgs", make_config()).name,
        )

    def test_maps_path_does_not_select_set_command(self) -> None:
        command = cli.resolve_command("get", make_config(maps_path=Path("custom-maps.yaml")))

        self.assertEqual("get", command.name)

    def test_load_cli_returns_command_and_config_options(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                os.environ,
                {
                    "SRC_ENDPOINT": "https://sourcegraph.example.com",
                    "SRC_ACCESS_TOKEN": "secret",
                },
                clear=True,
            ),
        ):
            env_file = Path(directory) / ".env"
            env_file.write_text("")
            cli_input = cli.load_cli(
                [
                    "set",
                    "--env-file",
                    str(env_file),
                    "--maps-path",
                    "custom-maps.yaml",
                    "--users",
                    "alice,bob@example.com",
                ]
            )

        self.assertEqual("set", cli_input.command_name)
        self.assertEqual(Path("custom-maps.yaml"), cli_input.config.maps_path)
        self.assertEqual(("alice", "bob@example.com"), cli_input.config.users)

    def test_maps_path_is_none_until_defaulted_for_an_endpoint(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                os.environ,
                {
                    "SRC_ENDPOINT": "https://sourcegraph.example.com",
                    "SRC_ACCESS_TOKEN": "secret",
                },
                clear=True,
            ),
        ):
            env_file = Path(directory) / ".env"
            env_file.write_text("")
            cli_input = cli.load_cli(["set", "--env-file", str(env_file), "--full"])

        self.assertEqual("set", cli_input.command_name)
        self.assertIsNone(cli_input.config.maps_path)

    def test_load_cli_rejects_singular_user_option(self) -> None:
        captured_stderr = io.StringIO()

        with (
            contextlib.redirect_stderr(captured_stderr),
            self.assertRaises(SystemExit) as exit_context,
        ):
            cli.load_cli(["get", "--user", "alice"])

        self.assertEqual(2, exit_context.exception.code)
        self.assertIn("unrecognized arguments: --user alice", captured_stderr.getvalue())

    def test_restore_path_config_loads_without_selecting_a_command(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_RESTORE_PATH="snapshot.json")

        self.assertEqual(Path.cwd() / "snapshot.json", config.restore_path)

    def test_load_cli_rejects_missing_restore_snapshot_file(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                os.environ,
                {
                    "SRC_ENDPOINT": "https://sourcegraph.example.com",
                    "SRC_ACCESS_TOKEN": "secret",
                },
                clear=True,
            ),
        ):
            env_file = Path(directory) / ".env"
            env_file.write_text("")
            missing_snapshot = Path(directory) / "missing-before.json"

            with self.assertRaises(SystemExit) as exit_context:
                cli.load_cli(
                    [
                        "restore",
                        "--env-file",
                        str(env_file),
                        "--restore-path",
                        str(missing_snapshot),
                    ]
                )

        self.assertIn("restore snapshot file does not exist", str(exit_context.exception))

    def test_users_config_loads_comma_delimited_values(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_USERS="alice, bob@example.com,,carol")

        self.assertEqual(("alice", "bob@example.com", "carol"), config.users)

    def test_repos_config_loads_comma_delimited_values(self) -> None:
        config = load_config_from_env(
            SRC_AUTH_PERMS_SYNC_REPOS="github.com/sourcegraph/one, github.com/sourcegraph/two"
        )

        self.assertEqual(
            ("github.com/sourcegraph/one", "github.com/sourcegraph/two"),
            config.repos,
        )

    def test_set_command_options_match_each_incremental_mode(self) -> None:
        self.assertEqual(
            "full",
            cli.set_command_options(make_config(maps_path=Path("maps.yaml"), full=True)).mode,
        )
        self.assertEqual(
            ("users", ("alice", "bob@example.com")),
            (
                cli.set_command_options(
                    make_config(maps_path=Path("maps.yaml"), users=("alice", "bob@example.com"))
                ).mode,
                cli.set_command_options(
                    make_config(maps_path=Path("maps.yaml"), users=("alice", "bob@example.com"))
                ).user_identifiers,
            ),
        )
        users_without_permissions = cli.set_command_options(
            make_config(
                maps_path=Path("maps.yaml"),
                users_without_explicit_perms=True,
                created_after="2026-01-01",
            )
        )
        self.assertEqual("users_without_explicit_perms", users_without_permissions.mode)
        self.assertEqual("2026-01-01", users_without_permissions.user_created_after)
        created_after = cli.set_command_options(
            make_config(maps_path=Path("maps.yaml"), created_after="2026-01-01")
        )
        self.assertEqual("created_after", created_after.mode)
        self.assertEqual("2026-01-01", created_after.user_created_after)
        repos = cli.set_command_options(
            make_config(
                maps_path=Path("maps.yaml"),
                repos=("github.com/sourcegraph/one",),
            )
        )
        self.assertEqual("repos", repos.mode)
        self.assertEqual(("github.com/sourcegraph/one",), repos.repository_names)
        repos_without_permissions = cli.set_command_options(
            make_config(maps_path=Path("maps.yaml"), repos_without_explicit_perms=True)
        )
        self.assertEqual("repos_without_explicit_perms", repos_without_permissions.mode)
        repos_created_after = cli.set_command_options(
            make_config(maps_path=Path("maps.yaml"), repos_created_after="2026-01-01")
        )
        self.assertEqual("repos_created_after", repos_created_after.mode)
        self.assertEqual("2026-01-01", repos_created_after.repository_created_after)

    def test_resolve_command_includes_set_mode_names(self) -> None:
        users_command = cli.resolve_command(
            "set",
            make_config(maps_path=Path("maps.yaml"), users=("alice",), apply=True),
        )
        full_command = cli.resolve_command(
            "set",
            make_config(maps_path=Path("maps.yaml"), full=True),
        )
        created_after_command = cli.resolve_command(
            "set",
            make_config(maps_path=Path("maps.yaml"), created_after="2026-01-01"),
        )
        repos_command = cli.resolve_command(
            "set",
            make_config(
                maps_path=Path("maps.yaml"),
                repos=("github.com/sourcegraph/one",),
            ),
        )

        self.assertEqual("set_users", users_command.log_name)
        self.assertEqual("set-add-users-apply", users_command.artifact_name)
        self.assertEqual("users", users_command.set_mode)
        self.assertEqual("set_full", full_command.log_name)
        self.assertEqual("set-dry-run", full_command.artifact_name)
        self.assertEqual("set_created_after", created_after_command.log_name)
        self.assertEqual(
            "set-add-users-created-after-dry-run",
            created_after_command.artifact_name,
        )
        self.assertEqual("created_after", created_after_command.set_mode)
        self.assertEqual("set_repos", repos_command.log_name)
        self.assertEqual("set-repos-dry-run", repos_command.artifact_name)
        self.assertEqual("repos", repos_command.set_mode)

    def test_resolve_command_includes_combined_set_sync_names(self) -> None:
        set_command = cli.resolve_command(
            "set",
            make_config(
                maps_path=Path("maps.yaml"),
                apply=True,
                sync_saml_orgs=True,
                full=True,
            ),
        )

        self.assertEqual("set", set_command.name)
        self.assertEqual("set_full_sync_saml_orgs", set_command.log_name)
        self.assertEqual("set-sync-saml-orgs-apply", set_command.artifact_name)
        self.assertTrue(set_command.sync_saml_orgs)

    def test_validate_config_allows_sync_saml_orgs_with_set(self) -> None:
        cli.validate_config(
            "set",
            make_config(maps_path=Path("maps.yaml"), sync_saml_orgs=True, full=True),
        )

    def test_validate_config_rejects_sync_saml_orgs_without_set(self) -> None:
        self.assert_config_error(
            "get",
            make_config(sync_saml_orgs=True),
            "can only be combined with set",
        )
        self.assert_config_error(
            "restore",
            make_config(restore_path=Path("snapshot.json"), sync_saml_orgs=True),
            "can only be combined with set",
        )
        self.assert_config_error(
            "sync_saml_orgs",
            make_config(sync_saml_orgs=True),
            "can only be combined with set",
        )

    def test_validate_config_rejects_apply_with_get(self) -> None:
        self.assert_config_error(
            "get",
            make_config(apply=True),
            "--apply cannot be used with the read-only get command",
        )

    def test_validate_config_allows_get_no_backup(self) -> None:
        cli.validate_config("get", make_config(no_backup=True))

    def test_validate_config_rejects_no_files_apply_without_no_backup(self) -> None:
        expected_message = "--no-files with --apply also requires --no-backup"
        self.assert_config_error(
            "set",
            make_config(full=True, no_files=True, apply=True),
            expected_message,
        )
        self.assert_config_error(
            "restore",
            make_config(restore_path=Path("snapshot.json"), no_files=True, apply=True),
            expected_message,
        )

    def test_validate_config_allows_no_files_apply_with_no_backup(self) -> None:
        cli.validate_config(
            "set",
            make_config(full=True, no_files=True, apply=True, no_backup=True),
        )
        cli.validate_config(
            "restore",
            make_config(
                restore_path=Path("snapshot.json"),
                no_files=True,
                apply=True,
                no_backup=True,
            ),
        )

    def test_validate_config_allows_no_files_without_apply(self) -> None:
        cli.validate_config("get", make_config(no_files=True))
        cli.validate_config("set", make_config(full=True, no_files=True))
        cli.validate_config(
            "restore",
            make_config(restore_path=Path("snapshot.json"), no_files=True),
        )
        cli.validate_config("sync_saml_orgs", make_config(full=True, no_files=True))

    def test_validate_config_rejects_maps_path_outside_get_and_set(self) -> None:
        expected_message = "--maps-path requires the get or set command"
        self.assert_config_error(
            "restore",
            make_config(restore_path=Path("snapshot.json"), maps_path=Path("maps.yaml")),
            expected_message,
        )
        self.assert_config_error(
            "sync_saml_orgs",
            make_config(maps_path=Path("maps.yaml")),
            expected_message,
        )

    def test_validate_config_allows_maps_path_with_get_and_set(self) -> None:
        cli.validate_config("get", make_config(maps_path=Path("maps.yaml")))
        cli.validate_config("set", make_config(maps_path=Path("maps.yaml"), full=True))

    def test_artifacts_dir_flag_is_accepted_on_every_command(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                os.environ,
                {
                    "SRC_ENDPOINT": "https://sourcegraph.example.com",
                    "SRC_ACCESS_TOKEN": "secret",
                },
                clear=True,
            ),
        ):
            env_file = Path(directory) / ".env"
            env_file.write_text("")
            snapshot_path = Path(directory) / "before.json"
            snapshot_path.write_text("{}")
            artifacts_dir = Path(directory) / "artifact-output"
            extra_arguments_by_command = {
                "get": [],
                "set": ["--full"],
                "restore": ["--restore-path", str(snapshot_path)],
                "sync-saml-orgs": ["--full"],
            }

            for command_argument, extra_arguments in extra_arguments_by_command.items():
                with self.subTest(command=command_argument):
                    cli_input = cli.load_cli(
                        [
                            command_argument,
                            "--env-file",
                            str(env_file),
                            "--artifacts-dir",
                            str(artifacts_dir),
                            *extra_arguments,
                        ]
                    )
                    self.assertEqual(artifacts_dir, cli_input.config.artifacts_dir)

    def test_get_help_lists_artifact_options(self) -> None:
        captured_stdout = io.StringIO()

        with (
            contextlib.redirect_stdout(captured_stdout),
            self.assertRaises(SystemExit) as exit_context,
        ):
            cli.load_cli(["get", "--help"])

        self.assertEqual(0, exit_context.exception.code)
        help_text = captured_stdout.getvalue()
        self.assertIn("--maps-path", help_text)
        self.assertIn("--artifacts-dir", help_text)
        self.assertIn("--no-files", help_text)

    def test_validate_config_rejects_restore_without_restore_path(self) -> None:
        self.assert_config_error("restore", make_config(), "restore requires --restore-path")

    def test_validate_config_rejects_restore_path_without_restore(self) -> None:
        self.assert_config_error(
            "get",
            make_config(restore_path=Path("snapshot.json")),
            "--restore-path requires the restore command",
        )

    def test_validate_config_rejects_set_modes_without_set(self) -> None:
        self.assert_config_error(
            "get", make_config(full=True), "requires the set or sync-saml-orgs command"
        )

    def test_validate_config_allows_get_user_filters_without_set(self) -> None:
        cli.validate_config("get", make_config(users=("alice", "bob@example.com")))
        cli.validate_config("get", make_config(users_without_explicit_perms=True))
        cli.validate_config("get", make_config(created_after="2026-01-01"))

    def test_validate_config_allows_get_repo_filters_without_set(self) -> None:
        cli.validate_config("get", make_config(repos=("github.com/sourcegraph/one",)))
        cli.validate_config("get", make_config(repos_without_explicit_perms=True))
        cli.validate_config("get", make_config(repos_created_after="2026-01-01"))

    def test_validate_config_rejects_get_user_filter_conflicts(self) -> None:
        self.assert_config_error(
            "get",
            make_config(users=("alice",), users_without_explicit_perms=True),
            "choose only one of --users or --users-without-explicit-perms",
        )

    def test_validate_config_rejects_user_filters_on_non_get_set_commands(self) -> None:
        self.assert_config_error(
            "restore",
            make_config(restore_path=Path("snapshot.json"), users=("alice",)),
            "require get, set, or sync-saml-orgs",
        )

    def test_validate_config_rejects_repo_filter_conflicts(self) -> None:
        self.assert_config_error(
            "get",
            make_config(
                repos=("github.com/sourcegraph/one",),
                repos_without_explicit_perms=True,
            ),
            "choose only one of --repos",
        )
        self.assert_config_error(
            "get",
            make_config(users=("alice",), repos=("github.com/sourcegraph/one",)),
            "choose either user filters or repo filters",
        )

    def test_validate_config_rejects_repo_filters_on_non_get_set_commands(self) -> None:
        self.assert_config_error(
            "restore",
            make_config(
                restore_path=Path("snapshot.json"),
                repos=("github.com/sourcegraph/one",),
            ),
            "require get or set",
        )

    def test_validate_config_rejects_set_without_explicit_mode(self) -> None:
        self.assert_config_error(
            "set",
            make_config(maps_path=Path("maps.yaml")),
            "set requires one of --full",
        )

    def test_validate_config_rejects_sync_saml_orgs_without_explicit_mode(self) -> None:
        self.assert_config_error(
            "sync_saml_orgs",
            make_config(),
            "sync-saml-orgs requires one of --full, --users",
        )

    def test_validate_config_rejects_sync_saml_orgs_full_with_user_filters(self) -> None:
        self.assert_config_error(
            "sync_saml_orgs",
            make_config(full=True, users=("alice",)),
            "choose at most one of --full, --users",
        )
        self.assert_config_error(
            "sync_saml_orgs",
            make_config(full=True, created_after="2099-01-01"),
            "--full cannot be combined with --created-after",
        )

    def test_validate_config_allows_sync_saml_orgs_modes(self) -> None:
        cli.validate_config("sync_saml_orgs", make_config(full=True))
        cli.validate_config("sync_saml_orgs", make_config(users=("alice",)))
        cli.validate_config("sync_saml_orgs", make_config(users_without_explicit_perms=True))
        cli.validate_config("sync_saml_orgs", make_config(created_after="2026-01-01"))

    def test_resolve_command_names_sync_saml_orgs_artifacts_by_mode(self) -> None:
        self.assertEqual(
            "sync-saml-orgs-full-dry-run",
            cli.resolve_command("sync_saml_orgs", make_config(full=True)).artifact_name,
        )
        self.assertEqual(
            "sync-saml-orgs-users-apply",
            cli.resolve_command(
                "sync_saml_orgs", make_config(users=("alice",), apply=True)
            ).artifact_name,
        )
        self.assertEqual(
            "sync-saml-orgs-created-after-dry-run",
            cli.resolve_command(
                "sync_saml_orgs", make_config(created_after="2026-01-01")
            ).artifact_name,
        )

    def test_created_after_config_accepts_yyyy_mm_dd_date_arguments(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_CREATED_AFTER="2026-01-01")

        self.assertEqual("2026-01-01", config.created_after)
        cli.validate_config("get", make_config(created_after="2026-01-01"))
        cli.validate_config(
            "set",
            make_config(
                maps_path=Path("maps.yaml"),
                users=("alice",),
                created_after="2026-01-01",
            ),
        )

    def test_created_after_config_rejects_values_outside_yyyy_mm_dd_shape(self) -> None:
        for invalid_value in ("2026-1-01", "2026-01-01T00:00:00Z"):
            with (
                self.subTest(invalid_value=invalid_value),
                self.assertRaisesRegex(shared_config.ConfigError, "String should match pattern"),
            ):
                load_config_from_env(SRC_AUTH_PERMS_SYNC_CREATED_AFTER=invalid_value)

    def test_explicit_permissions_batch_size_config_is_loaded_from_env(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_EXPLICIT_PERMISSIONS_BATCH_SIZE="50")

        self.assertEqual(50, config.explicit_permissions_batch_size)

    def test_explicit_permissions_batch_size_rejects_values_below_one(self) -> None:
        with self.assertRaisesRegex(shared_config.ConfigError, "greater than or equal to 1"):
            load_config_from_env(SRC_AUTH_PERMS_SYNC_EXPLICIT_PERMISSIONS_BATCH_SIZE="0")

    def test_http_timeout_config_is_loaded_from_env(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_HTTP_TIMEOUT_SECONDS="90")

        self.assertEqual(90, config.http_timeout_seconds)

    def test_http_timeout_rejects_values_at_or_below_zero(self) -> None:
        with self.assertRaisesRegex(shared_config.ConfigError, "greater than 0"):
            load_config_from_env(SRC_AUTH_PERMS_SYNC_HTTP_TIMEOUT_SECONDS="0")

    def test_fetch_sg_traces_config_is_loaded_from_env(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_FETCH_SG_TRACES="true")

        self.assertTrue(config.fetch_sg_traces)

    def test_open_telemetry_config_is_loaded_from_env(self) -> None:
        config = load_config_from_env(OTEL_ENABLED="true", OTEL_SERVICE_NAME="src-auth-test")

        self.assertTrue(config.open_telemetry)
        self.assertEqual("src-auth-test", config.open_telemetry_service_name)

    def test_run_with_client_enables_sourcegraph_trace_collection(self) -> None:
        configuration = make_config(fetch_sg_traces=True)
        command = cli.resolve_command("get", configuration)
        captured_clients: list[src.SourcegraphClient] = []

        def capture_client(
            _config: cli.Config,
            _command: cli.ResolvedCommand,
            client: src.SourcegraphClient,
            _run_paths: backups.RunPaths,
            _worker_pool: ThreadPoolExecutor,
            _mapping_rules: object = None,
        ) -> None:
            captured_clients.append(client)

        with (
            ThreadPoolExecutor(max_workers=1) as worker_pool,
            mock.patch.object(cli, "run_command", side_effect=capture_client),
        ):
            cli.run_with_client(
                configuration,
                command,
                "https://sourcegraph.example.com",
                make_run_paths(),
                worker_pool,
            )

        self.assertEqual(1, len(captured_clients))
        self.assertTrue(captured_clients[0].fetch_sg_traces)

    def test_run_with_client_uses_configured_http_timeout(self) -> None:
        configuration = make_config(http_timeout_seconds=75.0)
        command = cli.resolve_command("get", configuration)
        captured_clients: list[src.SourcegraphClient] = []

        def capture_client(
            _config: cli.Config,
            _command: cli.ResolvedCommand,
            client: src.SourcegraphClient,
            _run_paths: backups.RunPaths,
            _worker_pool: ThreadPoolExecutor,
            _mapping_rules: object = None,
        ) -> None:
            captured_clients.append(client)

        with (
            ThreadPoolExecutor(max_workers=1) as worker_pool,
            mock.patch.object(cli, "run_command", side_effect=capture_client),
        ):
            cli.run_with_client(
                configuration,
                command,
                "https://sourcegraph.example.com",
                make_run_paths(),
                worker_pool,
            )

        self.assertEqual(1, len(captured_clients))
        self.assertEqual(75.0, captured_clients[0].http.timeout)

    def test_validate_config_rejects_multiple_set_modes(self) -> None:
        self.assert_config_error(
            "set",
            make_config(maps_path=Path("maps.yaml"), full=True, users=("alice",)),
            "choose at most one",
        )

    def test_validate_config_rejects_full_created_after(self) -> None:
        self.assert_config_error(
            "set",
            make_config(maps_path=Path("maps.yaml"), full=True, created_after="2026-01-01"),
            "--full cannot be combined with --created-after",
        )

    def test_require_set_input_file_reports_missing_maps_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            existing_path = Path(directory) / "maps.yaml"
            existing_path.write_text("maps: []\n")
            cli.require_set_input_file(existing_path)

            with self.assertRaises(SystemExit) as exit_context:
                cli.require_set_input_file(Path(directory) / "missing.yaml")
            self.assertIn("set input file does not exist", str(exit_context.exception))

    def test_require_restore_input_file_reports_missing_snapshot_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            existing_path = Path(directory) / "before.json"
            existing_path.write_text("{}\n")
            cli.require_restore_input_file(existing_path)

            with self.assertRaises(SystemExit) as exit_context:
                cli.require_restore_input_file(Path(directory) / "missing.json")
            self.assertIn("restore snapshot file does not exist", str(exit_context.exception))

    def test_run_fields_include_command_arguments_without_command_duplicates(self) -> None:
        configuration = make_config(
            maps_path=Path("maps.yaml"),
            users=("alice",),
            apply=True,
        )
        command = cli.resolve_command("set", configuration)

        fields = cli.run_fields(
            configuration,
            command,
            "https://sourcegraph.example.com",
            make_run_paths(),
        )

        self.assertEqual("users", fields["set_mode"])
        self.assertEqual(True, fields["apply"])
        self.assertNotIn("cli_cmd", fields)
        self.assertNotIn("base_cmd", fields)
        self.assertEqual(25, fields["explicit_permissions_batch_size"])
        self.assertEqual(False, fields["fetch_sg_traces"])
        self.assertEqual(False, fields["open_telemetry"])
        self.assertEqual(300.0, fields["http_timeout_seconds"])

    def test_run_fields_omit_irrelevant_false_flags(self) -> None:
        configuration = make_config()
        command = cli.resolve_command("get", configuration)

        fields = cli.run_fields(
            configuration,
            command,
            "https://sourcegraph.example.com",
            make_run_paths(),
        )

        self.assertNotIn("apply", fields)
        self.assertNotIn("no_backup", fields)
        self.assertNotIn("set_mode", fields)
        self.assertNotIn("sync_saml_orgs", fields)
        self.assertNotIn("created_after", fields)

    def test_run_fields_include_no_backup_only_when_set(self) -> None:
        configuration = make_config(no_backup=True)
        command = cli.resolve_command("get", configuration)

        fields = cli.run_fields(
            configuration,
            command,
            "https://sourcegraph.example.com",
            make_run_paths(),
        )

        self.assertEqual(True, fields["no_backup"])

    def test_run_get_passes_no_backup_to_permission_command(self) -> None:
        configuration = make_config(no_backup=True)
        client = cast(
            src.SourcegraphClient,
            SimpleNamespace(endpoint="https://sourcegraph.example.com"),
        )
        sourcegraph_site_config = cli.site_config.SiteConfig(
            bind_id_mode="USERNAME",
            auth_providers_by_config_id={},
            saml_groups_attribute_name_by_config_id={},
        )
        run_paths = make_run_paths()
        worker_pool = cast(ThreadPoolExecutor, object())

        with (
            mock.patch.object(
                cli.permissions_maps, "create_maps_yaml_if_missing", return_value=False
            ),
            mock.patch.object(
                cli.permissions_command,
                "cmd_get",
                return_value=cli.run_context.CommandData(),
            ) as cmd_get,
        ):
            cli.run_get(configuration, client, sourcegraph_site_config, run_paths, worker_pool)

        self.assertFalse(cmd_get.call_args.kwargs["do_backup"])

    def test_cmd_get_no_backup_skips_snapshot_artifacts(self) -> None:
        client = cast(
            src.SourcegraphClient,
            SimpleNamespace(endpoint="https://sourcegraph.example.com"),
        )

        with (
            mock.patch.object(permissions_command, "load_discovery", return_value=([], [], {})),
            mock.patch.object(permissions_command, "load_selected_users", return_value=[]),
            mock.patch.object(permissions_command.permissions_maps, "dump_code_hosts_yaml"),
            mock.patch.object(permissions_command.permissions_maps, "dump_auth_providers_yaml"),
            mock.patch.object(
                permissions_command.permission_snapshot, "build_snapshot"
            ) as build_snapshot,
            mock.patch.object(permissions_command, "write_maps_backup") as write_maps_backup,
        ):
            permissions_command.cmd_get(
                client,
                make_run_paths(),
                user_identifiers=(),
                users_without_explicit_perms=False,
                user_created_after=None,
                repository_names=(),
                repositories_without_explicit_perms=False,
                repository_created_after=None,
                parallelism=1,
                explicit_permissions_batch_size=25,
                bind_id_mode="USERNAME",
                saml_groups_attribute_name_by_config_id={},
                auth_providers_by_config_id={},
                do_backup=False,
            )

        build_snapshot.assert_not_called()
        write_maps_backup.assert_not_called()

    def test_cmd_set_dispatches_repo_filters_to_full_set(self) -> None:
        client = cast(src.SourcegraphClient, object())
        options = permission_types.SetCommandOptions(
            mode="repos",
            repository_names=("github.com/sourcegraph/one",),
        )

        with mock.patch.object(
            permissions_command.permissions_full_set,
            "cmd_set_full",
            return_value=cli.run_context.CommandData(),
        ) as cmd_set_full:
            permissions_command.cmd_set(
                client,
                make_run_paths(),
                options,
                dry_run=True,
                parallelism=1,
                explicit_permissions_batch_size=25,
                bind_id_mode="USERNAME",
                saml_groups_attribute_name_by_config_id={},
                do_backup=True,
            )

        self.assertEqual(
            ("github.com/sourcegraph/one",),
            cmd_set_full.call_args.kwargs["repository_names"],
        )
        self.assertFalse(cmd_set_full.call_args.kwargs["repositories_without_explicit_perms"])
        self.assertIsNone(cmd_set_full.call_args.kwargs["repository_created_after"])

    def test_run_command_passes_set_data_to_combined_sync(self) -> None:
        configuration = make_config(sync_saml_orgs=True, full=True)
        command = cli.resolve_command("set", configuration)
        client = cast(src.SourcegraphClient, object())
        sourcegraph_site_config = object()
        command_data = cli.run_context.CommandData()
        run_paths = make_run_paths()

        with (
            ThreadPoolExecutor(max_workers=1) as worker_pool,
            mock.patch.object(
                cli.site_config,
                "validate_site_config",
                return_value=sourcegraph_site_config,
            ),
            mock.patch.object(cli, "run_set", return_value=command_data) as run_set,
            mock.patch.object(cli, "run_sync_saml_orgs") as run_sync_saml_orgs,
        ):
            cli.run_command(configuration, command, client, run_paths, worker_pool)

        run_set.assert_called_once_with(
            configuration,
            command,
            client,
            sourcegraph_site_config,
            run_paths,
            worker_pool,
            mapping_rules=None,
        )
        run_sync_saml_orgs.assert_called_once_with(
            configuration,
            client,
            sourcegraph_site_config,
            command_data,
            run_paths,
            worker_pool,
        )

    def test_package_exports_programmatic_runner_and_config(self) -> None:
        self.assertIs(src_auth_perms_sync.Config, cli.Config)
        self.assertIs(src_auth_perms_sync.Get, cli.Get)
        self.assertIs(src_auth_perms_sync.Set, cli.Set)
        self.assertIs(src_auth_perms_sync.Restore, cli.Restore)
        self.assertIs(src_auth_perms_sync.SyncSamlOrgs, cli.SyncSamlOrgs)
        self.assertIs(src_auth_perms_sync.GetResult, cli.GetResult)
        self.assertIs(src_auth_perms_sync.CommandResult, cli.CommandResult)
        self.assertIs(src_auth_perms_sync.RunPaths, backups.RunPaths)
        self.assertIs(src_auth_perms_sync.EventSink, src.EventSink)
        self.assertIs(src_auth_perms_sync.InMemoryEventSink, src.InMemoryEventSink)
        self.assertEqual(
            [
                "CallbackEventSink",
                "CommandResult",
                "CompositeEventSink",
                "Config",
                "EventSink",
                "Get",
                "GetResult",
                "InMemoryEventSink",
                "JSONLEventSink",
                "MappingRule",
                "NullEventSink",
                "Restore",
                "RunPaths",
                "Set",
                "SyncSamlOrgs",
            ],
            src_auth_perms_sync.__all__,
        )

    def test_programmatic_runner_uses_supplied_config(self) -> None:
        configuration = make_config(parallelism=1, sample_interval=0, no_files=True)
        captured: list[tuple[cli.Config, cli.ResolvedCommand, str]] = []

        def capture_run(
            scoped_config: cli.Config,
            command: cli.ResolvedCommand,
            endpoint: str,
            _run_paths: backups.RunPaths,
            _worker_pool: ThreadPoolExecutor,
            _mapping_rules: object = None,
        ) -> cli.run_context.CommandData:
            captured.append((scoped_config, command, endpoint))
            return cli.run_context.CommandData()

        with mock.patch.object(cli, "run_with_client", side_effect=capture_run):
            self.assertTrue(src_auth_perms_sync.Get(configuration))

        self.assertEqual(1, len(captured))
        scoped_config, command, endpoint = captured[0]
        self.assertIs(configuration, scoped_config)
        self.assertEqual("get", command.name)
        self.assertEqual("https://sourcegraph.example.com", endpoint)

    def test_programmatic_runner_returns_false_on_failure(self) -> None:
        configuration = make_config(parallelism=1, sample_interval=0, no_files=True)

        with mock.patch.object(cli, "run_with_client", side_effect=SystemExit(1)):
            self.assertFalse(src_auth_perms_sync.Get(configuration))

    def assert_config_error(
        self,
        command_name: cli.CommandName,
        config: cli.Config,
        expected_message: str,
    ) -> None:
        captured_stderr = io.StringIO()
        with (
            contextlib.redirect_stderr(captured_stderr),
            self.assertRaises(SystemExit) as exit_context,
        ):
            cli.validate_config(command_name, config)
        self.assertEqual(2, exit_context.exception.code)
        self.assertIn(expected_message, captured_stderr.getvalue())
