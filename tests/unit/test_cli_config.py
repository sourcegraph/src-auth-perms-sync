from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from src_py_lib.utils import config as shared_config

from auth_perms_sync import cli
from auth_perms_sync.shared import backups


def make_config(**updates: object) -> cli.AuthPermissionsSyncConfig:
    base_config = cli.AuthPermissionsSyncConfig(
        src_endpoint="https://sourcegraph.example.com",
        src_access_token="secret",
    )
    return base_config.model_copy(update=updates)


def load_config_from_env(**env: str) -> cli.AuthPermissionsSyncConfig:
    return shared_config.load_config(
        cli.AuthPermissionsSyncConfig,
        env_file=None,
        env={
            "SRC_ENDPOINT": "https://sourcegraph.example.com",
            "SRC_ACCESS_TOKEN": "secret",
            **env,
        },
        resolve_op_refs=False,
    )


class CliConfigTests(unittest.TestCase):
    def test_resolve_command_defaults_to_get(self) -> None:
        command = cli.resolve_command(make_config())

        self.assertEqual("get", command.name)
        self.assertEqual("get", command.log_name)
        self.assertEqual("get", command.artifact_name)

    def test_resolve_command_prefers_explicit_commands(self) -> None:
        self.assertEqual(
            "set", cli.resolve_command(make_config(set_path=Path("maps.yaml"), full=True)).name
        )
        self.assertEqual(
            "restore", cli.resolve_command(make_config(restore_path=Path("snapshot.json"))).name
        )
        self.assertEqual(
            "sync_saml_orgs", cli.resolve_command(make_config(sync_saml_organizations=True)).name
        )

    def test_set_command_options_match_each_incremental_mode(self) -> None:
        self.assertEqual(
            "full", cli.set_command_options(make_config(set_path=Path("maps.yaml"))).mode
        )
        self.assertEqual(
            ("user", "alice"),
            (
                cli.set_command_options(make_config(set_path=Path("maps.yaml"), user="alice")).mode,
                cli.set_command_options(
                    make_config(set_path=Path("maps.yaml"), user="alice")
                ).user_identifier,
            ),
        )
        users_without_permissions = cli.set_command_options(
            make_config(
                set_path=Path("maps.yaml"),
                users_without_explicit_perms=True,
                created_after="2026-01-01",
            )
        )
        self.assertEqual("users_without_explicit_perms", users_without_permissions.mode)
        self.assertEqual("2026-01-01", users_without_permissions.user_created_after)
        filtered_full = cli.set_command_options(
            make_config(set_path=Path("maps.yaml"), created_after="2026-01-01")
        )
        self.assertEqual("full", filtered_full.mode)
        self.assertEqual("2026-01-01", filtered_full.user_created_after)

    def test_resolve_command_includes_set_mode_names(self) -> None:
        user_command = cli.resolve_command(
            make_config(set_path=Path("maps.yaml"), user="alice", apply=True)
        )
        full_command = cli.resolve_command(make_config(set_path=Path("maps.yaml")))

        self.assertEqual("set_user", user_command.log_name)
        self.assertEqual("set-add-user-apply", user_command.artifact_name)
        self.assertEqual("user", user_command.set_mode)
        self.assertEqual("set_full", full_command.log_name)
        self.assertEqual("set-dry-run", full_command.artifact_name)

    def test_resolve_command_includes_combined_sync_names(self) -> None:
        get_command = cli.resolve_command(make_config(get=True, sync_saml_organizations=True))
        set_command = cli.resolve_command(
            make_config(set_path=Path("maps.yaml"), apply=True, sync_saml_organizations=True)
        )

        self.assertEqual("get", get_command.name)
        self.assertEqual("get_sync_saml_orgs", get_command.log_name)
        self.assertEqual("get-sync-saml-orgs-dry-run", get_command.artifact_name)
        self.assertTrue(get_command.sync_saml_organizations)
        self.assertEqual("set", set_command.name)
        self.assertEqual("set_full_sync_saml_orgs", set_command.log_name)
        self.assertEqual("set-sync-saml-orgs-apply", set_command.artifact_name)
        self.assertTrue(set_command.sync_saml_organizations)

    def test_validate_config_rejects_multiple_commands(self) -> None:
        self.assert_config_error(
            make_config(get=True, set_path=Path("maps.yaml"), full=True),
            "choose only one",
        )

    def test_validate_config_allows_sync_saml_orgs_with_get_or_set(self) -> None:
        cli.validate_config(make_config(get=True, sync_saml_organizations=True))
        cli.validate_config(make_config(set_path=Path("maps.yaml"), sync_saml_organizations=True))

    def test_validate_config_rejects_sync_saml_orgs_with_restore(self) -> None:
        self.assert_config_error(
            make_config(restore_path=Path("snapshot.json"), sync_saml_organizations=True),
            "with --get or --set",
        )

    def test_validate_config_rejects_set_modes_without_set(self) -> None:
        self.assert_config_error(make_config(full=True), "requires --set")

    def test_validate_config_allows_get_user_filters_without_set(self) -> None:
        cli.validate_config(make_config(user="alice"))
        cli.validate_config(make_config(users_without_explicit_perms=True))
        cli.validate_config(make_config(created_after="2026-01-01"))

    def test_validate_config_rejects_get_user_filter_conflicts(self) -> None:
        self.assert_config_error(
            make_config(user="alice", users_without_explicit_perms=True),
            "choose only one of --user or --users-without-explicit-perms",
        )

    def test_validate_config_rejects_user_filters_on_non_get_set_commands(self) -> None:
        self.assert_config_error(
            make_config(restore_path=Path("snapshot.json"), user="alice"),
            "require --get or --set",
        )

    def test_validate_config_allows_set_without_explicit_mode(self) -> None:
        cli.validate_config(make_config(set_path=Path("maps.yaml")))

    def test_created_after_config_accepts_yyyy_mm_dd_date_arguments(self) -> None:
        config = load_config_from_env(AUTH_PERMS_SYNC_CREATED_AFTER="2026-01-01")

        self.assertEqual("2026-01-01", config.created_after)
        cli.validate_config(make_config(get=True, created_after="2026-01-01"))
        cli.validate_config(
            make_config(
                set_path=Path("maps.yaml"),
                user="alice",
                created_after="2026-01-01",
            )
        )

    def test_created_after_config_rejects_values_outside_yyyy_mm_dd_shape(self) -> None:
        for invalid_value in ("2026-1-01", "2026-01-01T00:00:00Z"):
            with (
                self.subTest(invalid_value=invalid_value),
                self.assertRaisesRegex(shared_config.ConfigError, "String should match pattern"),
            ):
                load_config_from_env(AUTH_PERMS_SYNC_CREATED_AFTER=invalid_value)

    def test_validate_config_rejects_multiple_set_modes(self) -> None:
        self.assert_config_error(
            make_config(set_path=Path("maps.yaml"), full=True, user="alice"),
            "choose at most one",
        )

    def test_require_set_input_file_reports_missing_maps_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            existing_path = Path(directory) / "maps.yaml"
            existing_path.write_text("maps: []\n")
            cli.require_set_input_file(make_config(set_path=existing_path))

            with self.assertRaises(SystemExit) as exit_context:
                cli.require_set_input_file(make_config(set_path=Path(directory) / "missing.yaml"))
            self.assertIn("--set input file does not exist", str(exit_context.exception))

    def test_endpoint_scoped_config_rewrites_relative_artifact_paths(self) -> None:
        scoped_config = cli.endpoint_scoped_config(
            make_config(set_path=Path("maps.yaml"), restore_path=Path("snapshot.json")),
            "https://sourcegraph.example.com",
        )
        endpoint_directory = Path.cwd() / backups.ARTIFACTS_DIR_NAME / "sourcegraph.example.com"
        self.assertEqual(endpoint_directory / "maps.yaml", scoped_config.set_path)
        self.assertEqual(endpoint_directory / "snapshot.json", scoped_config.restore_path)

    def test_run_fields_include_concrete_command(self) -> None:
        configuration = make_config(set_path=Path("maps.yaml"), user="alice", apply=True)
        command = cli.resolve_command(configuration)

        fields = cli.run_fields(configuration, command, "https://sourcegraph.example.com")

        self.assertEqual("set_user", fields["cli_cmd"])
        self.assertEqual("set", fields["base_cmd"])
        self.assertEqual("user", fields["set_mode"])
        self.assertEqual(True, fields["apply_flag"])

    def test_run_command_passes_primary_data_to_combined_sync(self) -> None:
        configuration = make_config(get=True, sync_saml_organizations=True)
        command = cli.resolve_command(configuration)
        client = object()
        sourcegraph_site_config = object()
        command_data = cli.run_context.CommandData()

        with (
            ThreadPoolExecutor(max_workers=1) as worker_pool,
            mock.patch.object(
                cli.site_config,
                "validate_site_config",
                return_value=sourcegraph_site_config,
            ),
            mock.patch.object(cli, "run_get", return_value=command_data) as run_get,
            mock.patch.object(cli, "run_sync_saml_organizations") as run_sync_saml_orgs,
        ):
            cli.run_command(configuration, command, client, worker_pool)

        run_get.assert_called_once_with(
            configuration,
            client,
            sourcegraph_site_config,
            worker_pool,
        )
        run_sync_saml_orgs.assert_called_once_with(
            configuration,
            client,
            sourcegraph_site_config,
            command_data,
            worker_pool,
        )

    def assert_config_error(
        self, config: cli.AuthPermissionsSyncConfig, expected_message: str
    ) -> None:
        captured_stderr = io.StringIO()
        with (
            contextlib.redirect_stderr(captured_stderr),
            self.assertRaises(SystemExit) as exit_context,
        ):
            cli.validate_config(config)
        self.assertEqual(2, exit_context.exception.code)
        self.assertIn(expected_message, captured_stderr.getvalue())
