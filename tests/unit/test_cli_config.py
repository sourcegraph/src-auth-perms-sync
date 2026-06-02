from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast
from unittest import mock

import src_py_lib as src
from src_py_lib.utils import config as shared_config

import src_auth_perms_sync
from src_auth_perms_sync import cli
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
                ["set", "--env-file", str(env_file), "--maps-path", "custom-maps.yaml"]
            )

        self.assertEqual("set", cli_input.command_name)
        self.assertEqual(Path("custom-maps.yaml"), cli_input.config.maps_path)

    def test_restore_path_config_loads_without_selecting_a_command(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_RESTORE_PATH="snapshot.json")

        self.assertEqual(Path.cwd() / "snapshot.json", config.restore_path)

    def test_set_command_options_match_each_incremental_mode(self) -> None:
        self.assertEqual(
            "full",
            cli.set_command_options(make_config(maps_path=Path("maps.yaml"))).mode,
        )
        self.assertEqual(
            ("user", "alice"),
            (
                cli.set_command_options(
                    make_config(maps_path=Path("maps.yaml"), user="alice")
                ).mode,
                cli.set_command_options(
                    make_config(maps_path=Path("maps.yaml"), user="alice")
                ).user_identifier,
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
        filtered_full = cli.set_command_options(
            make_config(maps_path=Path("maps.yaml"), created_after="2026-01-01")
        )
        self.assertEqual("full", filtered_full.mode)
        self.assertEqual("2026-01-01", filtered_full.user_created_after)

    def test_resolve_command_includes_set_mode_names(self) -> None:
        user_command = cli.resolve_command(
            "set",
            make_config(maps_path=Path("maps.yaml"), user="alice", apply=True),
        )
        full_command = cli.resolve_command("set", make_config(maps_path=Path("maps.yaml")))

        self.assertEqual("set_user", user_command.log_name)
        self.assertEqual("set-add-user-apply", user_command.artifact_name)
        self.assertEqual("user", user_command.set_mode)
        self.assertEqual("set_full", full_command.log_name)
        self.assertEqual("set-dry-run", full_command.artifact_name)

    def test_resolve_command_includes_combined_sync_names(self) -> None:
        get_command = cli.resolve_command("get", make_config(sync_saml_organizations=True))
        set_command = cli.resolve_command(
            "set",
            make_config(
                maps_path=Path("maps.yaml"),
                apply=True,
                sync_saml_organizations=True,
            ),
        )

        self.assertEqual("get", get_command.name)
        self.assertEqual("get_sync_saml_orgs", get_command.log_name)
        self.assertEqual("get-sync-saml-orgs-dry-run", get_command.artifact_name)
        self.assertTrue(get_command.sync_saml_organizations)
        self.assertEqual("set", set_command.name)
        self.assertEqual("set_full_sync_saml_orgs", set_command.log_name)
        self.assertEqual("set-sync-saml-orgs-apply", set_command.artifact_name)
        self.assertTrue(set_command.sync_saml_organizations)

    def test_validate_config_allows_sync_saml_orgs_with_get_or_set(self) -> None:
        cli.validate_config("get", make_config(sync_saml_organizations=True))
        cli.validate_config(
            "set",
            make_config(maps_path=Path("maps.yaml"), sync_saml_organizations=True),
        )

    def test_validate_config_rejects_sync_saml_orgs_with_restore_or_sync_command(self) -> None:
        self.assert_config_error(
            "restore",
            make_config(restore_path=Path("snapshot.json"), sync_saml_organizations=True),
            "can only be combined with get or set",
        )
        self.assert_config_error(
            "sync_saml_orgs",
            make_config(sync_saml_organizations=True),
            "can only be combined with get or set",
        )

    def test_validate_config_rejects_restore_without_restore_path(self) -> None:
        self.assert_config_error("restore", make_config(), "restore requires --restore-path")

    def test_validate_config_rejects_restore_path_without_restore(self) -> None:
        self.assert_config_error(
            "get",
            make_config(restore_path=Path("snapshot.json")),
            "--restore-path requires the restore command",
        )

    def test_validate_config_rejects_set_modes_without_set(self) -> None:
        self.assert_config_error("get", make_config(full=True), "requires the set command")

    def test_validate_config_allows_get_user_filters_without_set(self) -> None:
        cli.validate_config("get", make_config(user="alice"))
        cli.validate_config("get", make_config(users_without_explicit_perms=True))
        cli.validate_config("get", make_config(created_after="2026-01-01"))

    def test_validate_config_rejects_get_user_filter_conflicts(self) -> None:
        self.assert_config_error(
            "get",
            make_config(user="alice", users_without_explicit_perms=True),
            "choose only one of --user or --users-without-explicit-perms",
        )

    def test_validate_config_rejects_user_filters_on_non_get_set_commands(self) -> None:
        self.assert_config_error(
            "restore",
            make_config(restore_path=Path("snapshot.json"), user="alice"),
            "require get or set",
        )

    def test_validate_config_allows_set_without_explicit_mode(self) -> None:
        cli.validate_config("set", make_config(maps_path=Path("maps.yaml")))

    def test_created_after_config_accepts_yyyy_mm_dd_date_arguments(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_CREATED_AFTER="2026-01-01")

        self.assertEqual("2026-01-01", config.created_after)
        cli.validate_config("get", make_config(created_after="2026-01-01"))
        cli.validate_config(
            "set",
            make_config(
                maps_path=Path("maps.yaml"),
                user="alice",
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

    def test_trace_config_is_loaded_from_env(self) -> None:
        config = load_config_from_env(SRC_AUTH_PERMS_SYNC_TRACE="true")

        self.assertTrue(config.trace)

    def test_run_with_client_enables_sourcegraph_trace_collection(self) -> None:
        configuration = make_config(trace=True)
        command = cli.resolve_command("get", configuration)
        captured_clients: list[src.SourcegraphClient] = []

        def capture_client(
            _config: cli.Config,
            _command: cli.ResolvedCommand,
            client: src.SourcegraphClient,
            _worker_pool: ThreadPoolExecutor,
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
                worker_pool,
            )

        self.assertEqual(1, len(captured_clients))
        self.assertTrue(captured_clients[0].trace)

    def test_run_with_client_uses_configured_http_timeout(self) -> None:
        configuration = make_config(http_timeout_seconds=75.0)
        command = cli.resolve_command("get", configuration)
        captured_clients: list[src.SourcegraphClient] = []

        def capture_client(
            _config: cli.Config,
            _command: cli.ResolvedCommand,
            client: src.SourcegraphClient,
            _worker_pool: ThreadPoolExecutor,
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
                worker_pool,
            )

        self.assertEqual(1, len(captured_clients))
        self.assertEqual(75.0, captured_clients[0].http.timeout)

    def test_validate_config_rejects_multiple_set_modes(self) -> None:
        self.assert_config_error(
            "set",
            make_config(maps_path=Path("maps.yaml"), full=True, user="alice"),
            "choose at most one",
        )

    def test_require_set_input_file_reports_missing_maps_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            existing_path = Path(directory) / "maps.yaml"
            existing_path.write_text("maps: []\n")
            cli.require_set_input_file(make_config(maps_path=existing_path))

            with self.assertRaises(SystemExit) as exit_context:
                cli.require_set_input_file(make_config(maps_path=Path(directory) / "missing.yaml"))
            self.assertIn("set input file does not exist", str(exit_context.exception))

    def test_endpoint_scoped_config_rewrites_relative_artifact_paths(self) -> None:
        scoped_set_config = cli.endpoint_scoped_config(
            "set",
            make_config(maps_path=Path("maps.yaml")),
            "https://sourcegraph.example.com",
        )
        endpoint_directory = Path.cwd() / backups.ARTIFACTS_DIR_NAME / "sourcegraph.example.com"
        self.assertEqual(endpoint_directory / "maps.yaml", scoped_set_config.maps_path)

        scoped_restore_config = cli.endpoint_scoped_config(
            "restore",
            make_config(restore_path=Path("snapshot.json")),
            "https://sourcegraph.example.com",
        )
        self.assertEqual(endpoint_directory / "snapshot.json", scoped_restore_config.restore_path)

    def test_run_fields_include_concrete_command(self) -> None:
        configuration = make_config(
            maps_path=Path("maps.yaml"),
            user="alice",
            apply=True,
        )
        command = cli.resolve_command("set", configuration)

        fields = cli.run_fields(configuration, command, "https://sourcegraph.example.com")

        self.assertEqual("set_user", fields["cli_cmd"])
        self.assertEqual("set", fields["base_cmd"])
        self.assertEqual("user", fields["set_mode"])
        self.assertEqual(True, fields["apply_flag"])
        self.assertEqual(25, fields["explicit_permissions_batch_size"])
        self.assertEqual(False, fields["trace"])
        self.assertEqual(60.0, fields["http_timeout_seconds"])

    def test_run_command_passes_primary_data_to_combined_sync(self) -> None:
        configuration = make_config(sync_saml_organizations=True)
        command = cli.resolve_command("get", configuration)
        client = cast(src.SourcegraphClient, object())
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

    def test_package_exports_programmatic_runner_and_config(self) -> None:
        self.assertIs(src_auth_perms_sync.Config, cli.Config)
        self.assertIs(src_auth_perms_sync.Get, cli.Get)
        self.assertIs(src_auth_perms_sync.Set, cli.Set)
        self.assertIs(src_auth_perms_sync.Restore, cli.Restore)
        self.assertIs(src_auth_perms_sync.SyncSamlOrgs, cli.SyncSamlOrgs)
        self.assertEqual(
            ["Config", "Get", "Restore", "Set", "SyncSamlOrgs"],
            src_auth_perms_sync.__all__,
        )

    def test_programmatic_runner_uses_supplied_config(self) -> None:
        configuration = make_config(parallelism=1, sample_interval=0)
        captured: list[tuple[cli.Config, cli.ResolvedCommand, str]] = []

        def capture_run(
            scoped_config: cli.Config,
            command: cli.ResolvedCommand,
            endpoint: str,
            _worker_pool: ThreadPoolExecutor,
        ) -> None:
            captured.append((scoped_config, command, endpoint))

        with (
            mock.patch.object(cli, "run_with_client", side_effect=capture_run),
            mock.patch.object(
                cli.src,
                "logging_settings_from_config",
                return_value=object(),
            ),
            mock.patch.object(cli.src, "logging", return_value=contextlib.nullcontext(None)),
        ):
            self.assertTrue(src_auth_perms_sync.Get(configuration))

        self.assertEqual(1, len(captured))
        scoped_config, command, endpoint = captured[0]
        self.assertIs(configuration, scoped_config)
        self.assertEqual("get", command.name)
        self.assertEqual("https://sourcegraph.example.com", endpoint)

    def test_programmatic_runner_returns_false_on_failure(self) -> None:
        configuration = make_config(parallelism=1, sample_interval=0)

        with (
            mock.patch.object(cli, "run_with_client", side_effect=SystemExit(1)),
            mock.patch.object(
                cli.src,
                "logging_settings_from_config",
                return_value=object(),
            ),
            mock.patch.object(cli.src, "logging", return_value=contextlib.nullcontext(None)),
        ):
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
