"""Focused tests for logging, HTTP, and API-client primitives."""

from __future__ import annotations

import argparse
import io
import json
import logging
import subprocess
import tempfile
import unittest
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx

import src_py_lib as src
from src_py_lib.clients.github import GitHubClient, graphql_api_url, pr_ref_from_url
from src_py_lib.clients.google_sheets import GoogleSheetsClient
from src_py_lib.clients.graphql import (
    GraphQLClient,
    GraphQLError,
    introspect_schema,
    stream_connection_nodes,
)
from src_py_lib.clients.linear import LinearClient, LinearClientConfig, linear_client_from_config
from src_py_lib.clients.one_password import (
    OnePasswordClient,
    OnePasswordError,
    resolve_op_secret_ref,
)
from src_py_lib.clients.slack import SlackClient
from src_py_lib.clients.sourcegraph import (
    SourcegraphClient,
    SourcegraphClientConfig,
    normalize_sourcegraph_endpoint,
    sourcegraph_client_from_config,
)
from src_py_lib.utils.config import (
    Config,
    ConfigError,
    add_config_arguments,
    config_env_file_from_args,
    config_field,
    config_overrides_from_args,
    config_parse_args,
    config_snapshot,
    load_config,
    load_config_env_file,
    load_config_from_args,
    resolve_config_refs,
)
from src_py_lib.utils.http import HTTPClient, HTTPClientError
from src_py_lib.utils.json_types import JSONDict, json_dict, json_list
from src_py_lib.utils.logging import (
    LoggingConfig,
    LoggingSettings,
    configure_logging,
    critical,
    debug,
    default_log_file,
    error,
    event,
    info,
    log,
    log_context,
    logging_settings_from_config,
    resolve_log_level_name,
    startup_event,
    warning,
)


class RecordingHTTP(HTTPClient):
    """HTTPClient test double that records JSON request arguments."""

    def __init__(self, responses: list[dict[str, Any]] | None = None) -> None:
        super().__init__()
        self.responses = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    def json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str | int | float | bool | None] | None = None,
        json_body: object | None = None,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "query": query,
                "json_body": json_body,
            }
        )
        if self.responses:
            return self.responses.pop(0)
        return {"data": {"viewer": {"username": "alice"}}}


class FakeOnePasswordClient(OnePasswordClient):
    """1Password test double that avoids shelling out."""

    def read(self, secret_ref: str) -> str:
        if secret_ref == "op://vault/item/field":
            return "resolved-secret"
        if secret_ref == "op://vault/page-size/value":
            return "40"
        if secret_ref == "op://vault/labels/value":
            return "gamma, delta"
        if secret_ref == "op://vault/name/value":
            return "resolved-name"
        raise OnePasswordError(f"unexpected secret ref: {secret_ref}")


class ExampleConfig(Config):
    """Config model used by Config tests."""

    token: str = config_field(
        default="",
        env_var="EXAMPLE_TOKEN",
        cli_flag="--token",
        metavar="TOKEN",
        help="Example token",
        secret=True,
    )
    page_size: int = config_field(
        default=25,
        env_var="EXAMPLE_PAGE_SIZE",
        cli_flag="--page-size",
        metavar="N",
        help="Example page size",
    )
    include_archived: bool = config_field(
        default=False,
        env_var="EXAMPLE_INCLUDE_ARCHIVED",
        cli_flag="--include-archived",
        help="Include archived examples",
    )
    output_dir: Path = config_field(
        default=Path("out"),
        env_var="EXAMPLE_OUTPUT_DIR",
        cli_flag="--output-dir",
        metavar="PATH",
        help="Example output directory",
    )
    labels: tuple[str, ...] = config_field(
        default=(),
        env_var="EXAMPLE_LABELS",
        cli_flag="--labels",
        metavar="CSV",
        help="Example labels",
    )


class RequiredConfig(Config):
    """Config model with a required secret field."""

    token: str = config_field(
        default="",
        env_var="REQUIRED_TOKEN",
        cli_flag="--token",
        metavar="TOKEN",
        help="Required token",
        secret=True,
        required=True,
    )
    name: str = config_field(
        default="",
        env_var="REQUIRED_NAME",
        cli_flag="--name",
        metavar="NAME",
        help="Non-secret required config name",
    )


class MultilineHelpConfig(Config):
    """Config model with multiline CLI help text."""

    notes: str = config_field(
        default="",
        env_var="MULTILINE_HELP_NOTES",
        cli_flag="--notes",
        metavar="TEXT",
        help="First line.\nSecond line.\n  Indented detail.",
    )


class SnapshotOrderConfig(Config):
    """Config model whose field names and env-var names sort differently."""

    alpha: str = config_field(default="a", env_var="ZZZ_ALPHA")
    zulu: str = config_field(default="z", env_var="AAA_ZULU")


class BoundedConfig(Config):
    """Config model with numeric bounds."""

    page_size: int = config_field(
        default=25,
        env_var="BOUNDED_PAGE_SIZE",
        cli_flag="--page-size",
        metavar="N",
        ge=1,
    )
    sample_interval: float = config_field(
        default=10.0,
        env_var="BOUNDED_SAMPLE_INTERVAL",
        cli_flag="--sample-interval",
        metavar="SECS",
        ge=0,
    )


class PatternConfig(Config):
    """Config model with a string pattern constraint."""

    date: str | None = config_field(
        default=None,
        env_var="PATTERN_DATE",
        cli_flag="--date",
        metavar="YYYY-MM-DD",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class CommandStyleConfig(Config):
    """Config model with command-style flags."""

    get: bool = config_field(
        default=False,
        env_var="COMMAND_STYLE_GET",
        cli_flag="--get",
        cli_action="store_true",
    )
    verbose: bool = config_field(
        default=False,
        env_var="COMMAND_STYLE_VERBOSE",
        cli_flag="--verbose",
        cli_aliases=("-v",),
        cli_action="store_true",
    )
    schema_path: Path | None = config_field(
        default=None,
        env_var="COMMAND_STYLE_SCHEMA_PATH",
        cli_flag="--get-schema",
        cli_nargs="?",
        cli_const="schema.gql",
        metavar="FILE",
    )


class LinearExampleConfig(LinearClientConfig):
    """Config model composed from Linear client fields and app fields."""

    page_size: int = config_field(
        default=25,
        env_var="LINEAR_EXAMPLE_PAGE_SIZE",
        cli_flag="--page-size",
        metavar="N",
        help="Example page size",
    )


class SourcegraphExampleConfig(SourcegraphClientConfig):
    """Config model composed from Sourcegraph client fields and app fields."""

    repo_query: str = config_field(
        default="",
        env_var="SOURCEGRAPH_EXAMPLE_REPO_QUERY",
        cli_flag="--repo-query",
        metavar="QUERY",
        help="Example Sourcegraph repository query",
    )


class LoggingExampleConfig(LoggingConfig):
    """Config model composed from shared logging fields."""


class ConfigTest(unittest.TestCase):
    def test_load_config_env_file_uses_dotenv_parser(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "\n".join(
                    (
                        "# comment",
                        "export EXAMPLE_TOKEN='quoted token'",
                        "EXAMPLE_PAGE_SIZE=10 # inline comment",
                        "EXAMPLE_OUTPUT_DIR=${EXAMPLE_TOKEN}/out",
                        "BARE_KEY",
                    )
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                load_config_env_file(env_file),
                {
                    "EXAMPLE_TOKEN": "quoted token",
                    "EXAMPLE_PAGE_SIZE": "10",
                    "EXAMPLE_OUTPUT_DIR": "quoted token/out",
                },
            )

    def test_client_config_mixin_adds_linear_token_and_builds_client(self) -> None:
        parser = argparse.ArgumentParser()
        add_config_arguments(parser, LinearExampleConfig)
        args = parser.parse_args(["--linear-api-token", "test-token", "--page-size", "50"])

        config = load_config_from_args(
            LinearExampleConfig,
            args,
            env={},
            resolve_op_refs=False,
        )
        http = RecordingHTTP()
        client = linear_client_from_config(config, http=http)

        self.assertEqual(config.linear_api_token, "test-token")
        self.assertEqual(config.page_size, 50)
        self.assertEqual(client.token, "test-token")
        self.assertIs(client.http, http)

    def test_client_config_mixin_adds_sourcegraph_fields_and_builds_client(self) -> None:
        parser = argparse.ArgumentParser()
        add_config_arguments(parser, SourcegraphExampleConfig)
        args = parser.parse_args(
            [
                "--src-access-token",
                "test-token",
                "--repo-query",
                "repo:example",
            ]
        )

        config = load_config_from_args(
            SourcegraphExampleConfig,
            args,
            env={},
            resolve_op_refs=False,
        )
        client = sourcegraph_client_from_config(config)

        self.assertEqual(config.src_endpoint, "https://sourcegraph.com")
        self.assertEqual(config.src_access_token, "test-token")
        self.assertEqual(config.repo_query, "repo:example")
        self.assertEqual(client.endpoint, "https://sourcegraph.com")
        self.assertEqual(client.token, "test-token")

    def test_load_config_uses_precedence_and_pydantic_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base_dir = Path(directory)
            env_file = base_dir / ".env"
            env_file.write_text(
                "\n".join(
                    (
                        "EXAMPLE_TOKEN=op://vault/item/field",
                        "EXAMPLE_PAGE_SIZE=10",
                        "EXAMPLE_INCLUDE_ARCHIVED=false",
                        "EXAMPLE_OUTPUT_DIR=from-env-file",
                        "EXAMPLE_LABELS=op://vault/labels/value",
                    )
                ),
                encoding="utf-8",
            )

            config = load_config(
                ExampleConfig,
                env_file=env_file,
                env={
                    "EXAMPLE_PAGE_SIZE": "op://vault/page-size/value",
                    "EXAMPLE_OUTPUT_DIR": "from-shell",
                },
                cli_overrides={
                    "include_archived": True,
                    "output_dir": "from-cli",
                },
                base_dir=base_dir,
                resolve_op_refs=True,
                op_client=FakeOnePasswordClient(),
            )

            self.assertEqual(config.token, "resolved-secret")
            self.assertEqual(config.page_size, 40)
            self.assertTrue(config.include_archived)
            self.assertEqual(config.output_dir, base_dir / "from-cli")
            self.assertEqual(config.labels, ("gamma", "delta"))
            snapshot = config_snapshot(config)
            self.assertEqual(
                list(snapshot),
                [
                    "EXAMPLE_INCLUDE_ARCHIVED",
                    "EXAMPLE_LABELS",
                    "EXAMPLE_OUTPUT_DIR",
                    "EXAMPLE_PAGE_SIZE",
                    "EXAMPLE_TOKEN",
                ],
            )
            self.assertEqual(
                snapshot,
                {
                    "EXAMPLE_INCLUDE_ARCHIVED": True,
                    "EXAMPLE_LABELS": ["gamma", "delta"],
                    "EXAMPLE_OUTPUT_DIR": str(base_dir / "from-cli"),
                    "EXAMPLE_PAGE_SIZE": 40,
                    "EXAMPLE_TOKEN": "provided",
                },
            )

    def test_config_snapshot_sorts_emitted_keys(self) -> None:
        snapshot = config_snapshot(SnapshotOrderConfig())

        self.assertEqual(list(snapshot), ["AAA_ZULU", "ZZZ_ALPHA"])
        self.assertEqual(snapshot, {"AAA_ZULU": "z", "ZZZ_ALPHA": "a"})

    def test_argparse_helpers_add_flags_and_collect_overrides(self) -> None:
        parser = argparse.ArgumentParser()
        add_config_arguments(parser, ExampleConfig)

        args = parser.parse_args(
            [
                "--env-file",
                "custom.env",
                "--token",
                "raw-token",
                "--page-size",
                "50",
                "--no-include-archived",
                "--labels",
                "one,two",
            ]
        )

        self.assertEqual(config_env_file_from_args(args), Path("custom.env"))
        self.assertEqual(
            config_overrides_from_args(ExampleConfig, args),
            {
                "token": "raw-token",
                "page_size": "50",
                "include_archived": False,
                "labels": "one,two",
            },
        )

    def test_config_arguments_support_aliases_actions_and_optional_values(self) -> None:
        parser = argparse.ArgumentParser()
        add_config_arguments(parser, CommandStyleConfig)

        default_schema_args = parser.parse_args(["--get", "-v", "--get-schema"])
        named_schema_args = parser.parse_args(["--get-schema", "custom.gql"])

        default_schema_config = load_config_from_args(
            CommandStyleConfig,
            default_schema_args,
            env={},
            resolve_op_refs=False,
        )
        named_schema_config = load_config_from_args(
            CommandStyleConfig,
            named_schema_args,
            env={},
            resolve_op_refs=False,
        )

        self.assertTrue(default_schema_config.get)
        self.assertTrue(default_schema_config.verbose)
        self.assertEqual(default_schema_config.schema_path, Path.cwd() / "schema.gql")
        self.assertEqual(named_schema_config.schema_path, Path.cwd() / "custom.gql")

    def test_config_field_supports_numeric_bounds(self) -> None:
        config = load_config(
            BoundedConfig,
            env_file=None,
            env={"BOUNDED_PAGE_SIZE": "1", "BOUNDED_SAMPLE_INTERVAL": "0"},
            resolve_op_refs=False,
        )

        self.assertEqual(config.page_size, 1)
        self.assertEqual(config.sample_interval, 0)
        with self.assertRaisesRegex(ConfigError, "greater than or equal to 1"):
            load_config(
                BoundedConfig,
                env_file=None,
                env={"BOUNDED_PAGE_SIZE": "0"},
                resolve_op_refs=False,
            )
        with self.assertRaisesRegex(ConfigError, "greater than or equal to 0"):
            load_config(
                BoundedConfig,
                env_file=None,
                env={"BOUNDED_SAMPLE_INTERVAL": "-0.1"},
                resolve_op_refs=False,
            )

    def test_config_field_supports_string_pattern(self) -> None:
        config = load_config(
            PatternConfig,
            env_file=None,
            env={"PATTERN_DATE": "2026-01-31"},
            resolve_op_refs=False,
        )

        self.assertEqual(config.date, "2026-01-31")
        with self.assertRaisesRegex(ConfigError, "String should match pattern"):
            load_config(
                PatternConfig,
                env_file=None,
                env={"PATTERN_DATE": "2026-1-31"},
                resolve_op_refs=False,
            )
        with self.assertRaisesRegex(ConfigError, "String should match pattern"):
            load_config(
                PatternConfig,
                env_file=None,
                env={"PATTERN_DATE": "2026-01-31T00:00:00Z"},
                resolve_op_refs=False,
            )

    def test_logging_config_mixin_adds_log_level_from_cli_and_env(self) -> None:
        parser = argparse.ArgumentParser()
        add_config_arguments(parser, LoggingExampleConfig)
        args = parser.parse_args(["--src-log-level", "INFO", "-v"])

        cli_config = load_config_from_args(
            LoggingExampleConfig,
            args,
            env={"SRC_LOG_LEVEL": "WARNING"},
            resolve_op_refs=False,
        )
        env_config = load_config(
            LoggingExampleConfig,
            env_file=None,
            env={"SRC_LOG_LEVEL": "ERROR"},
            resolve_op_refs=False,
        )

        self.assertEqual(cli_config.src_log_level, "INFO")
        self.assertTrue(cli_config.verbose)
        self.assertEqual(env_config.src_log_level, "ERROR")

    def test_logging_config_rejects_multiple_log_level_alias(self) -> None:
        with self.assertRaisesRegex(ConfigError, "choose only one of --verbose"):
            load_config(
                LoggingExampleConfig,
                env_file=None,
                env={"SRC_LOG_VERBOSE": "true", "SRC_LOG_QUIET": "true"},
                resolve_op_refs=False,
            )

    def test_resolve_log_level_name_maps_cli_alias(self) -> None:
        self.assertEqual(resolve_log_level_name(verbose=True), "DEBUG")
        self.assertEqual(resolve_log_level_name(quiet=True), "WARNING")
        self.assertEqual(resolve_log_level_name(silent=True), "ERROR")
        self.assertEqual(resolve_log_level_name(log_level="trace"), "trace")
        self.assertIsNone(resolve_log_level_name(object()))

        config = LoggingExampleConfig(src_log_level="INFO")
        self.assertEqual(resolve_log_level_name(config), "INFO")
        verbose_config = LoggingExampleConfig(src_log_level="INFO", verbose=True)
        self.assertEqual(resolve_log_level_name(verbose_config), "DEBUG")
        quiet_config = config_parse_args(
            LoggingExampleConfig,
            argv=["-q"],
            env={},
            resolve_op_refs=False,
        )
        self.assertEqual(resolve_log_level_name(quiet_config), "WARNING")
        env_config = load_config(
            LoggingExampleConfig,
            env_file=None,
            env={"SRC_LOG_SILENT": "true"},
            resolve_op_refs=False,
        )
        self.assertTrue(env_config.silent)
        self.assertEqual(resolve_log_level_name(env_config), "ERROR")

    def test_logging_settings_from_config_maps_common_cli_levels(self) -> None:
        default_settings = logging_settings_from_config(
            resource_sample_interval_seconds=2.5,
        )
        self.assertEqual(default_settings.terminal_level, "INFO")
        self.assertEqual(default_settings.log_file_level, "debug")
        self.assertEqual(default_settings.resource_sample_interval_seconds, 2.5)

        quiet_config = LoggingExampleConfig(src_log_level="INFO", quiet=True)
        quiet_settings = logging_settings_from_config(quiet_config)
        self.assertEqual(quiet_settings.terminal_level, "WARNING")
        self.assertEqual(quiet_settings.log_file_level, "WARNING")

        log_level_config = LoggingExampleConfig(src_log_level="ERROR")
        log_level_settings = logging_settings_from_config(log_level_config)
        self.assertEqual(log_level_settings.terminal_level, "ERROR")
        self.assertEqual(log_level_settings.log_file_level, "ERROR")

    def test_config_parse_args_loads_config_and_reports_config_errors(self) -> None:
        config = config_parse_args(
            ExampleConfig,
            argv=["--token", "raw-token", "--page-size", "50"],
            env={},
            resolve_op_refs=False,
            description="Example CLI.",
        )

        self.assertEqual(config.token, "raw-token")
        self.assertEqual(config.page_size, 50)

        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            config_parse_args(RequiredConfig, argv=[], env={}, resolve_op_refs=False)

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("REQUIRED_TOKEN", stderr.getvalue())

    def test_config_parse_args_preserves_description_newlines_in_help(self) -> None:
        description = "Example CLI.\n\nSteps:\n  1. Collect data.\n  2. Export data."
        stdout = io.StringIO()

        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            config_parse_args(
                ExampleConfig,
                argv=["--help"],
                description=description,
                env={},
                resolve_op_refs=False,
            )

        self.assertEqual(raised.exception.code, 0)
        self.assertIn(description, stdout.getvalue())

    def test_config_parse_args_keeps_long_options_on_help_line(self) -> None:
        stdout = io.StringIO()

        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            config_parse_args(
                SourcegraphExampleConfig,
                argv=["--help"],
                env={},
                resolve_op_refs=False,
            )

        self.assertEqual(raised.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertNotIn("--src-access-token TOKEN\n", help_text)
        self.assertRegex(help_text, r"--src-access-token TOKEN +Sourcegraph access token")

    def test_config_parse_args_preserves_argument_help_newlines(self) -> None:
        stdout = io.StringIO()

        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            config_parse_args(
                MultilineHelpConfig,
                argv=["--help"],
                env={},
                resolve_op_refs=False,
            )

        self.assertEqual(raised.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertIn("First line.\n", help_text)
        self.assertRegex(help_text, r"\n +Second line\.\n")
        self.assertRegex(help_text, r"\n +  Indented detail\.")

    def test_config_field_requires_named_default(self) -> None:
        config_field_any: Any = config_field

        with self.assertRaises(TypeError):
            config_field_any("", env_var="POSITIONAL_DEFAULT")

    def test_required_values_and_reference_resolution(self) -> None:
        with self.assertRaisesRegex(ConfigError, "REQUIRED_TOKEN"):
            load_config(RequiredConfig, env_file=None, env={})

        config = load_config(
            RequiredConfig,
            env_file=None,
            env={
                "REQUIRED_TOKEN": "op://vault/item/field",
                "REQUIRED_NAME": "op://vault/name/value",
            },
        )
        resolved = resolve_config_refs(config, client=FakeOnePasswordClient())

        self.assertEqual(config.token, "op://vault/item/field")
        self.assertEqual(config.name, "op://vault/name/value")
        self.assertEqual(resolved.token, "resolved-secret")
        self.assertEqual(resolved.name, "resolved-name")


class GraphQLTest(unittest.TestCase):
    def test_introspect_schema_returns_schema_with_documentation_query(self) -> None:
        schema: JSONDict = {
            "description": "Example schema.",
            "queryType": {"name": "Query"},
            "types": [{"kind": "OBJECT", "name": "Query", "description": "Root query."}],
        }
        http = RecordingHTTP([{"data": {"__schema": schema}}])
        client = GraphQLClient("https://example.com/graphql", {}, "Example", http=http)

        self.assertEqual(introspect_schema(client), schema)
        body = json_dict(http.calls[0]["json_body"])
        query = str(body.get("query") or "")
        self.assertIn("description", query)
        self.assertIn("fields(includeDeprecated: true)", query)
        self.assertIn("inputFields", query)
        self.assertIn("enumValues(includeDeprecated: true)", query)
        self.assertIn("deprecationReason", query)
        self.assertNotIn("__schema {\n    description", query)
        self.assertNotIn("isRepeatable", query)
        self.assertNotIn("args(includeDeprecated: true)", query)

    def test_introspect_schema_writes_schema_file(self) -> None:
        schema: JSONDict = {
            "description": "Example schema.",
            "queryType": {"name": "Query"},
            "types": [{"kind": "OBJECT", "name": "Query"}],
        }
        seen: dict[str, str] = {}

        def execute(query: str) -> JSONDict:
            seen["query"] = query
            return {"__schema": schema}

        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "schema" / "schema.json"

            result = introspect_schema(execute, output_file=output_file)

            self.assertIsNone(result)
            self.assertIn("IntrospectionQuery", seen["query"])
            self.assertEqual(json.loads(output_file.read_text(encoding="utf-8")), schema)


class LoggingTest(unittest.TestCase):
    def test_default_log_file_uses_dashed_timestamp_offset_and_run(self) -> None:
        path = default_log_file(Path("logs"), run="1ea51330")

        self.assertEqual(path.parent, Path("logs"))
        self.assertRegex(
            path.name,
            r"^\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{4}-1ea51330\.json$",
        )

    def test_configure_logging_defaults_log_file_under_logs_dir(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            logs_dir = Path(directory) / "logs"
            logger_name = "src_py_lib_test_default_logs_dir"
            log_file = configure_logging(
                LoggingSettings(
                    logger_name=logger_name,
                    terminal_level="critical",
                    logs_dir=logs_dir,
                    run="test-run",
                )
            )
            try:
                info("default_log_path", logger_name=logger_name)
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            if log_file is None:
                self.fail("configure_logging did not return a default log file")
            self.assertEqual(log_file.parent, logs_dir)
            self.assertRegex(
                log_file.name,
                r"^\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{4}-test-run\.json$",
            )
            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            self.assertTrue(any(row.get("event") == "default_log_path" for row in rows))

    def test_src_log_level_env_controls_log_file_level(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            logger_name = "src_py_lib_test_log_level"
            with patch.dict("os.environ", {"SRC_LOG_LEVEL": "INFO"}):
                configure_logging(
                    LoggingSettings(
                        logger_name=logger_name,
                        terminal_level="critical",
                        log_file=log_file,
                        run="test-run",
                    )
                )
            try:
                debug("debug_event", logger_name=logger_name)
                info("info_event", logger_name=logger_name)
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            events = [row["event"] for row in rows]
            self.assertNotIn("debug_event", events)
            self.assertIn("info_event", events)

    def test_log_and_level_helpers_use_string_levels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            logger_name = "src_py_lib_test_string_levels"
            configure_logging(
                LoggingSettings(
                    logger_name=logger_name,
                    terminal_level="critical",
                    log_file_level="debug",
                    log_file=log_file,
                    run="test-run",
                )
            )
            try:
                log("bogus", "fallback_info", logger_name=logger_name)
                warning("warning_event", logger_name=logger_name)
                error("error_event", logger_name=logger_name)
                critical("critical_event", logger_name=logger_name)
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            levels = {row["event"]: row["level"] for row in rows}
            self.assertEqual(levels["fallback_info"], "INFO")
            self.assertEqual(levels["warning_event"], "WARNING")
            self.assertEqual(levels["error_event"], "ERROR")
            self.assertEqual(levels["critical_event"], "CRITICAL")

    def test_logging_configures_logging_context_and_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            logger_name = "src_py_lib_test_logging_context"
            config = ExampleConfig(token="secret-token")
            try:
                with src.logging(
                    config,
                    command="unit-test",
                    git_cwd=__file__,
                    logging_config=LoggingSettings(
                        logger_name=logger_name,
                        terminal_level="critical",
                        log_file=log_file,
                        run="test-run",
                    ),
                ) as context_log_file:
                    self.assertEqual(context_log_file, log_file)
                    info("inside_command", logger_name=logger_name)
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            startup = next(row for row in rows if row["event"] == "startup")
            inside = next(row for row in rows if row["event"] == "inside_command")
            self.assertEqual(startup["command"], "unit-test")
            self.assertEqual(startup["config"]["EXAMPLE_TOKEN"], "provided")
            self.assertEqual(inside["command"], "unit-test")

    def test_structured_log_file_includes_context_and_sanitized_terminal_omits_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            logger_name = "src_py_lib_test_logging"
            configure_logging(
                LoggingSettings(
                    logger_name=logger_name,
                    terminal_level="info",
                    log_file=log_file,
                    run="test-run",
                )
            )
            try:
                startup_event(
                    command="unit-test",
                    logger_name=logger_name,
                    git_commit="abc1234",
                )
                with log_context(command="unit-test"):
                    info("example", logger_name=logger_name, answer=42)
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            startup = next(row for row in rows if row["event"] == "startup")
            self.assertEqual(startup["git_commit"], "abc1234")
            self.assertFalse(any("git_commit" in row for row in rows if row["event"] != "startup"))
            self.assertEqual(
                list(rows[0]),
                ["ts", "level", "run", "logger", "event", "message"],
            )
            self.assertEqual(
                rows[0]["message"],
                f"Writing log events to {log_file}.",
            )
            self.assertEqual(
                list(startup),
                [
                    "ts",
                    "command",
                    "level",
                    "run",
                    "event",
                    "git_commit",
                    "log_file",
                ],
            )
            self.assertEqual(
                list(rows[-1]),
                ["ts", "command", "level", "run", "event", "answer"],
            )
            self.assertEqual(rows[-1]["event"], "example")
            self.assertEqual(rows[-1]["run"], "test-run")
            self.assertEqual(rows[-1]["command"], "unit-test")
            self.assertEqual(rows[-1]["answer"], 42)

    def test_event_context_adds_trace_and_span_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            logger_name = "src_py_lib_test_traces"
            configure_logging(
                LoggingSettings(
                    logger_name=logger_name,
                    terminal_level="info",
                    log_file=log_file,
                    run="test-run",
                )
            )
            try:
                with event("outer", logger_name=logger_name):
                    info("inside", logger_name=logger_name, answer=42)
                    with event("inner", logger_name=logger_name):
                        logging.getLogger(logger_name).info("inside nested span")
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            outer_start = next(
                row for row in rows if row["event"] == "outer" and row["phase"] == "start"
            )
            outer_end = next(
                row for row in rows if row["event"] == "outer" and row["phase"] == "end"
            )
            inside = next(row for row in rows if row["event"] == "inside")
            inner_start = next(
                row for row in rows if row["event"] == "inner" and row["phase"] == "start"
            )
            inner_end = next(
                row for row in rows if row["event"] == "inner" and row["phase"] == "end"
            )
            inner_log = next(row for row in rows if row.get("message") == "inside nested span")

            self.assertEqual(
                list(outer_start),
                ["ts", "level", "run", "trace", "span", "event", "phase"],
            )
            self.assertEqual(outer_start["trace"], outer_end["trace"])
            self.assertEqual(outer_start["span"], outer_end["span"])
            self.assertEqual(len(outer_start["trace"]), 8)
            self.assertEqual(len(outer_start["span"]), 8)
            self.assertNotIn("parent_span", outer_start)

            self.assertEqual(inside["trace"], outer_start["trace"])
            self.assertEqual(inside["span"], outer_start["span"])

            self.assertEqual(
                list(inner_start),
                [
                    "ts",
                    "level",
                    "run",
                    "trace",
                    "span",
                    "parent_span",
                    "event",
                    "phase",
                ],
            )
            self.assertEqual(inner_start["trace"], outer_start["trace"])
            self.assertEqual(inner_start["span"], inner_end["span"])
            self.assertEqual(len(inner_start["span"]), 8)
            self.assertEqual(inner_start["parent_span"], outer_start["span"])
            self.assertNotEqual(inner_start["span"], outer_start["span"])

            self.assertEqual(
                list(inner_log),
                [
                    "ts",
                    "level",
                    "run",
                    "trace",
                    "span",
                    "parent_span",
                    "logger",
                    "event",
                    "message",
                ],
            )
            self.assertEqual(inner_log["trace"], outer_start["trace"])
            self.assertEqual(inner_log["span"], inner_start["span"])
            self.assertEqual(inner_log["parent_span"], outer_start["span"])

    def test_event_can_lower_start_level_and_omit_success_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            logger_name = "src_py_lib_test_quiet_event"
            configure_logging(
                LoggingSettings(
                    logger_name=logger_name,
                    terminal_level="critical",
                    log_file_level="info",
                    log_file=log_file,
                    run="test-run",
                )
            )
            try:
                with event(
                    "quiet_start",
                    logger_name=logger_name,
                    level="info",
                    start_level="debug",
                    omit_success_status=True,
                ):
                    pass
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            quiet_rows = [row for row in rows if row["event"] == "quiet_start"]
            self.assertEqual(len(quiet_rows), 1)
            self.assertEqual(quiet_rows[0]["phase"], "end")
            self.assertNotIn("status", quiet_rows[0])
            self.assertNotIn("error_type", quiet_rows[0])

    def test_logging_context_emits_run_summary_resource_and_http_metrics(self) -> None:
        attempts = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, json={"retry": True}, headers={"Retry-After": "0"})
            return httpx.Response(200, json={"ok": True})

        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            try:
                with src.logging(
                    command="unit-test",
                    logging_config=LoggingSettings(
                        terminal_level="critical",
                        log_file_level="debug",
                        log_file=log_file,
                        run="test-run",
                        resource_sample_interval_seconds=0,
                    ),
                    run_fields={"endpoint": "https://example.com"},
                    run_summary=lambda: {"custom_count": 7},
                ):
                    client = HTTPClient(
                        max_attempts=2,
                        retry_base_delay_seconds=0,
                        retry_max_delay_seconds=0,
                        transport=httpx.MockTransport(handler),
                    )
                    self.assertEqual(
                        client.json(
                            "POST",
                            "https://example.com/api",
                            json_body={"hello": "world"},
                        ),
                        {"ok": True},
                    )
            finally:
                logger = logging.getLogger("")
                for handler_ in list(logger.handlers):
                    logger.removeHandler(handler_)
                    handler_.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            run_end = next(row for row in rows if row["event"] == "run" and row["phase"] == "end")
            self.assertEqual(run_end["status"], "ok")
            self.assertEqual(run_end["exit_code"], 0)
            self.assertEqual(run_end["endpoint"], "https://example.com")
            self.assertEqual(run_end["custom_count"], 7)
            self.assertEqual(run_end["http_request_attempt_count"], 2)
            self.assertEqual(run_end["http_retry_count"], 1)
            self.assertEqual(run_end["http_2xx_count"], 1)
            self.assertEqual(run_end["http_429_count"], 1)
            self.assertGreater(run_end["http_request_bytes_total"], 0)
            self.assertGreater(run_end["http_response_bytes_total"], 0)
            self.assertIn("cpu_count_logical", run_end)

    def test_logging_context_records_system_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            try:
                with (
                    self.assertRaises(SystemExit),
                    src.logging(
                        command="unit-test",
                        logging_config=LoggingSettings(
                            terminal_level="critical",
                            log_file_level="debug",
                            log_file=log_file,
                            run="test-run",
                        ),
                    ),
                ):
                    raise SystemExit(3)
            finally:
                logger = logging.getLogger("")
                for handler_ in list(logger.handlers):
                    logger.removeHandler(handler_)
                    handler_.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            run_end = next(row for row in rows if row["event"] == "run" and row["phase"] == "end")
            self.assertEqual(run_end["status"], "error")
            self.assertEqual(run_end["error_type"], "SystemExit")
            self.assertEqual(run_end["exit_code"], 3)

    def test_httpx_request_logs_are_debug_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            logger_name = "httpx"
            configure_logging(
                LoggingSettings(
                    logger_name=logger_name,
                    terminal_level="critical",
                    log_file_level="debug",
                    log_file=log_file,
                    run="test-run",
                )
            )
            try:
                logging.getLogger(logger_name).info(
                    'HTTP Request: POST https://api.linear.app/graphql "HTTP/1.1 200 OK"'
                )
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            request_log = next(
                row for row in rows if row.get("message", "").startswith("HTTP Request:")
            )
            self.assertEqual(request_log["level"], "DEBUG")

    def test_httpcore_response_headers_are_structured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            logger_name = "httpcore"
            configure_logging(
                LoggingSettings(
                    logger_name=logger_name,
                    terminal_level="info",
                    log_file_level="debug",
                    log_file=log_file,
                    run="test-run",
                )
            )
            try:
                logging.getLogger("httpcore.http11").debug(
                    "receive_response_headers.complete "
                    "return_value=(b'HTTP/1.1', 200, b'OK', "
                    "[(b'Zed', b'last'), (b'Content-Type', b'application/json'), "
                    "(b'Alpha', b'first')])"
                )
            finally:
                logger = logging.getLogger(logger_name)
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            response_headers = next(
                row for row in rows if row.get("message") == "receive_response_headers.complete"
            )

            self.assertEqual(response_headers["logger"], "httpcore.http11")
            self.assertEqual(response_headers["http_version"], "HTTP/1.1")
            self.assertEqual(response_headers["status_code"], 200)
            self.assertEqual(response_headers["reason_phrase"], "OK")
            self.assertEqual(list(response_headers["headers"]), ["alpha", "content-type", "zed"])
            self.assertEqual(
                response_headers["headers"],
                {
                    "alpha": "first",
                    "content-type": "application/json",
                    "zed": "last",
                },
            )


class HTTPClientTest(unittest.TestCase):
    def test_json_request_adds_query_headers_and_decodes_object(self) -> None:
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["authorization"] = request.headers["Authorization"]
            seen["user_agent"] = request.headers["User-Agent"]
            seen["body"] = request.content
            return httpx.Response(200, json={"ok": True})

        client = HTTPClient(
            timeout=12,
            max_attempts=1,
            max_connections=7,
            transport=httpx.MockTransport(handler),
        )
        payload = client.json(
            "POST",
            "https://example.com/api",
            headers={"Authorization": "Bearer token"},
            query={"limit": 10, "skip": None},
            json_body={"hello": "world"},
        )

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(seen["url"], "https://example.com/api?limit=10")
        self.assertEqual(seen["authorization"], "Bearer token")
        self.assertEqual(seen["user_agent"], "src-py-lib")
        self.assertEqual(json.loads(seen["body"]), {"hello": "world"})
        self.assertEqual(client.max_connections, 7)

    def test_json_request_emits_structured_http_event(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"ok": True},
                headers={
                    "Zed": "last",
                    "Content-Type": "application/json",
                    "Set-Cookie": "session=secret",
                },
            )

        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            configure_logging(
                LoggingSettings(
                    terminal_level="critical",
                    log_file_level="debug",
                    log_file=log_file,
                    run="test-run",
                )
            )
            try:
                client = HTTPClient(max_attempts=1, transport=httpx.MockTransport(handler))
                payload = client.json(
                    "POST",
                    "https://example.com/api",
                    headers={"Authorization": "Bearer token"},
                    json_body={"hello": "world"},
                )
            finally:
                logger = logging.getLogger("")
                for handler_ in list(logger.handlers):
                    logger.removeHandler(handler_)
                    handler_.close()

            self.assertEqual(payload, {"ok": True})
            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            http_request = next(
                row
                for row in rows
                if row.get("event") == "http_request" and row.get("phase") == "end"
            )

            self.assertFalse(any(row.get("logger") in {"httpx", "httpcore"} for row in rows))
            self.assertEqual(http_request["status_code"], 200)
            self.assertEqual(http_request["reason_phrase"], "OK")
            self.assertEqual(http_request["request_bytes"], len(b'{"hello": "world"}'))
            self.assertEqual(http_request["request_headers"]["authorization"], "[redacted]")
            self.assertEqual(
                list(http_request["response_headers"]), sorted(http_request["response_headers"])
            )
            self.assertEqual(http_request["response_headers"]["content-type"], "application/json")
            self.assertEqual(http_request["response_headers"]["set-cookie"], "[redacted]")
            self.assertEqual(http_request["response_headers"]["zed"], "last")

    def test_json_request_wraps_timeouts(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("read timed out")

        client = HTTPClient(
            timeout=12,
            max_attempts=1,
            transport=httpx.MockTransport(handler),
        )

        with self.assertRaisesRegex(HTTPClientError, "read timed out"):
            client.json("POST", "https://example.com/api")

    def test_json_request_wraps_http_errors_with_body(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, text="rate limited", headers={"Retry-After": "0"})

        client = HTTPClient(
            max_attempts=1,
            transport=httpx.MockTransport(handler),
        )

        with self.assertRaisesRegex(HTTPClientError, "rate limited") as raised:
            client.json("GET", "https://example.com/api")

        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(raised.exception.body, "rate limited")


class ClientTest(unittest.TestCase):
    def test_normalize_sourcegraph_endpoint(self) -> None:
        self.assertEqual(
            normalize_sourcegraph_endpoint(" https://sourcegraph.example.com/ "),
            "https://sourcegraph.example.com",
        )
        self.assertEqual(
            normalize_sourcegraph_endpoint("http://localhost:3080/"),
            "http://localhost:3080",
        )
        with self.assertRaisesRegex(ValueError, "https:// URL"):
            normalize_sourcegraph_endpoint("http://localhost:3080", require_https=True)
        with self.assertRaisesRegex(ValueError, "http:// or https:// URL"):
            normalize_sourcegraph_endpoint("sourcegraph.example.com")

    def test_sourcegraph_client_builds_graphql_request(self) -> None:
        http = RecordingHTTP([{"data": {"currentUser": {"username": "alice"}}}])
        client = SourcegraphClient(" https://sourcegraph.example.com/ ", "token", http=http)
        data = client.graphql("query Viewer { currentUser { username } }")

        self.assertEqual(client.endpoint, "https://sourcegraph.example.com")
        self.assertEqual(data, {"currentUser": {"username": "alice"}})
        self.assertEqual(http.calls[0]["method"], "POST")
        self.assertEqual(http.calls[0]["url"], "https://sourcegraph.example.com/.api/graphql")
        self.assertEqual(http.calls[0]["headers"], {"Authorization": "token token"})

    def test_sourcegraph_client_streams_connection_nodes(self) -> None:
        http = RecordingHTTP(
            [
                {
                    "data": {
                        "users": {
                            "nodes": [{"username": "alice"}],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                        }
                    }
                },
                {
                    "data": {
                        "users": {
                            "nodes": [{"username": "bob"}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                },
            ]
        )
        client = SourcegraphClient("https://sourcegraph.example.com", "token", http=http)
        nodes = list(
            client.stream_connection_nodes(
                """
                query Users($first: Int, $after: String) {
                    users(first: $first, after: $after) {
                        nodes { username }
                        pageInfo { hasNextPage endCursor }
                    }
                }
                """,
                connection_path=("users",),
                page_size=1,
            )
        )

        self.assertEqual(nodes, [{"username": "alice"}, {"username": "bob"}])
        first_body = json_dict(http.calls[0]["json_body"])
        second_body = json_dict(http.calls[1]["json_body"])
        self.assertEqual(first_body["variables"], {"first": 1, "after": None})
        self.assertEqual(second_body["variables"], {"first": 1, "after": "cursor-1"})

    def test_sourcegraph_client_validate_queries_current_user(self) -> None:
        http = RecordingHTTP([{"data": {"currentUser": {"username": "alice"}}}])
        client = SourcegraphClient("https://sourcegraph.example.com/", "token", http=http)

        self.assertEqual(client.validate(), {"username": "alice"})
        body = json_dict(http.calls[0]["json_body"])
        self.assertIn("SourcegraphClientValidate", str(body.get("query") or ""))
        self.assertIn("currentUser", str(body.get("query") or ""))

    def test_graphql_client_paginates_cursor_results(self) -> None:
        http = RecordingHTTP(
            [
                {
                    "data": {
                        "viewer": {
                            "items": {
                                "nodes": [{"id": "1"}],
                                "pageInfo": {
                                    "hasNextPage": True,
                                    "endCursor": "cursor-1",
                                },
                            }
                        }
                    }
                },
                {
                    "data": {
                        "viewer": {
                            "items": {
                                "nodes": [{"id": "2"}],
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                },
            ]
        )
        client = GraphQLClient("https://example.com/graphql", {}, "Example", http=http)
        query = """
query Items($first: Int!, $after: String, $userId: ID!) {
  viewer { items { nodes { id } pageInfo { hasNextPage endCursor } } }
}
"""

        data = client.execute(
            query,
            variables={"userId": "u1"},
            page_size=2,
        )
        nodes = json_list(json_dict(json_dict(data.get("viewer")).get("items")).get("nodes"))

        self.assertEqual(nodes, [{"id": "1"}, {"id": "2"}])
        self.assertEqual(
            http.calls[0]["json_body"]["variables"],
            {"userId": "u1", "first": 2, "after": None},
        )
        self.assertEqual(
            http.calls[1]["json_body"]["variables"],
            {"userId": "u1", "first": 2, "after": "cursor-1"},
        )

    def test_graphql_client_streams_connection_nodes(self) -> None:
        http = RecordingHTTP(
            [
                {
                    "data": {
                        "viewer": {
                            "items": {
                                "nodes": [{"id": "1"}],
                                "pageInfo": {
                                    "hasNextPage": True,
                                    "endCursor": "cursor-1",
                                },
                            }
                        }
                    }
                },
                {
                    "data": {
                        "viewer": {
                            "items": {
                                "nodes": [{"id": "2"}],
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                },
            ]
        )
        client = GraphQLClient("https://example.com/graphql", {}, "Example", http=http)
        query = """
query Items($first: Int!, $after: String, $userId: ID!) {
  viewer { items { nodes { id } pageInfo { hasNextPage endCursor } } }
}
"""

        nodes = list(
            client.stream_connection_nodes(
                query,
                variables={"userId": "u1"},
                connection_path=("viewer", "items"),
                page_size=2,
            )
        )

        self.assertEqual(nodes, [{"id": "1"}, {"id": "2"}])
        self.assertEqual(
            http.calls[0]["json_body"]["variables"],
            {"userId": "u1", "first": 2, "after": None},
        )
        self.assertEqual(
            http.calls[1]["json_body"]["variables"],
            {"userId": "u1", "first": 2, "after": "cursor-1"},
        )

    def test_stream_connection_nodes_accepts_execute_callback(self) -> None:
        calls: list[dict[str, Any]] = []
        responses: list[JSONDict] = [
            {
                "viewer": {
                    "items": {
                        "nodes": [{"id": "1"}],
                        "pageInfo": {
                            "hasNextPage": True,
                            "endCursor": "cursor-1",
                        },
                    }
                }
            },
            {
                "viewer": {
                    "items": {
                        "nodes": [{"id": "2"}],
                        "pageInfo": {
                            "hasNextPage": False,
                            "endCursor": None,
                        },
                    }
                }
            },
        ]

        def execute(query: str, variables: Mapping[str, Any] | None) -> JSONDict:
            calls.append({"query": query, "variables": dict(variables or {})})
            return responses.pop(0)

        query = """
query Items($first: Int!, $after: String, $userId: ID!) {
  viewer { items { nodes { id } pageInfo { hasNextPage endCursor } } }
}
"""

        nodes = list(
            stream_connection_nodes(
                execute,
                query,
                variables={"userId": "u1"},
                connection_path=("viewer", "items"),
                page_size=2,
            )
        )

        self.assertEqual(nodes, [{"id": "1"}, {"id": "2"}])
        self.assertEqual(
            [call["variables"] for call in calls],
            [
                {"userId": "u1", "first": 2, "after": None},
                {"userId": "u1", "first": 2, "after": "cursor-1"},
            ],
        )

    def test_graphql_client_emits_query_debug_events(self) -> None:
        http = RecordingHTTP(
            [
                {
                    "data": {
                        "viewer": {
                            "items": {
                                "nodes": [{"id": "1"}],
                                "pageInfo": {
                                    "hasNextPage": True,
                                    "endCursor": "cursor-1",
                                },
                            }
                        }
                    }
                },
                {
                    "data": {
                        "viewer": {
                            "items": {
                                "nodes": [{"id": "2"}],
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                },
            ]
        )
        client = GraphQLClient("https://example.com/graphql", {}, "Example", http=http)
        query = """
query Items($first: Int!, $after: String, $userId: ID!) {
  viewer { items { nodes { id } pageInfo { hasNextPage endCursor } } }
}
"""

        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "events.json"
            configure_logging(
                LoggingSettings(
                    terminal_level="critical",
                    log_file_level="debug",
                    log_file=log_file,
                    run="test-run",
                )
            )
            try:
                client.execute(query, variables={"userId": "u1"}, page_size=2)
            finally:
                logger = logging.getLogger("")
                for handler in list(logger.handlers):
                    logger.removeHandler(handler)
                    handler.close()

            rows = [json.loads(line) for line in log_file.read_text().splitlines()]
            starts = [
                row
                for row in rows
                if row.get("event") == "graphql_query" and row.get("phase") == "start"
            ]
            ends = [
                row
                for row in rows
                if row.get("event") == "graphql_query" and row.get("phase") == "end"
            ]

            self.assertEqual([row["query_name"] for row in starts], ["Items", "Items"])
            self.assertEqual([row["page_number"] for row in starts], [1, 2])
            self.assertEqual([row["page_size"] for row in starts], [2, 2])
            self.assertEqual([row["cursor_present"] for row in starts], [False, True])
            self.assertEqual(starts[0]["graphql_client"], "Example")
            self.assertEqual(starts[0]["variable_names"], ["after", "first", "userId"])
            self.assertEqual(ends[0]["response_fields"], ["viewer"])

    def test_graphql_client_requires_end_cursor_for_next_page(self) -> None:
        http = RecordingHTTP(
            [
                {
                    "data": {
                        "items": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": True, "endCursor": None},
                        }
                    }
                }
            ]
        )
        client = GraphQLClient("https://example.com/graphql", {}, "Example", http=http)
        query = """
query Items($first: Int!, $after: String) {
  items { nodes { id } pageInfo { hasNextPage endCursor } }
}
"""

        with self.assertRaisesRegex(GraphQLError, "endCursor"):
            client.execute(
                query,
                page_size=100,
            )

    def test_graphql_client_rejects_stalled_cursor(self) -> None:
        http = RecordingHTTP(
            [
                {
                    "data": {
                        "items": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                        }
                    }
                },
                {
                    "data": {
                        "items": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                        }
                    }
                },
            ]
        )
        client = GraphQLClient("https://example.com/graphql", {}, "Example", http=http)
        query = """
query Items($first: Int!, $after: String) {
  items { nodes { id } pageInfo { hasNextPage endCursor } }
}
"""

        with self.assertRaisesRegex(GraphQLError, "stalled"):
            client.execute(
                query,
                page_size=100,
            )

    def test_graphql_client_preserves_http_status_on_transport_errors(self) -> None:
        class FailingHTTP(RecordingHTTP):
            def json(
                self,
                method: str,
                url: str,
                *,
                headers: Mapping[str, str] | None = None,
                query: Mapping[str, str | int | float | bool | None] | None = None,
                json_body: object | None = None,
            ) -> dict[str, Any]:
                raise HTTPClientError("unavailable", status_code=503)

        client = GraphQLClient("https://example.com/graphql", {}, "Example", http=FailingHTTP())

        with self.assertRaises(GraphQLError) as raised:
            client.execute("query Viewer { viewer { login } }", follow_pages=False)

        self.assertEqual(raised.exception.status_code, 503)
        self.assertFalse(raised.exception.is_application_error)

    def test_graphql_client_marks_application_errors(self) -> None:
        http = RecordingHTTP(
            [
                {
                    "data": {},
                    "errors": [{"message": "field does not exist"}],
                }
            ]
        )
        client = GraphQLClient("https://example.com/graphql", {}, "Example", http=http)

        with self.assertRaises(GraphQLError) as raised:
            client.execute("query Broken { missingField }", follow_pages=False)

        self.assertIsNone(raised.exception.status_code)
        self.assertTrue(raised.exception.is_application_error)

    def test_github_pr_ref_from_url(self) -> None:
        self.assertEqual(
            pr_ref_from_url("https://github.com/sourcegraph/amp/pull/1234"),
            "sourcegraph/amp#1234",
        )

    def test_github_client_defaults_to_github_dot_com(self) -> None:
        http = RecordingHTTP()
        client = GitHubClient("token", http=http)
        client.graphql("query Viewer { viewer { login } }")

        self.assertEqual(http.calls[0]["url"], "https://api.github.com/graphql")

    def test_github_client_can_target_github_enterprise(self) -> None:
        http = RecordingHTTP()
        client = GitHubClient("token", github_url="https://github.example.com", http=http)
        client.graphql("query Viewer { viewer { login } }")

        self.assertEqual(http.calls[0]["url"], "https://github.example.com/api/graphql")
        self.assertEqual(
            graphql_api_url("github.example.com"), "https://github.example.com/api/graphql"
        )

    def test_github_client_validate_queries_viewer(self) -> None:
        http = RecordingHTTP([{"data": {"viewer": {"login": "alice"}}}])
        client = GitHubClient("token", http=http)

        self.assertEqual(client.validate(), {"login": "alice"})
        body = json_dict(http.calls[0]["json_body"])
        self.assertIn("GitHubClientValidate", str(body.get("query") or ""))

    def test_slack_client_validate_calls_auth_test(self) -> None:
        response = {"ok": True, "url": "https://example.slack.com/", "user_id": "U1"}
        http = RecordingHTTP([response])
        client = SlackClient("token", http=http)

        self.assertEqual(client.validate(), response)
        self.assertEqual(http.calls[0]["url"], "https://slack.com/api/auth.test")
        self.assertEqual(http.calls[0]["headers"], {"Authorization": "Bearer token"})

    def test_google_sheets_client_validate_fetches_metadata(self) -> None:
        metadata = {"sheets": [{"properties": {"sheetId": 1, "title": "Sheet1"}}]}
        http = RecordingHTTP([metadata])
        client = GoogleSheetsClient("spreadsheet-id", "token", quota_project="quota", http=http)

        self.assertEqual(client.validate(), metadata)
        self.assertEqual(
            http.calls[0]["url"],
            "https://sheets.googleapis.com/v4/spreadsheets/spreadsheet-id"
            "?fields=sheets.properties(sheetId,title,gridProperties)",
        )
        self.assertEqual(
            http.calls[0]["headers"],
            {"Authorization": "Bearer token", "X-Goog-User-Project": "quota"},
        )

    def test_one_password_client_validate_returns_authenticated_account(self) -> None:
        with patch("src_py_lib.clients.one_password.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                ["op", "whoami", "--format", "json"],
                0,
                stdout='{ "email": "alice@example.com", "account_uuid": "A1" }\n',
                stderr="",
            )

            self.assertEqual(
                OnePasswordClient().validate(),
                {"email": "alice@example.com", "account_uuid": "A1"},
            )

        run.assert_called_once_with(
            ["op", "whoami", "--format", "json"],
            check=True,
            text=True,
            capture_output=True,
        )

    def test_one_password_client_validate_requires_authentication(self) -> None:
        with patch("src_py_lib.clients.one_password.subprocess.run") as run:
            run.side_effect = subprocess.CalledProcessError(
                1,
                ["op", "whoami", "--format", "json"],
                stderr="not signed in",
            )

            with self.assertRaisesRegex(OnePasswordError, "not authenticated"):
                OnePasswordClient().validate()

    def test_one_password_client_signin_runs_signin_then_validates(self) -> None:
        with patch("src_py_lib.clients.one_password.subprocess.run") as run:
            run.side_effect = [
                subprocess.CompletedProcess(["op", "signin"], 0),
                subprocess.CompletedProcess(
                    ["op", "whoami", "--format", "json"],
                    0,
                    stdout='{ "email": "alice@example.com" }\n',
                    stderr="",
                ),
            ]

            self.assertEqual(
                OnePasswordClient().signin(),
                {"email": "alice@example.com"},
            )

        self.assertEqual(run.call_count, 2)
        run.assert_any_call(["op", "signin"], check=True)
        run.assert_any_call(
            ["op", "whoami", "--format", "json"],
            check=True,
            text=True,
            capture_output=True,
        )

    def test_linear_client_builds_graphql_request(self) -> None:
        http = RecordingHTTP()
        with patch("src_py_lib.clients.linear.GraphQLClient") as client_cls:
            client_cls.return_value.execute.return_value = {
                "viewer": {"email": "alice@example.com"}
            }
            data = LinearClient("token", http=http).graphql(
                "query Viewer { viewer { email } }",
                {"first": 1},
                page_size=10,
            )

        self.assertEqual(data, {"viewer": {"email": "alice@example.com"}})
        client_cls.assert_called_once_with(
            url="https://api.linear.app/graphql",
            headers={"Authorization": "token"},
            label="Linear",
            http=http,
        )
        client_cls.return_value.execute.assert_called_once_with(
            "query Viewer { viewer { email } }",
            variables={"first": 1},
            page_size=10,
        )

    def test_linear_client_validate_queries_viewer(self) -> None:
        http = RecordingHTTP([{"data": {"viewer": {"email": "alice@example.com"}}}])
        client = LinearClient("token", http=http)

        self.assertEqual(client.validate(), {"email": "alice@example.com"})
        body = json_dict(http.calls[0]["json_body"])
        self.assertIn("LinearClientValidate", str(body.get("query") or ""))
        self.assertNotIn("\n    id\n", str(body.get("query") or ""))
        self.assertEqual(http.calls[0]["headers"], {"Authorization": "token"})

    def test_linear_client_validate_requires_viewer_email(self) -> None:
        http = RecordingHTTP([{"data": {"viewer": {}}}])
        client = LinearClient("token", http=http)

        with self.assertRaisesRegex(RuntimeError, "viewer.email"):
            client.validate()

    def test_linear_client_list_users_paginates(self) -> None:
        http = RecordingHTTP(
            [
                {
                    "data": {
                        "users": {
                            "nodes": [{"id": "U1", "name": "Alice"}],
                            "pageInfo": {
                                "hasNextPage": True,
                                "endCursor": "cursor-1",
                            },
                        }
                    }
                },
                {
                    "data": {
                        "users": {
                            "nodes": [{"id": "U2", "name": "Bob"}],
                            "pageInfo": {
                                "hasNextPage": False,
                                "endCursor": None,
                            },
                        }
                    }
                },
            ]
        )

        users = LinearClient("token", http=http).list_users(page_size=25)

        self.assertEqual([user["id"] for user in users], ["U1", "U2"])
        first_body = json_dict(http.calls[0]["json_body"])
        second_body = json_dict(http.calls[1]["json_body"])
        self.assertEqual(
            json_dict(first_body.get("variables")),
            {"first": 25, "after": None},
        )
        self.assertEqual(
            json_dict(second_body.get("variables")),
            {"first": 25, "after": "cursor-1"},
        )

    def test_json_cache_helpers_round_trip_and_parse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "cache.json"

            src.save_json_cache(path, {"b": {"name": "Bob"}, "a": {"name": "Alice"}})
            parsed = src.load_json_cache(path, parse=lambda value: str(value.get("name", "")))
            subset = src.load_json_subset(path, ["a", "missing"], parse=lambda value: value)

        self.assertEqual(parsed, {"a": "Alice", "b": "Bob"})
        self.assertEqual(subset, {"a": {"name": "Alice"}})

    def test_resolve_op_secret_ref_leaves_raw_values_alone(self) -> None:
        self.assertEqual(resolve_op_secret_ref(" raw-secret "), "raw-secret")

    def test_resolve_op_secret_ref_uses_one_password_client_for_refs(self) -> None:
        self.assertEqual(
            resolve_op_secret_ref("op://vault/item/field", client=FakeOnePasswordClient()),
            "resolved-secret",
        )

    def test_resolve_op_secret_ref_rejects_empty_values(self) -> None:
        with self.assertRaises(OnePasswordError):
            resolve_op_secret_ref("  ")


if __name__ == "__main__":
    unittest.main()
