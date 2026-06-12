"""
src-auth-perms-sync uses metadata from auth providers to set:
- Explicit repo permissions
- Organizations and memberships

See https://github.com/sourcegraph/src-auth-perms-sync/blob/main/README.md for usage instructions

"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import importlib.metadata
import logging
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, NoReturn, TypeAlias, cast

import src_py_lib as src
from src_py_lib.utils import config as config_utils

from .orgs import command as organizations_command
from .permissions import command as permissions_command
from .permissions import maps as permissions_maps
from .permissions import types as permission_types
from .shared import backups, run_context, site_config

log = logging.getLogger(__name__)


CommandName: TypeAlias = Literal["get", "set", "restore", "sync_saml_orgs"]
COMMON_CONFIG_FIELDS_BEFORE = src.config_field_names(
    src.SourcegraphClientConfig,
)
COMMON_CONFIG_FIELDS_AFTER = src.config_field_names(
    src.LoggingConfig,
    src.OpenTelemetryConfig,
    "parallelism",
    "http_timeout_seconds",
    "max_attempts",
    "sample_interval",
    "fetch_sg_traces",
)
GET_CONFIG_FIELDS = src.config_field_names(
    *COMMON_CONFIG_FIELDS_BEFORE,
    "maps_path",
    "users",
    "users_without_explicit_perms",
    "created_after",
    "repos",
    "repos_without_explicit_perms",
    "repos_created_after",
    "no_backup",
    "artifacts_dir",
    "no_files",
    "explicit_permissions_batch_size",
    *COMMON_CONFIG_FIELDS_AFTER,
)
SET_CONFIG_FIELDS = src.config_field_names(
    *COMMON_CONFIG_FIELDS_BEFORE,
    "maps_path",
    "full",
    "users",
    "users_without_explicit_perms",
    "created_after",
    "repos",
    "repos_without_explicit_perms",
    "repos_created_after",
    "sync_saml_organizations",
    "apply",
    "no_backup",
    "artifacts_dir",
    "no_files",
    "explicit_permissions_batch_size",
    *COMMON_CONFIG_FIELDS_AFTER,
)
RESTORE_CONFIG_FIELDS = src.config_field_names(
    *COMMON_CONFIG_FIELDS_BEFORE,
    "restore_path",
    "apply",
    "no_backup",
    "artifacts_dir",
    "no_files",
    "explicit_permissions_batch_size",
    *COMMON_CONFIG_FIELDS_AFTER,
)
SYNC_SAML_ORGS_CONFIG_FIELDS = src.config_field_names(
    *COMMON_CONFIG_FIELDS_BEFORE,
    "apply",
    "no_backup",
    "artifacts_dir",
    "no_files",
    "parallelism",
    *COMMON_CONFIG_FIELDS_AFTER,
)
LogCommandName: TypeAlias = Literal[
    "get",
    "set_full",
    "set_users",
    "set_users_without_explicit_perms",
    "set_created_after",
    "set_repos",
    "set_repos_without_explicit_perms",
    "set_repos_created_after",
    "restore",
    "sync_saml_orgs",
    "set_full_sync_saml_orgs",
    "set_users_sync_saml_orgs",
    "set_users_without_explicit_perms_sync_saml_orgs",
    "set_created_after_sync_saml_orgs",
    "set_repos_sync_saml_orgs",
    "set_repos_without_explicit_perms_sync_saml_orgs",
    "set_repos_created_after_sync_saml_orgs",
]

SET_COMMAND_LOG_NAMES: dict[permission_types.SetCommandMode, LogCommandName] = {
    "full": "set_full",
    "users": "set_users",
    "users_without_explicit_perms": "set_users_without_explicit_perms",
    "created_after": "set_created_after",
    "repos": "set_repos",
    "repos_without_explicit_perms": "set_repos_without_explicit_perms",
    "repos_created_after": "set_repos_created_after",
}
SET_COMMAND_ARTIFACT_NAMES: dict[permission_types.SetCommandMode, str] = {
    "full": "set-{run_mode}",
    "users": "set-add-users-{run_mode}",
    "users_without_explicit_perms": "set-add-users-without-explicit-perms-{run_mode}",
    "created_after": "set-add-users-created-after-{run_mode}",
    "repos": "set-repos-{run_mode}",
    "repos_without_explicit_perms": "set-repos-without-explicit-perms-{run_mode}",
    "repos_created_after": "set-repos-created-after-{run_mode}",
}
SYNC_SET_COMMAND_LOG_NAMES: dict[permission_types.SetCommandMode, LogCommandName] = {
    "full": "set_full_sync_saml_orgs",
    "users": "set_users_sync_saml_orgs",
    "users_without_explicit_perms": "set_users_without_explicit_perms_sync_saml_orgs",
    "created_after": "set_created_after_sync_saml_orgs",
    "repos": "set_repos_sync_saml_orgs",
    "repos_without_explicit_perms": "set_repos_without_explicit_perms_sync_saml_orgs",
    "repos_created_after": "set_repos_created_after_sync_saml_orgs",
}
SYNC_SET_COMMAND_ARTIFACT_NAMES: dict[permission_types.SetCommandMode, str] = {
    "full": "set-sync-saml-orgs-{run_mode}",
    "users": "set-add-users-sync-saml-orgs-{run_mode}",
    "users_without_explicit_perms": (
        "set-add-users-without-explicit-perms-sync-saml-orgs-{run_mode}"
    ),
    "created_after": "set-add-users-created-after-sync-saml-orgs-{run_mode}",
    "repos": "set-repos-sync-saml-orgs-{run_mode}",
    "repos_without_explicit_perms": ("set-repos-without-explicit-perms-sync-saml-orgs-{run_mode}"),
    "repos_created_after": "set-repos-created-after-sync-saml-orgs-{run_mode}",
}


@dataclass(frozen=True)
class ResolvedCommand:
    """Validated command facts derived from operator config."""

    name: CommandName
    log_name: LogCommandName
    artifact_name: str
    set_options: permission_types.SetCommandOptions | None = None
    sync_saml_organizations: bool = False

    @property
    def set_mode(self) -> permission_types.SetCommandMode | None:
        """Return the concrete set mode when this is a set command."""
        if self.set_options is None:
            return None
        return self.set_options.mode


@dataclass(frozen=True)
class CliInput:
    """Parsed CLI command and runtime config."""

    command_name: CommandName
    config: Config


@dataclass(frozen=True)
class CliCommand:
    """Argparse subcommand metadata."""

    argument_name: str
    command_name: CommandName
    help: str
    description: str
    config_fields: tuple[str, ...]


class Config(src.SourcegraphClientConfig, src.LoggingConfig, src.OpenTelemetryConfig):
    """Config values loaded from defaults, .env, environment, and CLI flags."""

    maps_path: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_MAPS_PATH",
        cli_flag="--maps-path",
        metavar="FILE",
        help=(
            "Maps YAML file for the get and set commands\n"
            "(default: <artifacts-dir>/<src-endpoint>/maps.yaml)\n"
            "Relative paths are resolved from the current working directory"
        ),
        help_group="Permission sync",
    )
    artifacts_dir: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_ARTIFACTS_DIR",
        cli_flag="--artifacts-dir",
        metavar="DIR",
        help=(
            "Directory containing per-endpoint artifact directories\n"
            "(default: ./src-auth-perms-sync-runs)\n"
            "Relative paths are resolved from the current working directory"
        ),
        help_group="Artifacts",
    )
    no_files: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_NO_FILES",
        cli_flag="--no-files",
        cli_action="store_true",
        help=(
            "Write nothing to disk: no generated YAML, snapshots, or log file\n"
            "With --apply, also requires --no-backup (explicitly giving up restore)"
        ),
        help_group="Artifacts",
    )
    restore_path: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_RESTORE_PATH",
        cli_flag="--restore-path",
        metavar="FILE",
        help=(
            "Snapshot JSON file for the restore command\n"
            "Relative paths are resolved from the current working directory"
        ),
        help_group="Restore",
    )
    full: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_FULL",
        cli_flag="--full",
        cli_action="store_true",
        help=(
            "Full overwrite of all explicit perms for the repos in scope\n"
            "Must be passed explicitly when no user or repo filter args are provided"
        ),
        help_group="Permission sync",
    )
    users: tuple[str, ...] = src.config_field(
        default=(),
        env_var="SRC_AUTH_PERMS_SYNC_USERS",
        cli_flag="--users",
        metavar="USERS",
        help="Process a comma-delimited list of Sourcegraph usernames and/or email addresses",
        help_group="User filters",
    )
    users_without_explicit_perms: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_USERS_WITHOUT_EXPLICIT_PERMS",
        cli_flag="--users-without-explicit-perms",
        cli_action="store_true",
        help="Process Sourcegraph users without explicit permissions",
        help_group="User filters",
    )
    created_after: str | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_CREATED_AFTER",
        cli_flag="--created-after",
        metavar="YYYY-MM-DD",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        help="Process Sourcegraph users created on or after this date",
        help_group="User filters",
    )
    repos: tuple[str, ...] = src.config_field(
        default=(),
        env_var="SRC_AUTH_PERMS_SYNC_REPOS",
        cli_flag="--repos",
        metavar="REPOS",
        help="Process a comma-delimited list of Sourcegraph repository names",
        help_group="Repo filters",
    )
    repos_without_explicit_perms: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_REPOS_WITHOUT_EXPLICIT_PERMS",
        cli_flag="--repos-without-explicit-perms",
        cli_action="store_true",
        help="Process repositories without explicit permissions",
        help_group="Repo filters",
    )
    repos_created_after: str | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_REPOS_CREATED_AFTER",
        cli_flag="--repos-created-after",
        metavar="YYYY-MM-DD",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        help="Process repositories cloned to the Sourcegraph instance on or after this date",
        help_group="Repo filters",
    )
    sync_saml_organizations: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_SYNC_SAML_ORGS",
        cli_flag="--sync-saml-orgs",
        cli_action="store_true",
        help="Create/update Sourcegraph organizations for each discovered SAML group",
        help_group="Organization sync",
    )
    apply: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_APPLY",
        cli_flag="--apply",
        cli_action="store_true",
        help="Apply changes (default is dry run)",
        help_group="Mutation",
    )
    no_backup: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_NO_BACKUP",
        cli_flag="--no-backup",
        cli_action="store_true",
        help="Skip before/after snapshot artifacts and validation where supported",
        help_group="Mutation",
    )
    parallelism: int = src.config_field(
        default=16,
        env_var="SRC_AUTH_PERMS_SYNC_PARALLELISM",
        cli_flag="--parallelism",
        metavar="N",
        ge=1,
        help="Concurrent Sourcegraph API worker threads (default: 16)",
        help_group="Performance",
    )
    explicit_permissions_batch_size: int = src.config_field(
        default=25,
        env_var="SRC_AUTH_PERMS_SYNC_EXPLICIT_PERMISSIONS_BATCH_SIZE",
        cli_flag="--explicit-permissions-batch-size",
        metavar="N",
        ge=1,
        help=(
            "Users per GraphQL request when capturing explicit repository permissions (default: 25)"
        ),
        help_group="Performance",
    )
    max_attempts: int = src.config_field(
        default=5,
        env_var="SRC_AUTH_PERMS_SYNC_MAX_ATTEMPTS",
        cli_flag="--max-attempts",
        metavar="N",
        ge=1,
        help="Max attempts per HTTP request before giving up (default: 5)",
        help_group="Performance",
    )
    http_timeout_seconds: float = src.config_field(
        default=300.0,
        env_var="SRC_AUTH_PERMS_SYNC_HTTP_TIMEOUT_SECONDS",
        cli_flag="--http-timeout-seconds",
        metavar="SECONDS",
        gt=0,
        help="HTTP read timeout per request in seconds (default: 300)",
        help_group="Performance",
    )
    sample_interval: float = src.config_field(
        default=10.0,
        env_var="SRC_AUTH_PERMS_SYNC_SAMPLE_INTERVAL",
        cli_flag="--sample-interval",
        metavar="SECONDS",
        ge=0,
        help="Seconds between logging compute resource samples; set 0 to disable (default: 10)",
        help_group="Performance",
    )
    fetch_sg_traces: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_FETCH_SG_TRACES",
        cli_flag="--fetch-sg-traces",
        cli_action="store_true",
        help="Ask Sourcegraph to retain GraphQL traces and return debug trace metadata",
        help_group="Performance",
    )


CLI_COMMANDS: tuple[CliCommand, ...] = (
    CliCommand(
        argument_name="get",
        command_name="get",
        help="Discover auth providers and code hosts",
        description="Gather auth providers, code hosts, users, and permissions.",
        config_fields=GET_CONFIG_FIELDS,
    ),
    CliCommand(
        argument_name="set",
        command_name="set",
        help="Reconcile repo permissions from maps.yaml",
        description="Reconcile Sourcegraph explicit repo permissions from maps.yaml.",
        config_fields=SET_CONFIG_FIELDS,
    ),
    CliCommand(
        argument_name="restore",
        command_name="restore",
        help="Restore repo permissions from a snapshot",
        description="Restore Sourcegraph explicit repo permissions from a snapshot JSON file.",
        config_fields=RESTORE_CONFIG_FIELDS,
    ),
    CliCommand(
        argument_name="sync-saml-orgs",
        command_name="sync_saml_orgs",
        help="Sync orgs from SAML groups",
        description="Create/update Sourcegraph organizations and memberships from SAML groups.",
        config_fields=SYNC_SAML_ORGS_CONFIG_FIELDS,
    ),
)


def config_error(message: str) -> NoReturn:
    """Exit with a concise config/argument error."""
    print(f"src-auth-perms-sync: error: {message}", file=sys.stderr)
    raise SystemExit(2)


def validate_config(command_name: CommandName, config: Config) -> None:
    """Validate cross-field CLI/config constraints."""
    validate_command_options(command_name, config)
    validate_user_filter_selection(command_name, config)
    validate_repository_filter_selection(command_name, config)
    validate_set_mode_selection(command_name, config)


def validate_command_options(command_name: CommandName, config: Config) -> None:
    """Validate options that only make sense with specific commands."""
    if command_name == "get" and config.apply:
        config_error("--apply cannot be used with the read-only get command")
    if config.sync_saml_organizations and command_name != "set":
        config_error("--sync-saml-orgs can only be combined with set")
    if command_name == "restore" and config.restore_path is None:
        config_error("restore requires --restore-path")
    if config.restore_path is not None and command_name != "restore":
        config_error("--restore-path requires the restore command")
    if config.maps_path is not None and command_name not in {"get", "set"}:
        config_error("--maps-path requires the get or set command")
    if config.no_files and config.apply and not config.no_backup:
        config_error(
            "--no-files with --apply also requires --no-backup: without files there "
            "are no before/after snapshots, so say explicitly that you are giving "
            "up the restore path"
        )


def validate_user_filter_selection(command_name: CommandName, config: Config) -> None:
    """Validate user-scope filters and their compatible commands."""
    user_scope_filter_count = sum((bool(config.users), config.users_without_explicit_perms))
    if user_scope_filter_count > 1:
        config_error("choose only one of --users or --users-without-explicit-perms")

    user_filter_selected = user_scope_filter_count > 0 or config.created_after is not None
    user_filter_allowed = command_name in {"get", "set"}
    if user_filter_selected and not user_filter_allowed:
        config_error(
            "--users, --users-without-explicit-perms, and --created-after require get or set"
        )


def validate_repository_filter_selection(command_name: CommandName, config: Config) -> None:
    """Validate repo-scope filters and their compatible commands."""
    repository_filter_count = sum(
        (
            bool(config.repos),
            config.repos_without_explicit_perms,
            config.repos_created_after is not None,
        )
    )
    if repository_filter_count > 1:
        config_error(
            "choose only one of --repos, --repos-without-explicit-perms, or --repos-created-after"
        )

    repository_filter_selected = repository_filter_count > 0
    repository_filter_allowed = command_name in {"get", "set"}
    if repository_filter_selected and not repository_filter_allowed:
        config_error(
            "--repos, --repos-without-explicit-perms, and --repos-created-after require get or set"
        )

    user_filter_selected = any(
        (bool(config.users), config.users_without_explicit_perms, config.created_after is not None)
    )
    if repository_filter_selected and user_filter_selected:
        config_error("choose either user filters or repo filters, not both")


def validate_set_mode_selection(command_name: CommandName, config: Config) -> None:
    """Validate set command mode flags."""
    if config.full and command_name != "set":
        config_error("--full requires the set command")

    if command_name != "set":
        return

    if config.full and config.created_after is not None:
        config_error(
            "--full cannot be combined with --created-after because full mode "
            "overwrites mapped repos; omit --full to add grants for new users"
        )

    if (
        sum(
            (
                config.full,
                bool(config.users),
                config.users_without_explicit_perms,
                bool(config.repos),
                config.repos_without_explicit_perms,
                config.repos_created_after is not None,
            )
        )
        > 1
    ):
        config_error(
            "with set, choose at most one of --full, --users, "
            "--users-without-explicit-perms, --repos, "
            "--repos-without-explicit-perms, or --repos-created-after"
        )

    set_mode_selected = any(
        (
            config.full,
            bool(config.users),
            config.users_without_explicit_perms,
            config.created_after is not None,
            bool(config.repos),
            config.repos_without_explicit_perms,
            config.repos_created_after is not None,
        )
    )
    if not set_mode_selected:
        config_error(
            "set requires one of --full, --users, --users-without-explicit-perms, "
            "--created-after, --repos, --repos-without-explicit-perms, or "
            "--repos-created-after"
        )


def set_command_options(config: Config) -> permission_types.SetCommandOptions:
    """Return the validated set mode options."""
    if config.users:
        return permission_types.SetCommandOptions(
            mode="users",
            user_identifiers=config.users,
            user_created_after=config.created_after,
        )
    if config.users_without_explicit_perms:
        return permission_types.SetCommandOptions(
            mode="users_without_explicit_perms",
            user_created_after=config.created_after,
        )
    if config.created_after is not None:
        return permission_types.SetCommandOptions(
            mode="created_after",
            user_created_after=config.created_after,
        )
    if config.repos:
        return permission_types.SetCommandOptions(
            mode="repos",
            repository_names=config.repos,
        )
    if config.repos_without_explicit_perms:
        return permission_types.SetCommandOptions(
            mode="repos_without_explicit_perms",
        )
    if config.repos_created_after is not None:
        return permission_types.SetCommandOptions(
            mode="repos_created_after",
            repository_created_after=config.repos_created_after,
        )
    return permission_types.SetCommandOptions(
        mode="full",
    )


def resolve_command(command_name: CommandName, config: Config) -> ResolvedCommand:
    """Return the command execution plan derived from config."""
    run_mode = "apply" if config.apply else "dry-run"
    if command_name == "set":
        return resolve_set_command(config, run_mode)
    if command_name == "restore":
        return ResolvedCommand(
            name="restore",
            log_name="restore",
            artifact_name=f"restore-{run_mode}",
        )
    if command_name == "get":
        return ResolvedCommand(name="get", log_name="get", artifact_name="get")
    return ResolvedCommand(
        name="sync_saml_orgs",
        log_name="sync_saml_orgs",
        artifact_name=f"sync-saml-orgs-{run_mode}",
        sync_saml_organizations=True,
    )


def resolve_set_command(config: Config, run_mode: str) -> ResolvedCommand:
    """Return resolved metadata for the selected set command mode."""
    set_options = set_command_options(config)
    log_names = (
        SYNC_SET_COMMAND_LOG_NAMES if config.sync_saml_organizations else SET_COMMAND_LOG_NAMES
    )
    artifact_names = (
        SYNC_SET_COMMAND_ARTIFACT_NAMES
        if config.sync_saml_organizations
        else SET_COMMAND_ARTIFACT_NAMES
    )
    return ResolvedCommand(
        name="set",
        log_name=log_names[set_options.mode],
        artifact_name=artifact_names[set_options.mode].format(run_mode=run_mode),
        set_options=set_options,
        sync_saml_organizations=config.sync_saml_organizations,
    )


def load_cli(argv: Sequence[str] | None = None) -> CliInput:
    """Parse and validate the CLI command plus environment/config options."""
    parser = argparse.ArgumentParser(
        description=__doc__.strip() if __doc__ is not None else None,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(
        title="commands",
        metavar="COMMAND",
        dest="command_argument",
        required=True,
    )
    for command in CLI_COMMANDS:
        command_parser = subparsers.add_parser(
            command.argument_name,
            help=command.help,
            description=command.description,
            formatter_class=config_utils.config_help_formatter(
                Config,
                include_fields=command.config_fields,
            ),
            allow_abbrev=False,
        )
        command_parser.set_defaults(command_name=command.command_name)
        config_utils.add_config_arguments(
            command_parser,
            Config,
            include_fields=command.config_fields,
        )
    arguments = parser.parse_args(argv)
    try:
        config = config_utils.load_config_from_args(
            Config,
            arguments,
            base_dir=Path("."),
            resolve_op_refs=True,
        )
    except src.ConfigError as exception:
        parser.error(str(exception))
    command_name = cast(CommandName, arguments.command_name)
    validate_config(command_name, config)
    if command_name == "restore":
        assert config.restore_path is not None
        require_restore_input_file(config.restore_path)
    return CliInput(command_name=command_name, config=config)


def require_set_input_file(maps_path: Path) -> None:
    """Exit with a clear error if the selected maps file is missing."""
    if maps_path.is_file():
        return
    if maps_path.exists():
        raise SystemExit(f"set input path is not a file: {maps_path}")
    raise SystemExit(
        "set input file does not exist: "
        f"{maps_path}\n"
        "Run `uv run src-auth-perms-sync get` to create the default maps.yaml, "
        "or pass a path to an existing maps file."
    )


def require_restore_input_file(restore_path: Path) -> None:
    """Exit with a clear error if the selected restore snapshot is missing."""
    if restore_path.is_file():
        return
    if restore_path.exists():
        raise SystemExit(f"restore snapshot path is not a file: {restore_path}")
    raise SystemExit(f"restore snapshot file does not exist: {restore_path}")


def run_fields(
    config: Config,
    command: ResolvedCommand,
    endpoint: str,
    run_paths: backups.RunPaths,
) -> dict[str, object]:
    """Return run-level fields for structured logging."""
    fields: dict[str, object] = {
        "endpoint": endpoint,
        "parallelism": config.parallelism,
        "explicit_permissions_batch_size": config.explicit_permissions_batch_size,
        "fetch_sg_traces": config.fetch_sg_traces,
        "open_telemetry": config.open_telemetry,
        "max_attempts": config.max_attempts,
        "http_timeout_seconds": config.http_timeout_seconds,
        "sample_interval": config.sample_interval,
        "artifacts_dir": str(run_paths.endpoint_directory),
        "run_directory": str(run_paths.run_directory),
    }
    if command.name != "get":
        fields["apply"] = config.apply
    if config.no_backup:
        fields["no_backup"] = True
    if config.no_files:
        fields["no_files"] = True
    if command.set_mode is not None:
        fields["set_mode"] = command.set_mode
    if command.sync_saml_organizations:
        fields["sync_saml_orgs"] = True
    if config.created_after is not None:
        fields["created_after"] = config.created_after
    if config.repos:
        fields["repos"] = config.repos
    if config.repos_without_explicit_perms:
        fields["repos_without_explicit_perms"] = True
    if config.repos_created_after is not None:
        fields["repos_created_after"] = config.repos_created_after
    return fields


def run_with_client(
    config: Config,
    command: ResolvedCommand,
    endpoint: str,
    run_paths: backups.RunPaths,
    worker_pool: ThreadPoolExecutor,
) -> run_context.CommandData:
    """Create a client, run the selected command, and always close HTTP resources."""
    http = src.HTTPClient(
        timeout=config.http_timeout_seconds,
        user_agent="src-auth-perms-sync/0.1 (+python)",
        max_attempts=config.max_attempts,
        max_connections=config.parallelism,
    )
    client = src.SourcegraphClient(
        endpoint=endpoint,
        token=config.src_access_token,
        http=http,
        fetch_sg_traces=config.fetch_sg_traces,
    )
    try:
        return run_command(config, command, client, run_paths, worker_pool)
    finally:
        client.http.close()


def run_command(
    config: Config,
    command: ResolvedCommand,
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    worker_pool: ThreadPoolExecutor,
) -> run_context.CommandData:
    """Dispatch the selected command."""
    sourcegraph_site_config = site_config.validate_site_config(client)
    command_data = run_context.CommandData()
    if command.name == "get":
        command_data = run_get(config, client, sourcegraph_site_config, run_paths, worker_pool)
    elif command.name == "set":
        command_data = run_set(
            config, command, client, sourcegraph_site_config, run_paths, worker_pool
        )
    elif command.name == "restore":
        run_restore(config, client, sourcegraph_site_config, run_paths, worker_pool)
        return command_data
    else:
        run_sync_saml_organizations(
            config,
            client,
            sourcegraph_site_config,
            command_data,
            run_paths,
            worker_pool,
        )
        return command_data

    if command.sync_saml_organizations:
        run_sync_saml_organizations(
            config,
            client,
            sourcegraph_site_config,
            command_data,
            run_paths,
            worker_pool,
        )
    return command_data


def run_set(
    config: Config,
    command: ResolvedCommand,
    client: src.SourcegraphClient,
    sourcegraph_site_config: site_config.SiteConfig,
    run_paths: backups.RunPaths,
    worker_pool: ThreadPoolExecutor,
) -> run_context.CommandData:
    """Run the selected repo-permission sync command."""
    assert command.set_options is not None
    require_set_input_file(run_paths.maps_path)
    return permissions_command.cmd_set(
        client,
        run_paths,
        command.set_options,
        dry_run=not config.apply,
        parallelism=config.parallelism,
        explicit_permissions_batch_size=config.explicit_permissions_batch_size,
        bind_id_mode=sourcegraph_site_config.bind_id_mode,
        saml_groups_attribute_name_by_config_id=(
            sourcegraph_site_config.saml_groups_attribute_name_by_config_id
        ),
        do_backup=not config.no_backup,
        retain_saml_group_users=command.sync_saml_organizations,
        worker_pool=worker_pool,
    )


def run_restore(
    config: Config,
    client: src.SourcegraphClient,
    sourcegraph_site_config: site_config.SiteConfig,
    run_paths: backups.RunPaths,
    worker_pool: ThreadPoolExecutor,
) -> None:
    """Run the selected repo-permission restore command."""
    assert config.restore_path is not None
    require_restore_input_file(config.restore_path)
    permissions_command.cmd_restore(
        client,
        config.restore_path,
        run_paths,
        dry_run=not config.apply,
        parallelism=config.parallelism,
        explicit_permissions_batch_size=config.explicit_permissions_batch_size,
        bind_id_mode=sourcegraph_site_config.bind_id_mode,
        do_backup=not config.no_backup,
        worker_pool=worker_pool,
    )


def run_sync_saml_organizations(
    config: Config,
    client: src.SourcegraphClient,
    sourcegraph_site_config: site_config.SiteConfig,
    command_data: run_context.CommandData,
    run_paths: backups.RunPaths,
    worker_pool: ThreadPoolExecutor,
) -> None:
    """Run the selected SAML organization sync command."""
    organizations_command.cmd_sync_saml_organizations(
        client,
        run_paths,
        dry_run=not config.apply,
        parallelism=config.parallelism,
        saml_groups_attribute_name_by_config_id=(
            sourcegraph_site_config.saml_groups_attribute_name_by_config_id
        ),
        do_backup=not config.no_backup,
        command_data=command_data,
        worker_pool=worker_pool,
    )


def run_get(
    config: Config,
    client: src.SourcegraphClient,
    sourcegraph_site_config: site_config.SiteConfig,
    run_paths: backups.RunPaths,
    worker_pool: ThreadPoolExecutor,
) -> run_context.CommandData:
    """Run the default read-only discovery command."""
    maps_created = False
    if run_paths.write_files:
        maps_created = permissions_maps.create_maps_yaml_if_missing(run_paths.maps_path)
        if maps_created:
            log.info("maps.yaml missing, created %s with an empty maps list.", run_paths.maps_path)
        else:
            log.info("Left existing %s unchanged.", run_paths.maps_path)
    else:
        log.info("Skipping maps.yaml creation because --no-files is set.")

    command_data = permissions_command.cmd_get(
        client,
        run_paths,
        user_identifiers=config.users,
        users_without_explicit_perms=config.users_without_explicit_perms,
        user_created_after=config.created_after,
        repository_names=config.repos,
        repositories_without_explicit_perms=config.repos_without_explicit_perms,
        repository_created_after=config.repos_created_after,
        parallelism=config.parallelism,
        explicit_permissions_batch_size=config.explicit_permissions_batch_size,
        bind_id_mode=sourcegraph_site_config.bind_id_mode,
        saml_groups_attribute_name_by_config_id=(
            sourcegraph_site_config.saml_groups_attribute_name_by_config_id
        ),
        auth_providers_by_config_id=sourcegraph_site_config.auth_providers_by_config_id,
        do_backup=not config.no_backup,
        retain_saml_group_users=False,
        worker_pool=worker_pool,
    )
    return dataclasses.replace(command_data, maps_created=maps_created)


def reraise_system_exit_with_logged_error(exception: SystemExit) -> NoReturn:
    """Log string SystemExit messages inside the structured logging context."""
    if isinstance(exception.code, str):
        log.error("%s", exception.code)
        raise SystemExit(1) from exception
    raise exception


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one module-mode command run."""

    succeeded: bool
    paths: backups.RunPaths | None = None

    def __bool__(self) -> bool:
        return self.succeeded


@dataclass(frozen=True)
class GetResult:
    """Outcome of one discovery run, carrying the discovered data in memory.

    `auth_providers` and `code_hosts` hold the same dicts written to
    `auth-providers.yaml` and `code-hosts.yaml`, so module callers can
    assemble mapping rules without re-parsing files.
    """

    succeeded: bool
    paths: backups.RunPaths | None = None
    auth_providers: tuple[dict[str, Any], ...] = ()
    code_hosts: tuple[dict[str, Any], ...] = ()
    maps_created: bool = False

    def __bool__(self) -> bool:
        return self.succeeded


def Get(config: Config, *, event_sink: src.EventSink | None = None) -> GetResult:
    """Run repository permission discovery; returns data and paths in memory."""
    succeeded, command_data, run_paths = _run("get", config, event_sink)
    if not succeeded or command_data is None:
        return GetResult(succeeded=succeeded, paths=run_paths)
    return GetResult(
        succeeded=True,
        paths=run_paths,
        auth_providers=tuple(command_data.auth_provider_views or ()),
        code_hosts=tuple(command_data.code_host_views or ()),
        maps_created=command_data.maps_created,
    )


def Set(config: Config, *, event_sink: src.EventSink | None = None) -> CommandResult:
    """Run repository permission reconciliation."""
    succeeded, _, run_paths = _run("set", config, event_sink)
    return CommandResult(succeeded=succeeded, paths=run_paths)


def Restore(config: Config, *, event_sink: src.EventSink | None = None) -> CommandResult:
    """Run repository permission restore."""
    succeeded, _, run_paths = _run("restore", config, event_sink)
    return CommandResult(succeeded=succeeded, paths=run_paths)


def SyncSamlOrgs(config: Config, *, event_sink: src.EventSink | None = None) -> CommandResult:
    """Run SAML organization sync."""
    succeeded, _, run_paths = _run("sync_saml_orgs", config, event_sink)
    return CommandResult(succeeded=succeeded, paths=run_paths)


def _run(
    command_name: CommandName,
    config: Config,
    event_sink: src.EventSink | None,
) -> tuple[bool, run_context.CommandData | None, backups.RunPaths | None]:
    """Run a module-mode command, reporting success instead of raising."""
    try:
        command_data, run_paths = _run_or_raise(command_name, config, event_sink=event_sink)
    except SystemExit as exception:
        return exception.code in (None, 0), None, None
    except Exception:
        log.exception("src-auth-perms-sync run failed.")
        return False, None, None
    return True, command_data, run_paths


def _package_version() -> str:
    try:
        return importlib.metadata.version("src-auth-perms-sync")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _module_event_sink(
    stack: contextlib.ExitStack,
    run_paths: backups.RunPaths,
    event_sink: src.EventSink | None,
) -> src.EventSink | None:
    """Compose the module-mode sink: JSONL run log plus optional caller sink."""
    sinks: list[src.EventSink] = []
    if run_paths.write_files:
        sinks.append(stack.enter_context(src.JSONLEventSink(run_paths.log_path)))
    if event_sink is not None:
        sinks.append(event_sink)
    if not sinks:
        return None
    if len(sinks) == 1:
        return sinks[0]
    return src.CompositeEventSink(tuple(sinks))


def _run_or_raise(
    command_name: CommandName,
    config: Config,
    *,
    cli_mode: bool = False,
    event_sink: src.EventSink | None = None,
) -> tuple[run_context.CommandData, backups.RunPaths]:
    """Run src-auth-perms-sync, preserving CLI-style exceptions.

    CLI mode installs terminal and event-bridge handlers on this package's
    loggers; module mode never touches stdlib logging handlers, so the host
    application's logging configuration stays in charge.
    """
    validate_config(command_name, config)
    command = resolve_command(command_name, config)
    try:
        endpoint = src.normalize_sourcegraph_endpoint(config.src_endpoint)
    except ValueError as error:
        config_error(str(error))
    run_paths = backups.resolve_run_paths(
        endpoint=endpoint,
        command_artifact_name=command.artifact_name,
        artifacts_dir=config.artifacts_dir,
        maps_path=config.maps_path,
        write_files=not config.no_files,
    )
    fields = run_fields(config, command, endpoint, run_paths)
    resource = {
        "service.name": "src-auth-perms-sync",
        "service.version": _package_version(),
    }
    open_telemetry_settings = src.open_telemetry_settings_from_config(
        config,
        force_traces=config.fetch_sg_traces,
        service_name="src-auth-perms-sync",
    )

    with contextlib.ExitStack() as stack:
        if cli_mode:
            logging_settings = src.logging_settings_from_config(
                config,
                logger_names=("src_auth_perms_sync", "src_py_lib"),
                log_file=run_paths.log_path if run_paths.write_files else None,
                logs_dir=None,
                resource_sample_interval_seconds=config.sample_interval,
                open_telemetry=open_telemetry_settings,
            )
            stack.enter_context(
                src.logging(
                    config,
                    command=command.name,
                    git_cwd=__file__,
                    logging_config=logging_settings,
                    run_fields=fields,
                    resource=resource,
                )
            )
        else:
            stack.enter_context(
                src.observability_context(
                    command.name,
                    config,
                    sink=_module_event_sink(stack, run_paths, event_sink),
                    git_cwd=__file__,
                    run_fields=fields,
                    resource=resource,
                    open_telemetry=open_telemetry_settings,
                    resource_sample_interval_seconds=config.sample_interval,
                    log_file=run_paths.log_path if run_paths.write_files else None,
                )
            )
        worker_pool = stack.enter_context(run_context.thread_pool(config.parallelism))
        try:
            command_data = run_with_client(config, command, endpoint, run_paths, worker_pool)
        except SystemExit as exception:
            reraise_system_exit_with_logged_error(exception)
        return command_data, run_paths


def main() -> None:
    cli_input = load_cli()
    _run_or_raise(cli_input.command_name, cli_input.config, cli_mode=True)
