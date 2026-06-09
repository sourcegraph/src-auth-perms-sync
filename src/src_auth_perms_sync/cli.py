"""
src-auth-perms-sync uses metadata from auth providers to set:
- Explicit repo permissions
- Organizations and memberships

See https://github.com/sourcegraph/src-auth-perms-sync/blob/main/README.md for usage instructions

"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, NoReturn, TypeAlias, cast

import src_py_lib as src
from src_py_lib.utils import config as config_utils

from .orgs import command as organizations_command
from .permissions import command as permissions_command
from .permissions import maps as permissions_maps
from .permissions import types as permission_types
from .shared import backups, run_context, site_config

log = logging.getLogger(__name__)


CommandName: TypeAlias = Literal["get", "set", "restore", "sync_saml_orgs"]
DEFAULT_MAPS_FILE_NAME = "maps.yaml"
COMMON_CONFIG_FIELDS = src.config_field_names(
    src.SourcegraphClientConfig,
    src.LoggingConfig,
    src.OpenTelemetryConfig,
    "parallelism",
    "http_timeout_seconds",
    "max_attempts",
    "sample_interval",
    "fetch_sg_traces",
)
GET_CONFIG_FIELDS = src.config_field_names(
    "users",
    "users_without_explicit_perms",
    "created_after",
    "no_backup",
    "explicit_permissions_batch_size",
    *COMMON_CONFIG_FIELDS,
)
SET_CONFIG_FIELDS = src.config_field_names(
    "maps_path",
    "full",
    "users",
    "users_without_explicit_perms",
    "created_after",
    "sync_saml_organizations",
    "apply",
    "no_backup",
    "explicit_permissions_batch_size",
    *COMMON_CONFIG_FIELDS,
)
RESTORE_CONFIG_FIELDS = src.config_field_names(
    "restore_path",
    "apply",
    "no_backup",
    "explicit_permissions_batch_size",
    *COMMON_CONFIG_FIELDS,
)
SYNC_SAML_ORGS_CONFIG_FIELDS = src.config_field_names(
    "apply",
    "no_backup",
    *COMMON_CONFIG_FIELDS,
)
LogCommandName: TypeAlias = Literal[
    "get",
    "set_full",
    "set_users",
    "set_users_without_explicit_perms",
    "restore",
    "sync_saml_orgs",
    "set_full_sync_saml_orgs",
    "set_users_sync_saml_orgs",
    "set_users_without_explicit_perms_sync_saml_orgs",
]

SET_COMMAND_LOG_NAMES: dict[permission_types.SetCommandMode, LogCommandName] = {
    "full": "set_full",
    "users": "set_users",
    "users_without_explicit_perms": "set_users_without_explicit_perms",
}
SET_COMMAND_ARTIFACT_NAMES: dict[permission_types.SetCommandMode, str] = {
    "full": "set-{run_mode}",
    "users": "set-add-users-{run_mode}",
    "users_without_explicit_perms": "set-add-users-without-explicit-perms-{run_mode}",
}
SYNC_SET_COMMAND_LOG_NAMES: dict[permission_types.SetCommandMode, LogCommandName] = {
    "full": "set_full_sync_saml_orgs",
    "users": "set_users_sync_saml_orgs",
    "users_without_explicit_perms": "set_users_without_explicit_perms_sync_saml_orgs",
}
SYNC_SET_COMMAND_ARTIFACT_NAMES: dict[permission_types.SetCommandMode, str] = {
    "full": "set-sync-saml-orgs-{run_mode}",
    "users": "set-add-users-sync-saml-orgs-{run_mode}",
    "users_without_explicit_perms": (
        "set-add-users-without-explicit-perms-sync-saml-orgs-{run_mode}"
    ),
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
            "Maps YAML file for the set command.\n"
            "If omitted, set uses maps.yaml under src-auth-perms-sync-runs/<endpoint>/.\n"
            "Relative paths are resolved from the current working directory."
        ),
        help_group="Permission sync",
    )
    restore_path: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_RESTORE_PATH",
        cli_flag="--restore-path",
        metavar="FILE",
        help=(
            "Snapshot JSON file for the restore command.\n"
            "Relative paths are resolved from the current working directory."
        ),
        help_group="Restore",
    )
    full: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_FULL",
        cli_flag="--full",
        cli_action="store_true",
        help="With the set command: run the full overwrite reconciliation mode (default)",
        help_group="Permission sync",
    )
    users: tuple[str, ...] = src.config_field(
        default=(),
        env_var="SRC_AUTH_PERMS_SYNC_USERS",
        cli_flag="--users",
        metavar="USERS",
        help="Process comma-delimited Sourcegraph usernames and/or email addresses",
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
        help="With mutating commands: actually mutate state. Default is dry-run",
        help_group="Mutation",
    )
    no_backup: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_NO_BACKUP",
        cli_flag="--no-backup",
        cli_action="store_true",
        help="With mutating commands: skip before/after snapshots and validation",
        help_group="Mutation",
    )
    parallelism: int = src.config_field(
        default=16,
        env_var="SRC_AUTH_PERMS_SYNC_PARALLELISM",
        cli_flag="--parallelism",
        metavar="N",
        ge=1,
        help="Concurrent Sourcegraph API worker threads (default: 16)",
        help_group="Runtime",
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
        help_group="Runtime",
    )
    max_attempts: int = src.config_field(
        default=5,
        env_var="SRC_AUTH_PERMS_SYNC_MAX_ATTEMPTS",
        cli_flag="--max-attempts",
        metavar="N",
        ge=1,
        help="Max attempts per HTTP request before giving up (default: 5)",
        help_group="Runtime",
    )
    http_timeout_seconds: float = src.config_field(
        default=60.0,
        env_var="SRC_AUTH_PERMS_SYNC_HTTP_TIMEOUT_SECONDS",
        cli_flag="--http-timeout-seconds",
        metavar="SECONDS",
        gt=0,
        help="HTTP read timeout per request in seconds (default: 60)",
        help_group="Runtime",
    )
    sample_interval: float = src.config_field(
        default=10.0,
        env_var="SRC_AUTH_PERMS_SYNC_SAMPLE_INTERVAL",
        cli_flag="--sample-interval",
        metavar="SECONDS",
        ge=0,
        help="Seconds between logging compute resource samples; set 0 to disable (default: 10)",
        help_group="Runtime",
    )
    fetch_sg_traces: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_FETCH_SG_TRACES",
        cli_flag="--fetch-sg-traces",
        cli_action="store_true",
        help="Ask Sourcegraph to retain GraphQL traces and return debug trace metadata",
        help_group="Runtime",
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


def validate_set_mode_selection(command_name: CommandName, config: Config) -> None:
    """Validate set command mode flags."""
    if config.full and command_name != "set":
        config_error("--full requires the set command")

    if command_name != "set":
        return

    if sum((config.full, bool(config.users), config.users_without_explicit_perms)) > 1:
        config_error(
            "with set, choose at most one of --full, --users, or --users-without-explicit-perms"
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
    return permission_types.SetCommandOptions(
        mode="full",
        user_created_after=config.created_after,
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
    return CliInput(command_name=command_name, config=config)


def default_maps_path(endpoint: str) -> Path:
    """Return the generated maps path for a Sourcegraph endpoint."""
    return backups.endpoint_artifacts_directory(endpoint) / DEFAULT_MAPS_FILE_NAME


def config_with_default_paths(command_name: CommandName, config: Config, endpoint: str) -> Config:
    """Return config with omitted file paths filled from generated defaults."""
    if command_name != "set" or config.maps_path is not None:
        return config
    return config.model_copy(update={"maps_path": default_maps_path(endpoint)})


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


def run_fields(config: Config, command: ResolvedCommand, endpoint: str) -> dict[str, object]:
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
        "artifacts_dir": str(backups.endpoint_artifacts_directory(endpoint)),
        "python_version": sys.version.split()[0],
        "pid": os.getpid(),
    }
    if command.name != "get":
        fields["apply"] = config.apply
    if config.no_backup:
        fields["no_backup"] = True
    if command.set_mode is not None:
        fields["set_mode"] = command.set_mode
    if command.sync_saml_organizations:
        fields["sync_saml_orgs"] = True
    if config.created_after is not None:
        fields["created_after"] = config.created_after
    return fields


def startup_config_fields(config: Config) -> dict[str, object]:
    """Return the startup config snapshot plus derived runtime limits."""
    fields = src.config_snapshot(config)
    fields["SRC_AUTH_PERMS_SYNC_MAX_PENDING_BATCHES"] = max(1, config.parallelism * 2)
    return fields


def run_with_client(
    config: Config,
    command: ResolvedCommand,
    endpoint: str,
    worker_pool: ThreadPoolExecutor,
) -> None:
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
        run_command(config, command, client, worker_pool)
    finally:
        client.http.close()


def run_command(
    config: Config,
    command: ResolvedCommand,
    client: src.SourcegraphClient,
    worker_pool: ThreadPoolExecutor,
) -> None:
    """Dispatch the selected command."""
    sourcegraph_site_config = site_config.validate_site_config(client)
    command_data = run_context.CommandData()
    if command.name == "get":
        command_data = run_get(config, client, sourcegraph_site_config, worker_pool)
    elif command.name == "set":
        command_data = run_set(config, command, client, sourcegraph_site_config, worker_pool)
    elif command.name == "restore":
        run_restore(config, client, sourcegraph_site_config, worker_pool)
    else:
        run_sync_saml_organizations(
            config,
            client,
            sourcegraph_site_config,
            command_data,
            worker_pool,
        )
        return

    if command.sync_saml_organizations:
        run_sync_saml_organizations(
            config,
            client,
            sourcegraph_site_config,
            command_data,
            worker_pool,
        )


def run_set(
    config: Config,
    command: ResolvedCommand,
    client: src.SourcegraphClient,
    sourcegraph_site_config: site_config.SiteConfig,
    worker_pool: ThreadPoolExecutor,
) -> run_context.CommandData:
    """Run the selected repo-permission sync command."""
    assert command.set_options is not None
    maps_path = config.maps_path
    if maps_path is None:
        raise SystemExit("set requires a maps file path")
    require_set_input_file(maps_path)
    return permissions_command.cmd_set(
        client,
        maps_path,
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
    worker_pool: ThreadPoolExecutor,
) -> None:
    """Run the selected repo-permission restore command."""
    assert config.restore_path is not None
    permissions_command.cmd_restore(
        client,
        config.restore_path,
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
    worker_pool: ThreadPoolExecutor,
) -> None:
    """Run the selected SAML organization sync command."""
    organizations_command.cmd_sync_saml_organizations(
        client,
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
    worker_pool: ThreadPoolExecutor,
) -> run_context.CommandData:
    """Run the default read-only discovery command."""
    artifacts_directory = backups.endpoint_artifacts_directory(client.endpoint)
    maps_path = default_maps_path(client.endpoint)
    maps_created = permissions_maps.create_maps_yaml_if_missing(maps_path)
    if maps_created:
        log.info("maps.yaml missing, created %s with an empty maps list.", maps_path)
    else:
        log.info("Left existing %s unchanged.", maps_path)

    return permissions_command.cmd_get(
        client,
        artifacts_directory / "code-hosts.yaml",
        artifacts_directory / "auth-providers.yaml",
        maps_path,
        user_identifiers=config.users,
        users_without_explicit_perms=config.users_without_explicit_perms,
        user_created_after=config.created_after,
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


def reraise_system_exit_with_logged_error(exception: SystemExit) -> NoReturn:
    """Log string SystemExit messages inside the structured logging context."""
    if isinstance(exception.code, str):
        log.error("%s", exception.code)
        raise SystemExit(1) from exception
    raise exception


def Get(config: Config) -> bool:
    """Run repository permission discovery and return whether it succeeded."""
    return _run("get", config)


def Set(config: Config) -> bool:
    """Run repository permission reconciliation and return whether it succeeded."""
    return _run("set", config)


def Restore(config: Config) -> bool:
    """Run repository permission restore and return whether it succeeded."""
    return _run("restore", config)


def SyncSamlOrgs(config: Config) -> bool:
    """Run SAML organization sync and return whether it succeeded."""
    return _run("sync_saml_orgs", config)


def _run(command_name: CommandName, config: Config) -> bool:
    """Run a command and return whether it completed successfully."""
    try:
        _run_or_raise(command_name, config)
    except SystemExit as exception:
        return exception.code in (None, 0)
    except Exception:
        log.exception("src-auth-perms-sync run failed.")
        return False
    return True


def _run_or_raise(command_name: CommandName, config: Config) -> None:
    """Run src-auth-perms-sync, preserving CLI-style exceptions."""
    validate_config(command_name, config)
    command = resolve_command(command_name, config)
    try:
        endpoint = src.normalize_sourcegraph_endpoint(config.src_endpoint)
    except ValueError as error:
        config_error(str(error))
    config = config_with_default_paths(command_name, config, endpoint)
    run_timestamp = backups.backup_timestamp()
    run_directory = backups.artifact_run_directory(
        run_timestamp,
        endpoint,
        command.artifact_name,
    )

    logging_settings = src.logging_settings_from_config(
        config,
        log_file=backups.run_log_path(run_directory),
        logs_dir=None,
        resource_sample_interval_seconds=config.sample_interval,
        open_telemetry=src.open_telemetry_settings_from_config(
            config,
            force_traces=config.fetch_sg_traces,
            service_name="src-auth-perms-sync",
        ),
    )

    with (
        backups.run_artifacts_context(run_directory, run_timestamp),
        src.logging(
            startup_config_fields(config),
            command=command.name,
            git_cwd=__file__,
            logging_config=logging_settings,
            run_fields=run_fields(config, command, endpoint),
        ),
        run_context.thread_pool(config.parallelism) as worker_pool,
    ):
        try:
            run_with_client(config, command, endpoint, worker_pool)
        except SystemExit as exception:
            reraise_system_exit_with_logged_error(exception)


def main() -> None:
    cli_input = load_cli()
    _run_or_raise(cli_input.command_name, cli_input.config)
