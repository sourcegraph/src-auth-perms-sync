"""
src-auth-perms-sync uses metadata from auth providers to set:
- Explicit repo permissions
- Organizations and memberships

See https://github.com/sourcegraph/src-auth-perms-sync/blob/main/README.md for usage instructions

"""

from __future__ import annotations

import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, NoReturn, TypeAlias

import src_py_lib as src

from .orgs import command as organizations_command
from .permissions import command as permissions_command
from .permissions import maps as permissions_maps
from .permissions import types as permission_types
from .shared import backups, run_context, site_config

log = logging.getLogger(__name__)

CommandName: TypeAlias = Literal["get", "set", "restore", "sync_saml_orgs"]
LogCommandName: TypeAlias = Literal[
    "get",
    "set_full",
    "set_user",
    "set_users_without_explicit_perms",
    "restore",
    "sync_saml_orgs",
    "get_sync_saml_orgs",
    "set_full_sync_saml_orgs",
    "set_user_sync_saml_orgs",
    "set_users_without_explicit_perms_sync_saml_orgs",
]

SET_COMMAND_LOG_NAMES: dict[permission_types.SetCommandMode, LogCommandName] = {
    "full": "set_full",
    "user": "set_user",
    "users_without_explicit_perms": "set_users_without_explicit_perms",
}
SET_COMMAND_ARTIFACT_NAMES: dict[permission_types.SetCommandMode, str] = {
    "full": "set-{run_mode}",
    "user": "set-add-user-{run_mode}",
    "users_without_explicit_perms": "set-add-users-without-explicit-perms-{run_mode}",
}
SYNC_SET_COMMAND_LOG_NAMES: dict[permission_types.SetCommandMode, LogCommandName] = {
    "full": "set_full_sync_saml_orgs",
    "user": "set_user_sync_saml_orgs",
    "users_without_explicit_perms": "set_users_without_explicit_perms_sync_saml_orgs",
}
SYNC_SET_COMMAND_ARTIFACT_NAMES: dict[permission_types.SetCommandMode, str] = {
    "full": "set-sync-saml-orgs-{run_mode}",
    "user": "set-add-user-sync-saml-orgs-{run_mode}",
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
        """Return the concrete `--set` mode when this is a set command."""
        if self.set_options is None:
            return None
        return self.set_options.mode


class SrcAuthPermissionsSyncConfig(src.SourcegraphClientConfig, src.LoggingConfig):
    """Config values loaded from defaults, .env, environment, and CLI flags."""

    get: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_GET",
        cli_flag="--get",
        cli_action="store_true",
        help="Query the SG instance and write/refresh auth-providers.yaml and code-hosts.yaml",
    )
    set_path: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_SET",
        cli_flag="--set",
        cli_nargs="?",
        cli_const="maps.yaml",
        metavar="FILE",
        help=(
            "Read the YAML config file and execute the mapping rules.\n"
            "Defaults to maps.yaml under src-auth-perms-sync-runs/<endpoint>/.\n"
            "Relative paths are resolved from that path."
        ),
    )
    full: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_FULL",
        cli_flag="--full",
        cli_action="store_true",
        help="With --set: run the full overwrite reconciliation mode (default)",
    )
    user: str | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_USER",
        cli_flag="--user",
        metavar="USER",
        help="Process a specific Sourcegraph user by username or email address",
    )
    users_without_explicit_perms: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_USERS_WITHOUT_EXPLICIT_PERMS",
        cli_flag="--users-without-explicit-perms",
        cli_action="store_true",
        help="Process Sourcegraph users without explicit permissions",
    )
    created_after: str | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_CREATED_AFTER",
        cli_flag="--created-after",
        metavar="YYYY-MM-DD",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        help="Process Sourcegraph users created on or after this date",
    )
    restore_path: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_RESTORE",
        cli_flag="--restore",
        metavar="FILE",
        help=(
            "Restore explicit-permissions state to match the given snapshot JSON file.\n"
            "Relative paths are resolved under 'src-auth-perms-sync-runs/<endpoint>/.'"
        ),
    )
    sync_saml_organizations: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_SYNC_SAML_ORGS",
        cli_flag="--sync-saml-orgs",
        cli_action="store_true",
        help="Create/update Sourcegraph organizations for each discovered SAML group",
    )
    apply: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_APPLY",
        cli_flag="--apply",
        cli_action="store_true",
        help="With mutating commands: actually mutate state. Default is dry-run",
    )
    no_backup: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_NO_BACKUP",
        cli_flag="--no-backup",
        cli_action="store_true",
        help="With mutating commands: skip before/after snapshots and validation",
    )
    parallelism: int = src.config_field(
        default=16,
        env_var="SRC_AUTH_PERMS_SYNC_PARALLELISM",
        cli_flag="--parallelism",
        metavar="N",
        ge=1,
        help="Concurrent Sourcegraph API worker threads (default: 16)",
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
    )
    max_attempts: int = src.config_field(
        default=5,
        env_var="SRC_AUTH_PERMS_SYNC_MAX_ATTEMPTS",
        cli_flag="--max-attempts",
        metavar="N",
        ge=1,
        help="Max attempts per HTTP request before giving up (default: 5)",
    )
    sample_interval: float = src.config_field(
        default=10.0,
        env_var="SRC_AUTH_PERMS_SYNC_SAMPLE_INTERVAL",
        cli_flag="--sample-interval",
        metavar="SECONDS",
        ge=0,
        help="Seconds between logging compute resource samples; set 0 to disable (default: 10)",
    )
    trace: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_TRACE",
        cli_flag="--trace",
        cli_action="store_true",
        help=("Ask Sourcegraph to retain traces for GraphQL requests and return trace metadata"),
    )


def config_error(message: str) -> NoReturn:
    """Exit with a concise config/argument error."""
    print(f"src-auth-perms-sync: error: {message}", file=sys.stderr)
    raise SystemExit(2)


def validate_config(config: SrcAuthPermissionsSyncConfig) -> None:
    """Validate cross-field CLI/config constraints."""
    validate_command_selection(config)
    validate_user_filter_selection(config)
    validate_set_mode_selection(config)


def validate_command_selection(config: SrcAuthPermissionsSyncConfig) -> None:
    """Validate compatible top-level command flags."""
    if sum((config.get, config.set_path is not None, config.restore_path is not None)) > 1:
        config_error("choose only one of --get, --set, or --restore")
    if config.restore_path is not None and config.sync_saml_organizations:
        config_error("--sync-saml-orgs can run by itself or with --get or --set")


def validate_user_filter_selection(config: SrcAuthPermissionsSyncConfig) -> None:
    """Validate user-scope filters and their compatible commands."""
    user_identifier_filters = sum((config.user is not None, config.users_without_explicit_perms))
    if user_identifier_filters > 1:
        config_error("choose only one of --user or --users-without-explicit-perms")

    user_filter_selected = user_identifier_filters > 0 or config.created_after is not None
    user_filter_allowed = (
        config.get
        or config.set_path is not None
        or (config.restore_path is None and not config.sync_saml_organizations)
    )
    if user_filter_selected and not user_filter_allowed:
        config_error(
            "--user, --users-without-explicit-perms, and --created-after require --get or --set"
        )


def validate_set_mode_selection(config: SrcAuthPermissionsSyncConfig) -> None:
    """Validate `--set` mode flags."""
    if config.full and config.set_path is None:
        config_error("--full requires --set")

    if config.set_path is None:
        return

    if sum((config.full, config.user is not None, config.users_without_explicit_perms)) > 1:
        config_error(
            "with --set, choose at most one of --full, --user, or --users-without-explicit-perms"
        )


def set_command_options(config: SrcAuthPermissionsSyncConfig) -> permission_types.SetCommandOptions:
    """Return the validated `--set` mode options."""
    if config.user is not None:
        return permission_types.SetCommandOptions(
            mode="user",
            user_identifier=config.user,
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


def resolve_command(config: SrcAuthPermissionsSyncConfig) -> ResolvedCommand:
    """Return the command execution plan derived from config."""
    run_mode = "apply" if config.apply else "dry-run"
    if config.set_path is not None:
        return resolve_set_command(config, run_mode)
    if config.restore_path is not None:
        return ResolvedCommand(
            name="restore",
            log_name="restore",
            artifact_name=f"restore-{run_mode}",
        )
    if config.get and config.sync_saml_organizations:
        return ResolvedCommand(
            name="get",
            log_name="get_sync_saml_orgs",
            artifact_name=f"get-sync-saml-orgs-{run_mode}",
            sync_saml_organizations=True,
        )
    if config.get:
        return ResolvedCommand(name="get", log_name="get", artifact_name="get")
    if config.sync_saml_organizations:
        return ResolvedCommand(
            name="sync_saml_orgs",
            log_name="sync_saml_orgs",
            artifact_name=f"sync-saml-orgs-{run_mode}",
            sync_saml_organizations=True,
        )
    return ResolvedCommand(name="get", log_name="get", artifact_name="get")


def resolve_set_command(config: SrcAuthPermissionsSyncConfig, run_mode: str) -> ResolvedCommand:
    """Return resolved metadata for the selected `--set` command mode."""
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


def load_config() -> SrcAuthPermissionsSyncConfig:
    """Parse and validate CLI/environment config."""
    config = src.parse_args(
        SrcAuthPermissionsSyncConfig,
        description=__doc__,
        base_dir=Path("."),
    )
    validate_config(config)
    return config


def endpoint_scoped_config(
    config: SrcAuthPermissionsSyncConfig, endpoint: str
) -> SrcAuthPermissionsSyncConfig:
    """Return config with relative operator artifact paths scoped to this endpoint."""
    updates: dict[str, object] = {}
    if config.set_path is not None:
        updates["set_path"] = backups.endpoint_artifact_path(endpoint, config.set_path)
    if config.restore_path is not None:
        updates["restore_path"] = backups.endpoint_artifact_path(endpoint, config.restore_path)
    if not updates:
        return config
    return config.model_copy(update=updates)


def require_set_input_file(config: SrcAuthPermissionsSyncConfig) -> None:
    """Exit with a clear error if the selected maps file is missing."""
    if config.set_path is None:
        return
    if config.set_path.is_file():
        return
    if config.set_path.exists():
        raise SystemExit(f"--set input path is not a file: {config.set_path}")
    raise SystemExit(
        "--set input file does not exist: "
        f"{config.set_path}\n"
        "Run `uv run src-auth-perms-sync --get` to create the default maps.yaml, "
        "or pass a path to an existing maps file."
    )


def run_fields(
    config: SrcAuthPermissionsSyncConfig, command: ResolvedCommand, endpoint: str
) -> dict[str, object]:
    """Return run-level fields for structured logging."""
    return {
        "cli_cmd": command.log_name,
        "base_cmd": command.name,
        "set_mode": command.set_mode,
        "sync_saml_orgs_flag": command.sync_saml_organizations,
        "apply_flag": config.apply,
        "endpoint": endpoint,
        "parallelism": config.parallelism,
        "explicit_permissions_batch_size": config.explicit_permissions_batch_size,
        "trace": config.trace,
        "max_attempts": config.max_attempts,
        "no_backup": config.no_backup,
        "sample_interval": config.sample_interval,
        "user_created_after": config.created_after,
        "artifacts_dir": str(backups.endpoint_artifacts_directory(endpoint)),
        "python_version": sys.version.split()[0],
        "pid": os.getpid(),
    }


def run_with_client(
    config: SrcAuthPermissionsSyncConfig,
    command: ResolvedCommand,
    endpoint: str,
    worker_pool: ThreadPoolExecutor,
) -> None:
    """Create a client, run the selected command, and always close HTTP resources."""
    http = src.HTTPClient(
        user_agent="src-auth-perms-sync/0.1 (+python)",
        max_attempts=config.max_attempts,
        max_connections=config.parallelism,
    )
    client = src.SourcegraphClient(
        endpoint=endpoint,
        token=config.src_access_token,
        http=http,
        trace=config.trace,
    )
    try:
        run_command(config, command, client, worker_pool)
    finally:
        client.http.close()


def run_command(
    config: SrcAuthPermissionsSyncConfig,
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
    config: SrcAuthPermissionsSyncConfig,
    command: ResolvedCommand,
    client: src.SourcegraphClient,
    sourcegraph_site_config: site_config.SiteConfig,
    worker_pool: ThreadPoolExecutor,
) -> run_context.CommandData:
    """Run the selected repo-permission sync command."""
    assert config.set_path is not None
    assert command.set_options is not None
    require_set_input_file(config)
    return permissions_command.cmd_set(
        client,
        config.set_path,
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
    config: SrcAuthPermissionsSyncConfig,
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
    config: SrcAuthPermissionsSyncConfig,
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
    config: SrcAuthPermissionsSyncConfig,
    client: src.SourcegraphClient,
    sourcegraph_site_config: site_config.SiteConfig,
    worker_pool: ThreadPoolExecutor,
) -> run_context.CommandData:
    """Run the default read-only discovery command."""
    artifacts_directory = backups.endpoint_artifacts_directory(client.endpoint)
    maps_path = artifacts_directory / "maps.yaml"
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
        user_identifier=config.user,
        users_without_explicit_perms=config.users_without_explicit_perms,
        user_created_after=config.created_after,
        parallelism=config.parallelism,
        explicit_permissions_batch_size=config.explicit_permissions_batch_size,
        bind_id_mode=sourcegraph_site_config.bind_id_mode,
        saml_groups_attribute_name_by_config_id=(
            sourcegraph_site_config.saml_groups_attribute_name_by_config_id
        ),
        auth_providers_by_config_id=sourcegraph_site_config.auth_providers_by_config_id,
        retain_saml_group_users=config.sync_saml_organizations,
        worker_pool=worker_pool,
    )


def reraise_system_exit_with_logged_error(exception: SystemExit) -> NoReturn:
    """Log string SystemExit messages inside the structured logging context."""
    if isinstance(exception.code, str):
        log.error("%s", exception.code)
        raise SystemExit(1) from exception
    raise exception


def main() -> None:
    config = load_config()
    command = resolve_command(config)
    try:
        endpoint = src.normalize_sourcegraph_endpoint(config.src_endpoint)
    except ValueError as error:
        config_error(str(error))
    config = endpoint_scoped_config(config, endpoint)
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
    )

    with (
        backups.run_artifacts_context(run_directory, run_timestamp),
        src.logging(
            config,
            command=command.log_name,
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
