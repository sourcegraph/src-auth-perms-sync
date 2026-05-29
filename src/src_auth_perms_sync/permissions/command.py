"""Repo-permission sync command handlers."""

from __future__ import annotations

import datetime
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import src_py_lib as src

from ..shared import backups, id_codec, run_context, saml_groups
from ..shared import sourcegraph as shared_sourcegraph
from ..shared import types as shared_types
from . import apply as permissions_apply
from . import full_set as permissions_full_set
from . import mapping as permissions_mapping
from . import maps as permissions_maps
from . import restore as permissions_restore
from . import snapshot as permission_snapshot
from . import sourcegraph as permissions_sourcegraph
from . import types as permission_types
from .workflow import (
    load_discovery,
    load_mapping_context,
    parse_cli_date,
    snapshot_path,
    sourcegraph_datetime_filter,
    user_ids_created_on_or_after,
    write_maps_backup,
    write_user_scoped_snapshot_diff_file,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _ResolvedMapping:
    """A mapping rule with its repository side pre-resolved."""

    index: int
    name: str
    users_section: dict[str, object]
    repos: list[permission_types.Repository]


def resolve_additive_mappings(context: permission_types.MappingContext) -> list[_ResolvedMapping]:
    """Pre-resolve the repository side of every mapping rule."""
    resolved: list[_ResolvedMapping] = []
    for mapping_index, mapping in enumerate(context.mapping_rules, start=1):
        name = mapping.get("name", f"<unnamed mapping #{mapping_index}>")
        repos_section = cast(dict[str, object], mapping["repos"])
        matched_repos = permissions_mapping.resolve_repos(
            repos_section,
            context.services_by_id,
            context.repos_by_external_service_id,
            context.all_repos_by_id,
        )
        log.info(
            "Mapping %d / %d %s: repo side matched %d repo(s).",
            mapping_index,
            len(context.mapping_rules),
            name,
            len(matched_repos),
        )
        if not matched_repos:
            continue
        resolved.append(
            _ResolvedMapping(
                index=mapping_index,
                name=name,
                users_section=cast(dict[str, object], mapping["users"]),
                repos=matched_repos,
            )
        )
    return resolved


def cmd_get(
    client: src.SourcegraphClient,
    code_hosts_path: Path,
    auth_providers_path: Path,
    maps_path: Path,
    *,
    user_identifier: str | None,
    users_without_explicit_perms: bool,
    user_created_after: str | None,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    auth_providers_by_config_id: dict[str, dict[str, Any]],
    retain_saml_group_users: bool = False,
    worker_pool: ThreadPoolExecutor | None = None,
) -> run_context.CommandData:
    """Refresh the generated discovery YAML files.

    `code_hosts_path` receives Sourcegraph code host connection configs,
    `auth_providers_path` receives auth provider configs, and `maps_path`
    is used for the generated get-snapshot name.

    `saml_groups_attribute_name_by_config_id` is the per-`configID`
    override map produced by `validate_site_config`; non-default
    `groupsAttributeName` values from `auth.providers[*]` flow through
    here so per-group counts are computed against the same SAML
    attribute Sourcegraph itself reads at sign-in time.

    `auth_providers_by_config_id` carries the parsed `auth.providers[*]`
    site-config entries (secrets stripped) keyed by explicit `configID`,
    so every non-secret provider attribute (e.g.
    `identityProviderMetadataURL`, `serviceProviderIssuer`) shows up in
    `auth-providers.yaml` alongside the GraphQL-discovered fields.
    Providers without an explicit `configID` get only the GraphQL-derived view.
    """
    with src.event(
        "cmd_get",
        code_hosts_path=str(code_hosts_path),
        auth_providers_path=str(auth_providers_path),
        maps_path=str(maps_path),
        user_identifier=user_identifier,
        users_without_explicit_perms=users_without_explicit_perms,
        user_created_after=user_created_after,
        parallelism=parallelism,
    ) as cmd_event:
        raw_providers, raw_services, attribute_names_by_provider = load_discovery(
            client, saml_groups_attribute_name_by_config_id
        )
        services = [permissions_maps.external_service_to_yaml(service) for service in raw_services]
        cmd_event["auth_provider_count"] = len(raw_providers)
        cmd_event["external_service_count"] = len(services)

        users = _load_get_users(
            client,
            user_identifier=user_identifier,
            users_without_explicit_perms=users_without_explicit_perms,
            user_created_after=user_created_after,
        )
        counts = permissions_maps.count_users_per_provider(users)
        # SAML-only: tally distinct users per (serviceID, clientID, group)
        # by parsing each user's SAML AssertionInfo `accountData`. Surfaced
        # in the YAML so operators can size groups before authoring a
        # `authProvider.samlGroup` mapping rule. See
        # `src/src_auth_perms_sync/shared/saml_groups.py`.
        saml_group_counts = saml_groups.count_users_per_saml_group(
            users, attribute_names_by_provider
        )
        cmd_event["user_count"] = len(users)
        cmd_event["saml_providers_with_groups"] = len(saml_group_counts)

        providers = [
            permissions_maps.auth_provider_to_yaml(
                provider,
                counts.get(
                    (provider["serviceType"], provider["serviceID"], provider["clientID"]), 0
                ),
                # SAML providers always get the field (possibly empty) so
                # operators can see at a glance whether the IdP is releasing
                # a groups claim. Non-SAML providers get None → field omitted.
                saml_group_user_counts=(
                    saml_group_counts.get((provider["serviceID"], provider["clientID"]), {})
                    if provider["serviceType"] == saml_groups.SAML_SERVICE_TYPE
                    else None
                ),
                # Match by explicit `configID` only — Sourcegraph
                # synthesizes one for entries that omit it, but the synth
                # is a content-addressed hash we can't safely replicate.
                # Such providers get only the GraphQL-derived view.
                site_config_entry=auth_providers_by_config_id.get(provider["configID"]),
            )
            for provider in raw_providers
        ]

        permissions_maps.dump_code_hosts_yaml(code_hosts_path, services)
        permissions_maps.dump_auth_providers_yaml(auth_providers_path, providers)
        log.info("Wrote %s and %s", code_hosts_path, auth_providers_path)

        timestamp = backups.backup_timestamp()
        before_snapshot = permission_snapshot.build_snapshot(
            client,
            users,
            parallelism,
            bind_id_mode,
            maps_path,
            total_users=len(users),
            explicit_permissions_batch_size=explicit_permissions_batch_size,
            worker_pool=worker_pool,
        )
        before_path = snapshot_path(maps_path, timestamp, client.endpoint, "get", "before")
        permission_snapshot.write_snapshot(before_path, before_snapshot)
        cmd_event["beforesnapshot_path"] = str(before_path)
        maps_backup_path = write_maps_backup(maps_path, timestamp, client.endpoint, "get")
        if maps_backup_path is not None:
            cmd_event["maps_backup_path"] = str(maps_backup_path)
        log.info(
            "Wrote before-snapshot: %s (%d repo(s) with explicit grants, %d total grant(s)).",
            before_path,
            before_snapshot["stats"]["repos_with_explicit_grants"],
            before_snapshot["stats"]["total_grants"],
        )
        saml_group_users = (
            saml_groups.compact_saml_group_users(
                users,
                raw_providers,
                attribute_names_by_provider,
            )
            if user_identifier is None
            and not users_without_explicit_perms
            and user_created_after is None
            and retain_saml_group_users
            else None
        )
        return run_context.CommandData(
            auth_providers=raw_providers,
            saml_group_users=saml_group_users,
        )


def _load_get_users(
    client: src.SourcegraphClient,
    *,
    user_identifier: str | None,
    users_without_explicit_perms: bool,
    user_created_after: str | None,
) -> list[shared_types.User]:
    """Load the Sourcegraph users selected by get/set-compatible user filters."""
    if user_identifier is not None:
        user = _resolve_user_identifier(client, user_identifier)
        if user_created_after is None:
            return [user]
        candidate_user_ids = user_ids_created_on_or_after(client, user_created_after)
        if user["id"] in candidate_user_ids:
            return [user]
        log.info(
            "User %s was not created on or after %s — no user metadata selected.",
            user["username"],
            user_created_after,
        )
        return []

    if users_without_explicit_perms or user_created_after is not None:
        created_after_filter: str | None = None
        if user_created_after is not None:
            created_after_filter = sourcegraph_datetime_filter(
                parse_cli_date(user_created_after, "--created-after")
            )
        candidates = permissions_sourcegraph.list_site_user_candidates(client, created_after_filter)
        log.info("Received %d non-deleted user candidate(s).", len(candidates))

        users: list[shared_types.User] = []
        for candidate in candidates:
            if users_without_explicit_perms and permissions_sourcegraph.user_has_explicit_repos(
                client, candidate["id"]
            ):
                continue
            user = permissions_sourcegraph.get_user_by_id(client, candidate["id"])
            if user is None:
                log.warning(
                    "Skipping user candidate %s: user no longer exists.",
                    candidate["username"],
                )
                continue
            users.append(user)
        log.info("Selected %d user(s) for get output.", len(users))
        return users

    return _load_all_get_users(client)


def _load_all_get_users(client: src.SourcegraphClient) -> list[shared_types.User]:
    """Load all users for get output, with progress logs for large instances."""
    total_users = shared_sourcegraph.count_users(client)
    page_count = (
        total_users + shared_sourcegraph.DEFAULT_PAGE_SIZE - 1
    ) // shared_sourcegraph.DEFAULT_PAGE_SIZE
    log.info(
        "Querying metadata for %d users (%d page(s) of %d users / page) ...",
        total_users,
        page_count,
        shared_sourcegraph.DEFAULT_PAGE_SIZE,
    )
    users: list[shared_types.User] = []
    load_started = time.perf_counter()
    progress_step = max(1, total_users // 10)
    for completed, user in enumerate(shared_sourcegraph.list_users_streaming(client), start=1):
        users.append(user)
        if completed % progress_step == 0 or completed == total_users:
            elapsed = time.perf_counter() - load_started
            rate = completed / elapsed if elapsed > 0 else 0.0
            remaining = max(total_users - completed, 0)
            eta_seconds = remaining / rate if rate > 0 else 0.0
            log.info(
                "Received user metadata for %d / %d users (%.0f%%) "
                "in %.0fs (%.0f users/sec, ETA %.0fs).",
                completed,
                total_users,
                100.0 * completed / total_users,
                elapsed,
                rate,
                eta_seconds,
            )
    return users


def cmd_set(
    client: src.SourcegraphClient,
    input_path: Path,
    options: permission_types.SetCommandOptions,
    dry_run: bool,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    retain_saml_group_users: bool = False,
    worker_pool: ThreadPoolExecutor | None = None,
) -> run_context.CommandData:
    """Dispatch the selected `--set` mode."""
    if options.mode == "full":
        return permissions_full_set.cmd_set_full(
            client,
            input_path,
            options.user_created_after,
            dry_run,
            parallelism,
            explicit_permissions_batch_size,
            bind_id_mode,
            saml_groups_attribute_name_by_config_id,
            do_backup,
            retain_saml_group_users,
            worker_pool,
        )
    if options.mode == "user":
        assert options.user_identifier is not None
        return cmd_set_additive_user(
            client,
            input_path,
            options.user_identifier,
            options.user_created_after,
            dry_run,
            parallelism,
            bind_id_mode,
            saml_groups_attribute_name_by_config_id,
            do_backup,
            worker_pool,
        )
    if options.mode == "users_without_explicit_perms":
        return cmd_set_additive_users_without_explicit_perms(
            client,
            input_path,
            options.user_created_after,
            dry_run,
            parallelism,
            bind_id_mode,
            saml_groups_attribute_name_by_config_id,
            do_backup,
            worker_pool,
        )
    return run_context.CommandData()


def cmd_set_additive_user(
    client: src.SourcegraphClient,
    input_path: Path,
    user_identifier: str,
    user_created_after: str | None,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> run_context.CommandData:
    """Add missing mapped permissions for one resolved user."""
    with src.event(
        "cmd_set_additive_user",
        input_path=str(input_path),
        user_identifier=user_identifier,
        user_created_after=user_created_after,
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ):
        context = load_mapping_context(client, input_path, saml_groups_attribute_name_by_config_id)
        if context is None:
            return run_context.CommandData()
        user = _resolve_user_identifier(client, user_identifier)
        if user_created_after is not None:
            candidate_user_ids = user_ids_created_on_or_after(client, user_created_after)
            if user["id"] not in candidate_user_ids:
                log.info(
                    "User %s was not created on or after %s — nothing to do.",
                    user["username"],
                    user_created_after,
                )
                return run_context.CommandData(auth_providers=context.providers)
        resolved_mappings = resolve_additive_mappings(context)
        additions = _plan_additions_for_user(
            client,
            context,
            resolved_mappings,
            user,
        )
        _run_additive_apply(
            client,
            input_path,
            [user],
            additions,
            dry_run=dry_run,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            do_backup=do_backup,
            command_name="set-add-user",
            worker_pool=worker_pool,
        )
        return run_context.CommandData(auth_providers=context.providers)


def cmd_set_additive_users_without_explicit_perms(
    client: src.SourcegraphClient,
    input_path: Path,
    user_created_after: str | None,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> run_context.CommandData:
    """Add mapped permissions for users with no explicit API grants."""
    created_after_filter: str | None = None
    if user_created_after is not None:
        created_after_filter = sourcegraph_datetime_filter(
            parse_cli_date(user_created_after, "--created-after")
        )
    with src.event(
        "cmd_set_additive_users_without_explicit_perms",
        input_path=str(input_path),
        user_created_after=user_created_after,
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ):
        context = load_mapping_context(client, input_path, saml_groups_attribute_name_by_config_id)
        if context is None:
            return run_context.CommandData()
        resolved_mappings = resolve_additive_mappings(context)
        candidates = permissions_sourcegraph.list_site_user_candidates(client, created_after_filter)
        log.info("Received %d non-deleted user candidate(s).", len(candidates))

        users: list[shared_types.User] = []
        additions: list[permissions_apply.PermissionAddition] = []
        for candidate in candidates:
            if permissions_sourcegraph.user_has_explicit_repos(client, candidate["id"]):
                continue
            user = permissions_sourcegraph.get_user_by_id(client, candidate["id"])
            if user is None:
                log.warning(
                    "Skipping user candidate %s: user no longer exists.",
                    candidate["username"],
                )
                continue
            user_additions = _plan_additions_for_user(
                client,
                context,
                resolved_mappings,
                user,
                existing_repo_ids=set(),
            )
            users.append(user)
            additions.extend(user_additions)

        log.info(
            "Planned additive grants for %d user(s) with no explicit grants.",
            len(users),
        )
        _run_additive_apply(
            client,
            input_path,
            users,
            additions,
            dry_run=dry_run,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            do_backup=do_backup,
            command_name="set-add-users-without-explicit-perms",
            worker_pool=worker_pool,
        )
        return run_context.CommandData(auth_providers=context.providers)


def _resolve_user_identifier(
    client: src.SourcegraphClient, user_identifier: str
) -> shared_types.User:
    """Resolve username/email input to one Sourcegraph user."""
    user: shared_types.User | None
    if "@" in user_identifier:
        user = permissions_sourcegraph.get_user_by_email(
            client, user_identifier
        ) or permissions_sourcegraph.get_user_by_username(client, user_identifier)
    else:
        user = permissions_sourcegraph.get_user_by_username(
            client, user_identifier
        ) or permissions_sourcegraph.get_user_by_email(client, user_identifier)
    if user is None:
        raise SystemExit(f"No Sourcegraph user found for {user_identifier!r}.")
    if user["username"] != user_identifier:
        log.info("Resolved %s to Sourcegraph username %s.", user_identifier, user["username"])
    return user


def _plan_additions_for_user(
    client: src.SourcegraphClient,
    context: permission_types.MappingContext,
    resolved_mappings: list[_ResolvedMapping],
    user: shared_types.User,
    existing_repo_ids: set[str] | None = None,
) -> list[permissions_apply.PermissionAddition]:
    """Return missing additive permission edges for one user."""
    desired_repos: dict[str, permission_types.Repository] = {}
    for resolved_mapping in resolved_mappings:
        if not permissions_mapping.user_matches_users_section(
            resolved_mapping.users_section,
            user,
            context.providers,
            context.saml_groups_attribute_names,
        ):
            continue
        for repository in resolved_mapping.repos:
            desired_repos[repository["id"]] = repository

    if existing_repo_ids is None:
        existing_repo_ids = {
            repository["id"]
            for repository in permissions_sourcegraph.list_user_explicit_repos(client, user["id"])
        }
    additions = [
        permissions_apply.PermissionAddition(
            user_id=user["id"],
            username=user["username"],
            repo_id=repository["id"],
            repo_name=repository["name"],
        )
        for repository_id, repository in desired_repos.items()
        if repository_id not in existing_repo_ids
    ]
    additions.sort(key=lambda addition: (addition.username, addition.repo_name))
    log.info(
        "User %s: %d desired repo grant(s), %d already explicit, %d to add.",
        user["username"],
        len(desired_repos),
        len(existing_repo_ids & set(desired_repos)),
        len(additions),
    )
    return additions


def _additive_run_label(command_name: str, dry_run: bool) -> str:
    return f"{command_name}-dry-run" if dry_run else f"{command_name}-apply"


def _write_additive_initial_artifacts(
    client: src.SourcegraphClient,
    input_path: Path,
    snapshot_users: list[permission_snapshot.SnapshotUser],
    additions: list[permissions_apply.PermissionAddition],
    timestamp: str,
    *,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    command_name: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> permission_snapshot.UserScopedSnapshot:
    """Capture before-snapshot and write dry-run/no-op additive artifacts."""
    before_snapshot = permission_snapshot.build_user_scoped_snapshot(
        client,
        snapshot_users,
        parallelism,
        bind_id_mode,
        input_path,
        worker_pool=worker_pool,
    )
    run_label = _additive_run_label(command_name, dry_run)
    before_path = snapshot_path(input_path, timestamp, client.endpoint, run_label, "before")
    after_path = snapshot_path(input_path, timestamp, client.endpoint, run_label, "after")
    permission_snapshot.write_user_scoped_snapshot(before_path, before_snapshot)
    after_planned_snapshot = _user_scoped_snapshot_with_additions(
        before_snapshot,
        additions,
    )
    diff_path: Path | None = None
    if dry_run or not additions:
        permission_snapshot.write_user_scoped_snapshot(after_path, after_planned_snapshot)
        diff_path = write_user_scoped_snapshot_diff_file(
            input_path,
            timestamp,
            client.endpoint,
            run_label,
            before_snapshot,
            after_planned_snapshot,
        )
    maps_backup_path = write_maps_backup(input_path, timestamp, client.endpoint, run_label)
    log.info("Wrote scoped before-snapshot: %s", before_path)
    if dry_run or not additions:
        log.info("Wrote scoped after-snapshot: %s diff=%s", after_path, diff_path)
    if maps_backup_path is not None:
        log.info("Wrote maps backup for additive run: %s", maps_backup_path)
    log.info(
        "Diff (before → planned after):\n%s",
        permission_snapshot.render_user_scoped_diff(before_snapshot, after_planned_snapshot),
    )
    return before_snapshot


def _finish_additive_dry_run(
    additions: list[permissions_apply.PermissionAddition],
) -> None:
    """Log the additive dry-run mutation plan."""
    for addition in additions:
        log.info(
            "[DRY RUN] Would add %s to %s (id=%d).",
            addition.username,
            addition.repo_name,
            id_codec.decode_repository_id(addition.repo_id),
        )
    log.info("Dry run complete. Pass --apply to mutate state.")


def _apply_additive_permissions(
    client: src.SourcegraphClient,
    additions: list[permissions_apply.PermissionAddition],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    """Apply additive repo-permission mutations."""
    log.info(
        "Applying %d addRepositoryPermissionForUser mutation(s) with parallelism=%d ...",
        len(additions),
        parallelism,
    )
    with src.stage("apply"):
        mutations = permissions_apply.apply_additions(
            client,
            additions,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )
    log.info(
        "Additive apply done. %d succeeded, %d failed, %d canceled.",
        mutations.succeeded,
        mutations.failed,
        mutations.canceled,
    )
    return mutations


def _finish_additive_apply_with_backup(
    client: src.SourcegraphClient,
    input_path: Path,
    snapshot_users: list[permission_snapshot.SnapshotUser],
    before_snapshot: permission_snapshot.UserScopedSnapshot,
    additions: list[permissions_apply.PermissionAddition],
    timestamp: str,
    *,
    parallelism: int,
    bind_id_mode: str,
    command_name: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Capture and validate additive post-apply state."""
    after_snapshot = permission_snapshot.build_user_scoped_snapshot(
        client,
        snapshot_users,
        parallelism,
        bind_id_mode,
        input_path,
        worker_pool=worker_pool,
    )
    after_path = snapshot_path(
        input_path,
        timestamp,
        client.endpoint,
        f"{command_name}-apply",
        "after",
    )
    permission_snapshot.write_user_scoped_snapshot(after_path, after_snapshot)
    diff_path = write_user_scoped_snapshot_diff_file(
        input_path,
        timestamp,
        client.endpoint,
        f"{command_name}-apply",
        before_snapshot,
        after_snapshot,
    )
    log.info("Wrote scoped after-snapshot: %s diff=%s", after_path, diff_path)
    log.info(
        "Diff (before → after):\n%s",
        permission_snapshot.render_user_scoped_diff(before_snapshot, after_snapshot),
    )
    _validate_additive_after(after_snapshot, additions)


def _raise_for_failed_additive(mutations: shared_types.MutationCounts) -> None:
    if not (mutations.failed or mutations.canceled):
        return
    log.error(
        "ADDITIVE RUN FAILED: %d mutation(s) failed, %d canceled by circuit breaker.",
        mutations.failed,
        mutations.canceled,
    )
    raise SystemExit(1)


def _run_additive_apply(
    client: src.SourcegraphClient,
    input_path: Path,
    users: list[shared_types.User],
    additions: list[permissions_apply.PermissionAddition],
    *,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    do_backup: bool,
    command_name: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Snapshot, dry-run, apply, and validate an additive permission plan."""
    if not users:
        log.info("No users selected — nothing to do.")
        return

    snapshot_users = _snapshot_users_from_users(users)
    timestamp = backups.backup_timestamp()
    before_snapshot: permission_snapshot.UserScopedSnapshot | None = None
    if dry_run or do_backup:
        before_snapshot = _write_additive_initial_artifacts(
            client,
            input_path,
            snapshot_users,
            additions,
            timestamp,
            dry_run=dry_run,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            command_name=command_name,
            worker_pool=worker_pool,
        )

    log.info("Additive plan: %d grant(s) to add for %d user(s).", len(additions), len(users))
    if dry_run:
        _finish_additive_dry_run(additions)
        return

    if not additions:
        log.info("All selected users already have the mapped explicit grants — nothing to apply.")
        return

    mutations = _apply_additive_permissions(client, additions, parallelism, worker_pool)

    if do_backup:
        assert before_snapshot is not None
        _finish_additive_apply_with_backup(
            client,
            input_path,
            snapshot_users,
            before_snapshot,
            additions,
            timestamp,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            command_name=command_name,
            worker_pool=worker_pool,
        )

    _raise_for_failed_additive(mutations)


def _snapshot_users_from_users(
    users: list[shared_types.User],
) -> list[permission_snapshot.SnapshotUser]:
    """Return deduplicated snapshot users sorted by username."""
    users_by_id = {user["id"]: user for user in users}
    return [
        {"id": user["id"], "username": user["username"]}
        for user in sorted(users_by_id.values(), key=lambda item: item["username"])
    ]


def _user_scoped_snapshot_with_additions(
    before_snapshot: permission_snapshot.UserScopedSnapshot,
    additions: list[permissions_apply.PermissionAddition],
) -> permission_snapshot.UserScopedSnapshot:
    """Return a copy of a scoped snapshot with planned additions applied."""
    users = _copy_user_scoped_users(before_snapshot)
    for addition in additions:
        user_snapshot = users.setdefault(
            addition.username,
            {"id": addition.user_id, "explicit_repositories": []},
        )
        repositories = {
            repository["id"]: repository for repository in user_snapshot["explicit_repositories"]
        }
        repositories[addition.repo_id] = {"id": addition.repo_id, "name": addition.repo_name}
        user_snapshot["explicit_repositories"] = sorted(
            repositories.values(),
            key=lambda repository: repository["name"],
        )
    return _copy_user_scoped_snapshot_with_users(before_snapshot, users)


def _copy_user_scoped_users(
    snapshot: permission_snapshot.UserScopedSnapshot,
) -> dict[str, permission_snapshot.UserScopedUserSnapshot]:
    return {
        username: {
            "id": user_snapshot["id"],
            "explicit_repositories": list(user_snapshot["explicit_repositories"]),
        }
        for username, user_snapshot in snapshot["users"].items()
    }


def _copy_user_scoped_snapshot_with_users(
    snapshot: permission_snapshot.UserScopedSnapshot,
    users: dict[str, permission_snapshot.UserScopedUserSnapshot],
) -> permission_snapshot.UserScopedSnapshot:
    total_grants = sum(
        len(user_snapshot["explicit_repositories"]) for user_snapshot in users.values()
    )
    return {
        "schema_version": snapshot["schema_version"],
        "snapshot_kind": snapshot["snapshot_kind"],
        "captured_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "endpoint": snapshot["endpoint"],
        "bindID_mode": snapshot["bindID_mode"],
        "config_file": snapshot["config_file"],
        "config_sha256": snapshot["config_sha256"],
        "stats": {
            "total_users_scanned": len(users),
            "users_with_explicit_grants": sum(
                1 for user_snapshot in users.values() if user_snapshot["explicit_repositories"]
            ),
            "total_grants": total_grants,
        },
        "users": dict(sorted(users.items())),
    }


def _validate_additive_after(
    after_snapshot: permission_snapshot.UserScopedSnapshot,
    additions: list[permissions_apply.PermissionAddition],
) -> None:
    """Validate that every requested additive edge exists after apply."""
    missing: list[permissions_apply.PermissionAddition] = []
    repos_by_username = {
        username: {repository["id"] for repository in user_snapshot["explicit_repositories"]}
        for username, user_snapshot in after_snapshot["users"].items()
    }
    for addition in additions:
        if addition.repo_id not in repos_by_username.get(addition.username, set()):
            missing.append(addition)
    if missing:
        log.warning("VALIDATION: %d requested additive grant(s) are missing.", len(missing))
        for addition in missing[:20]:
            log.warning(
                "  missing %s → %s (id=%d)",
                addition.username,
                addition.repo_name,
                id_codec.decode_repository_id(addition.repo_id),
            )
        return
    log.info("VALIDATION OK: all %d requested additive grant(s) are present.", len(additions))


def cmd_restore_user_scoped(
    client: src.SourcegraphClient,
    snapshot_path: Path,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    do_backup: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Restore explicit permissions for the users present in a scoped snapshot."""
    permissions_restore.cmd_restore_user_scoped(
        client,
        snapshot_path,
        dry_run,
        parallelism,
        bind_id_mode,
        do_backup,
        worker_pool=worker_pool,
    )


def cmd_restore(
    client: src.SourcegraphClient,
    snapshot_path: Path,
    dry_run: bool,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    do_backup: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Restore explicit-permissions state on the instance to match a snapshot."""
    permissions_restore.cmd_restore(
        client,
        snapshot_path,
        dry_run,
        parallelism,
        explicit_permissions_batch_size,
        bind_id_mode,
        do_backup,
        worker_pool,
    )
