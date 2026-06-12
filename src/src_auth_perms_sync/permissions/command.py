"""Repo-permission sync command handlers."""

from __future__ import annotations

import datetime
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import src_py_lib as src

from ..shared import backups, run_context, saml_groups
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
    load_mapping_context_discovery,
    load_repos_for_mapping_context,
    load_repository_candidates_by_names,
    load_repository_candidates_created_on_or_after,
    parse_cli_date,
    resolve_mapping_rules,
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
    user_selector: permission_types.UserSelector
    repos: list[permission_types.Repository]


def resolve_additive_mappings(context: permission_types.MappingContext) -> list[_ResolvedMapping]:
    """Pre-resolve the repository side of every mapping rule."""
    resolved: list[_ResolvedMapping] = []
    for mapping_index, mapping in enumerate(context.mapping_rules, start=1):
        name = mapping.get("name", f"<unnamed mapping #{mapping_index}>")
        repository_selector = mapping["repos"]
        matched_repos = permissions_mapping.resolve_repos(
            repository_selector,
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
                user_selector=mapping["users"],
                repos=matched_repos,
            )
        )
    return resolved


def _mapping_context_with_rules(
    context: permission_types.MappingContext,
    mapping_rules: list[permission_types.MappingRule],
) -> permission_types.MappingContext:
    return permission_types.MappingContext(
        mapping_rules=mapping_rules,
        providers=context.providers,
        saml_groups_attribute_names=context.saml_groups_attribute_names,
        services_by_id=context.services_by_id,
        repos_by_external_service_id=context.repos_by_external_service_id,
        all_repos_by_id=context.all_repos_by_id,
    )


def _users_matching_any_mapping_rule(
    context: permission_types.MappingContext,
    users: list[shared_types.User],
) -> list[shared_types.User]:
    """Return users matched by at least one mapping rule's user selector."""
    return [
        user
        for user in users
        if any(
            permissions_mapping.user_matches_user_selector(
                mapping_rule["users"],
                user,
                context.providers,
                context.saml_groups_attribute_names,
            )
            for mapping_rule in context.mapping_rules
        )
    ]


def _mapping_rules_matching_selected_users(
    context: permission_types.MappingContext,
    users: list[shared_types.User],
) -> list[permission_types.MappingRule]:
    matching_rules: list[permission_types.MappingRule] = []
    for mapping_rule in context.mapping_rules:
        if any(
            permissions_mapping.user_matches_user_selector(
                mapping_rule["users"],
                user,
                context.providers,
                context.saml_groups_attribute_names,
            )
            for user in users
        ):
            matching_rules.append(mapping_rule)
    return matching_rules


def _service_ids_required_by_mapping_rules(
    context: permission_types.MappingContext,
    mapping_rules: list[permission_types.MappingRule],
) -> set[int]:
    return permissions_mapping.service_ids_required_by_repository_selectors(
        context.services_by_id,
        [mapping_rule["repos"] for mapping_rule in mapping_rules],
    )


def _providers_need_saml_account_data(providers: list[shared_types.AuthProvider]) -> bool:
    """Return whether output needs SAML accountData-derived group counts."""
    return any(provider["serviceType"] == saml_groups.SAML_SERVICE_TYPE for provider in providers)


def _repository_filter_selected(
    repository_names: tuple[str, ...],
    repositories_without_explicit_perms: bool,
    repository_created_after: str | None,
) -> bool:
    return any(
        (
            bool(repository_names),
            repositories_without_explicit_perms,
            repository_created_after is not None,
        )
    )


def _repository_ids(candidates: list[permissions_sourcegraph.RepositoryCandidate]) -> set[str]:
    return {candidate.repository["id"] for candidate in candidates}


def _load_get_repository_filter_ids(
    client: src.SourcegraphClient,
    *,
    repository_names: tuple[str, ...],
    repository_created_after: str | None,
) -> set[str] | None:
    """Return selected repo IDs for get snapshot filtering when known up front."""
    if repository_names:
        return _repository_ids(load_repository_candidates_by_names(client, repository_names))
    if repository_created_after is not None:
        return _repository_ids(
            load_repository_candidates_created_on_or_after(
                client,
                repository_created_after,
                "--repos-created-after",
            )
        )
    return None


def _filter_get_snapshot_to_repositories_without_explicit_perms(
    client: src.SourcegraphClient,
    before_snapshot: permission_snapshot.Snapshot,
) -> permission_snapshot.Snapshot:
    """Return a get snapshot scoped to repos with no explicit API grants."""
    candidates = permissions_sourcegraph.list_repository_candidates(client)
    explicit_repository_ids = set(before_snapshot["repos"])
    selected_repository_ids = {
        candidate.repository["id"]
        for candidate in candidates
        if candidate.repository["id"] not in explicit_repository_ids
    }
    log.info(
        "Selected %d / %d repo(s) without explicit repo permissions.",
        len(selected_repository_ids),
        len(candidates),
    )
    return permission_snapshot.snapshot_with_repository_filter(
        before_snapshot,
        selected_repository_ids,
    )


def cmd_get(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    *,
    user_identifiers: tuple[str, ...],
    users_without_explicit_perms: bool,
    user_created_after: str | None,
    repository_names: tuple[str, ...],
    repositories_without_explicit_perms: bool,
    repository_created_after: str | None,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    auth_providers_by_config_id: dict[str, dict[str, Any]],
    do_backup: bool,
    retain_saml_group_users: bool = False,
    worker_pool: ThreadPoolExecutor | None = None,
) -> run_context.CommandData:
    """Refresh the generated discovery YAML files.

    `run_paths.code_hosts_path` receives Sourcegraph code host connection
    configs, `run_paths.auth_providers_path` receives auth provider configs,
    and `run_paths.maps_path` names the maps file recorded in the snapshot.

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
    cmd_fields: dict[str, Any] = {}
    if user_identifiers:
        cmd_fields["user_identifiers"] = user_identifiers
    if users_without_explicit_perms:
        cmd_fields["users_without_explicit_perms"] = True
    if user_created_after is not None:
        cmd_fields["created_after"] = user_created_after
    if repository_names:
        cmd_fields["repositories"] = repository_names
    if repositories_without_explicit_perms:
        cmd_fields["repositories_without_explicit_perms"] = True
    if repository_created_after is not None:
        cmd_fields["repositories_created_after"] = repository_created_after
    if not do_backup:
        cmd_fields["backup"] = False

    with src.span("cmd_get", **cmd_fields) as cmd_event:
        raw_providers, raw_services, attribute_names_by_provider = load_discovery(
            client, saml_groups_attribute_name_by_config_id
        )
        services = [permissions_maps.external_service_to_yaml(service) for service in raw_services]
        cmd_event["auth_provider_count"] = len(raw_providers)
        cmd_event["external_service_count"] = len(services)
        include_user_account_data = _providers_need_saml_account_data(raw_providers)

        users = load_selected_users(
            client,
            user_identifiers=user_identifiers,
            users_without_explicit_perms=users_without_explicit_perms,
            user_created_after=user_created_after,
            parallelism=parallelism,
            explicit_permissions_batch_size=explicit_permissions_batch_size,
            include_account_data=include_user_account_data,
            worker_pool=worker_pool,
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
        cmd_event["selected_user_count"] = len(users)
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

        if run_paths.write_files:
            permissions_maps.dump_code_hosts_yaml(run_paths.code_hosts_path, services)
            permissions_maps.dump_auth_providers_yaml(run_paths.auth_providers_path, providers)
            log.info("Wrote %s and %s", run_paths.code_hosts_path, run_paths.auth_providers_path)
        else:
            log.info("Skipping code-hosts.yaml and auth-providers.yaml because --no-files is set.")
        cmd_event["code_hosts_path"] = str(run_paths.code_hosts_path)
        cmd_event["auth_providers_path"] = str(run_paths.auth_providers_path)
        cmd_event["maps_path"] = str(run_paths.maps_path)

        if do_backup:
            selected_repository_ids = _load_get_repository_filter_ids(
                client,
                repository_names=repository_names,
                repository_created_after=repository_created_after,
            )
            before_snapshot = permission_snapshot.build_snapshot(
                client,
                users,
                parallelism,
                bind_id_mode,
                run_paths.maps_path,
                expected_user_count=len(users),
                explicit_permissions_batch_size=explicit_permissions_batch_size,
                worker_pool=worker_pool,
                selected_repository_ids=selected_repository_ids,
            )
            if repositories_without_explicit_perms:
                before_snapshot = _filter_get_snapshot_to_repositories_without_explicit_perms(
                    client,
                    before_snapshot,
                )
            if run_paths.write_files:
                before_path = run_paths.artifact_path("before")
                permission_snapshot.write_snapshot(before_path, before_snapshot)
                cmd_event["before_snapshot_path"] = str(before_path)
                maps_backup_path = write_maps_backup(run_paths.maps_path, run_paths)
                if maps_backup_path is not None:
                    cmd_event["maps_backup_path"] = str(maps_backup_path)
                log.info(
                    "Wrote before-snapshot: %s "
                    "(%d repo(s) with explicit grants, %d total grant(s)).",
                    before_path,
                    before_snapshot["stats"]["repos_with_explicit_grants"],
                    before_snapshot["stats"]["total_grants"],
                )
            else:
                log.info("Skipping get before-snapshot and maps backup because --no-files is set.")
        else:
            log.info("Skipping get before-snapshot and maps backup because --no-backup is set.")
        saml_group_users = (
            saml_groups.compact_saml_group_users(
                users,
                raw_providers,
                attribute_names_by_provider,
            )
            if not user_identifiers
            and not users_without_explicit_perms
            and user_created_after is None
            and not _repository_filter_selected(
                repository_names,
                repositories_without_explicit_perms,
                repository_created_after,
            )
            and retain_saml_group_users
            else None
        )
        return run_context.CommandData(
            auth_providers=raw_providers,
            saml_group_users=saml_group_users,
            auth_provider_views=providers,
            code_host_views=services,
        )


def load_selected_users(
    client: src.SourcegraphClient,
    *,
    user_identifiers: tuple[str, ...],
    users_without_explicit_perms: bool,
    user_created_after: str | None,
    parallelism: int,
    explicit_permissions_batch_size: int,
    include_account_data: bool,
    include_organizations: bool = False,
    worker_pool: ThreadPoolExecutor | None,
) -> list[shared_types.User]:
    """Load the Sourcegraph users selected by the shared user filters.

    Used by the get command and by the standalone scoped sync-saml-orgs
    modes; `include_organizations` rides the users' org memberships along
    in the same queries for scoped org sync.
    """
    if user_identifiers:
        users = _resolve_user_identifiers(
            client,
            user_identifiers,
            include_account_data=include_account_data,
            include_organizations=include_organizations,
        )
        if user_created_after is None:
            return users
        candidate_user_ids = user_ids_created_on_or_after(client, user_created_after)
        selected_users: list[shared_types.User] = []
        for user in users:
            if user["id"] in candidate_user_ids:
                selected_users.append(user)
                continue
            log.info(
                "User %s was not created on or after %s — no user metadata selected.",
                user["username"],
                user_created_after,
            )
        return selected_users

    if users_without_explicit_perms or user_created_after is not None:
        created_after_filter: str | None = None
        if user_created_after is not None:
            created_after_filter = sourcegraph_datetime_filter(
                parse_cli_date(user_created_after, "--created-after")
            )
        if users_without_explicit_perms:
            candidate_selection = (
                permissions_sourcegraph.list_site_user_candidates_without_explicit_repos(
                    client,
                    created_after_filter,
                    batch_size=explicit_permissions_batch_size,
                    parallelism=parallelism,
                    worker_pool=worker_pool,
                )
            )
            candidates = candidate_selection.candidates
            log.info(
                "Selected %d active user candidate(s) without explicit repo permissions; "
                "skipped %d with existing explicit permissions.",
                len(candidates),
                candidate_selection.explicit_user_count,
            )
        else:
            candidates = permissions_sourcegraph.list_site_user_candidates(
                client,
                created_after_filter,
                parallelism=parallelism,
                worker_pool=worker_pool,
            )
            log.info("Loaded %d active user candidate(s).", len(candidates))

        users = _hydrate_site_user_candidates(
            client,
            candidates,
            include_account_data=include_account_data,
            include_organizations=include_organizations,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )
        log.info("Selected %d user(s) for get output.", len(users))
        return users

    return _load_all_get_users(
        client,
        include_account_data=include_account_data,
        include_organizations=include_organizations,
    )


def _load_all_get_users(
    client: src.SourcegraphClient,
    *,
    include_account_data: bool,
    include_organizations: bool = False,
) -> list[shared_types.User]:
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
    for completed, user in enumerate(
        shared_sourcegraph.list_users_streaming(
            client,
            include_account_data=include_account_data,
            include_organizations=include_organizations,
        ),
        start=1,
    ):
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


def _hydrate_site_user_candidates(
    client: src.SourcegraphClient,
    candidates: list[shared_types.SiteUserCandidate],
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    include_organizations: bool = False,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None,
) -> list[shared_types.User]:
    """Hydrate filtered site-user candidates into full user metadata."""
    if not candidates:
        return []

    log.info(
        "Hydrating Sourcegraph metadata for %d selected user candidate(s) "
        "in batches of %d with parallelism=%d ...",
        len(candidates),
        permissions_sourcegraph.USER_HYDRATION_BATCH_SIZE,
        parallelism,
    )
    hydrated_users = permissions_sourcegraph.get_users_by_ids(
        client,
        [candidate["id"] for candidate in candidates],
        include_emails=include_emails,
        include_account_data=include_account_data,
        include_organizations=include_organizations,
        parallelism=parallelism,
        worker_pool=worker_pool,
        progress_label="Hydrated selected Sourcegraph user metadata",
    )
    users = [user for user in hydrated_users if user is not None]
    missing_user_count = len(hydrated_users) - len(users)
    if missing_user_count:
        log.warning(
            "Skipped %d selected user candidate(s) that no longer exist.",
            missing_user_count,
        )
    log.info("Hydrated metadata for %d selected user(s).", len(users))
    return users


def _log_user_planning_progress(
    completed: int,
    total_count: int,
    started: float,
    *,
    grant_count: int,
) -> None:
    elapsed = time.perf_counter() - started
    rate = completed / elapsed if elapsed > 0 else 0.0
    remaining = max(total_count - completed, 0)
    eta_seconds = remaining / rate if rate > 0 else 0.0
    log.info(
        "Planned additive grants for %d / %d selected user(s) (%.0f%%) "
        "in %.0fs (%.0f users/sec, ETA %.0fs): grant_count=%d.",
        completed,
        total_count,
        100.0 * completed / total_count,
        elapsed,
        rate,
        eta_seconds,
        grant_count,
    )


def _additive_command_data(
    context: permission_types.MappingContext | None,
    selected_users: list[shared_types.User],
    retain_saml_group_users: bool,
) -> run_context.CommandData:
    """Build an additive set command's result data.

    When `retain_saml_group_users` is set, the selected users are compacted
    into `scoped_saml_group_users` so a subsequent `--sync-saml-orgs` phase
    syncs org membership for exactly these users — per-user additions and
    removals — without streaming all users again. An empty selection yields
    an empty scope (org sync no-ops), never a full-instance sync.
    """
    providers = context.providers if context is not None else None
    if not retain_saml_group_users:
        return run_context.CommandData(auth_providers=providers)
    return run_context.CommandData(
        auth_providers=providers,
        scoped_saml_group_users=saml_groups.compact_scoped_saml_group_users(
            selected_users,
            providers or [],
            context.saml_groups_attribute_names if context is not None else {},
        ),
    )


def cmd_set(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    set_options: permission_types.SetCommandOptions,
    *,
    dry_run: bool,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    retain_saml_group_users: bool = False,
    worker_pool: ThreadPoolExecutor | None = None,
    mapping_rules: list[permission_types.MappingRule] | None = None,
) -> run_context.CommandData:
    """Dispatch the selected set mode.

    `mapping_rules` carries in-memory rules from module callers; when None,
    rules are loaded from `run_paths.maps_path`.
    """
    options = set_options
    if options.mode == "full":
        return permissions_full_set.cmd_set_full(
            client,
            run_paths,
            options.user_created_after,
            repository_names=(),
            repositories_without_explicit_perms=False,
            repository_created_after=None,
            dry_run=dry_run,
            parallelism=parallelism,
            explicit_permissions_batch_size=explicit_permissions_batch_size,
            bind_id_mode=bind_id_mode,
            saml_groups_attribute_name_by_config_id=saml_groups_attribute_name_by_config_id,
            do_backup=do_backup,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
            mapping_rules=mapping_rules,
        )
    if options.mode == "repos":
        assert options.repository_names
        return permissions_full_set.cmd_set_full(
            client,
            run_paths,
            None,
            repository_names=options.repository_names,
            repositories_without_explicit_perms=False,
            repository_created_after=None,
            dry_run=dry_run,
            parallelism=parallelism,
            explicit_permissions_batch_size=explicit_permissions_batch_size,
            bind_id_mode=bind_id_mode,
            saml_groups_attribute_name_by_config_id=saml_groups_attribute_name_by_config_id,
            do_backup=do_backup,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
            mapping_rules=mapping_rules,
        )
    if options.mode == "repos_without_explicit_perms":
        return permissions_full_set.cmd_set_full(
            client,
            run_paths,
            None,
            repository_names=(),
            repositories_without_explicit_perms=True,
            repository_created_after=None,
            dry_run=dry_run,
            parallelism=parallelism,
            explicit_permissions_batch_size=explicit_permissions_batch_size,
            bind_id_mode=bind_id_mode,
            saml_groups_attribute_name_by_config_id=saml_groups_attribute_name_by_config_id,
            do_backup=do_backup,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
            mapping_rules=mapping_rules,
        )
    if options.mode == "repos_created_after":
        assert options.repository_created_after is not None
        return permissions_full_set.cmd_set_full(
            client,
            run_paths,
            None,
            repository_names=(),
            repositories_without_explicit_perms=False,
            repository_created_after=options.repository_created_after,
            dry_run=dry_run,
            parallelism=parallelism,
            explicit_permissions_batch_size=explicit_permissions_batch_size,
            bind_id_mode=bind_id_mode,
            saml_groups_attribute_name_by_config_id=saml_groups_attribute_name_by_config_id,
            do_backup=do_backup,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
            mapping_rules=mapping_rules,
        )
    if options.mode == "users":
        assert options.user_identifiers
        return cmd_set_additive_users(
            client,
            run_paths,
            options.user_identifiers,
            options.user_created_after,
            dry_run,
            parallelism,
            bind_id_mode,
            saml_groups_attribute_name_by_config_id,
            do_backup,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
            mapping_rules=mapping_rules,
        )
    if options.mode == "users_without_explicit_perms":
        return cmd_set_additive_users_without_explicit_perms(
            client,
            run_paths,
            options.user_created_after,
            dry_run,
            parallelism,
            explicit_permissions_batch_size,
            bind_id_mode,
            saml_groups_attribute_name_by_config_id,
            do_backup,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
            mapping_rules=mapping_rules,
        )
    if options.mode == "created_after":
        assert options.user_created_after is not None
        return cmd_set_additive_created_after(
            client,
            run_paths,
            options.user_created_after,
            dry_run,
            parallelism,
            bind_id_mode,
            saml_groups_attribute_name_by_config_id,
            do_backup,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
            mapping_rules=mapping_rules,
        )
    return run_context.CommandData()


def cmd_set_additive_users(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    user_identifiers: tuple[str, ...],
    user_created_after: str | None,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    retain_saml_group_users: bool = False,
    worker_pool: ThreadPoolExecutor | None = None,
    mapping_rules: list[permission_types.MappingRule] | None = None,
) -> run_context.CommandData:
    """Add missing mapped permissions for resolved users."""
    with src.span(
        "cmd_set_additive_users",
        input_path=str(run_paths.maps_path),
        user_identifiers=user_identifiers,
        user_created_after=user_created_after,
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ):
        mapping_rules = resolve_mapping_rules(mapping_rules, run_paths.maps_path)
        if not mapping_rules:
            log.warning("No maps defined in %s — nothing to do.", run_paths.maps_path)
            return _additive_command_data(None, [], retain_saml_group_users)
        include_user_emails = permissions_mapping.mapping_rules_need_user_emails(mapping_rules)
        include_user_account_data = (
            permissions_mapping.mapping_rules_need_saml_account_data(mapping_rules)
            or retain_saml_group_users
        )
        users = _resolve_user_identifiers(
            client,
            user_identifiers,
            include_emails=include_user_emails,
            include_account_data=include_user_account_data,
            include_organizations=retain_saml_group_users,
        )
        context = load_mapping_context_discovery(
            client,
            mapping_rules,
            saml_groups_attribute_name_by_config_id,
        )
        if user_created_after is not None:
            candidate_user_ids = user_ids_created_on_or_after(client, user_created_after)
            selected_users: list[shared_types.User] = []
            for user in users:
                if user["id"] in candidate_user_ids:
                    selected_users.append(user)
                    continue
                log.info(
                    "User %s was not created on or after %s — nothing to do.",
                    user["username"],
                    user_created_after,
                )
            users = selected_users
            if not users:
                return _additive_command_data(context, users, retain_saml_group_users)

        matching_rules = _mapping_rules_matching_selected_users(context, users)
        log.info(
            "%d / %d mapping rule(s) match the selected user(s).",
            len(matching_rules),
            len(context.mapping_rules),
        )
        if not matching_rules:
            _run_additive_apply(
                client,
                run_paths,
                users,
                [],
                dry_run=dry_run,
                parallelism=parallelism,
                bind_id_mode=bind_id_mode,
                do_backup=do_backup,
                worker_pool=worker_pool,
            )
            return _additive_command_data(context, users, retain_saml_group_users)

        service_ids = _service_ids_required_by_mapping_rules(context, matching_rules)
        log.info(
            "Selected mapping rule(s) require repo scans for %d / %d code host connection(s).",
            len(service_ids),
            len(context.services_by_id),
        )
        context = load_repos_for_mapping_context(
            client,
            _mapping_context_with_rules(context, matching_rules),
            service_ids,
        )
        resolved_mappings = resolve_additive_mappings(context)
        additions: list[permissions_apply.PermissionAddition] = []
        existing_repos_by_user_id = (
            _load_selected_user_explicit_repos(client, users) if do_backup else None
        )
        for user in users:
            existing_repo_ids = None
            if existing_repos_by_user_id is not None:
                existing_repo_ids = {
                    repository["id"] for repository in existing_repos_by_user_id[user["id"]]
                }
            additions.extend(
                _plan_additions_for_user(
                    client,
                    context,
                    resolved_mappings,
                    user,
                    existing_repo_ids=existing_repo_ids,
                )
            )
        _run_additive_apply(
            client,
            run_paths,
            users,
            additions,
            dry_run=dry_run,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            do_backup=do_backup,
            existing_repos_by_user_id=existing_repos_by_user_id,
            worker_pool=worker_pool,
        )
        return _additive_command_data(context, users, retain_saml_group_users)


def cmd_set_additive_users_without_explicit_perms(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    user_created_after: str | None,
    dry_run: bool,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    retain_saml_group_users: bool = False,
    worker_pool: ThreadPoolExecutor | None = None,
    mapping_rules: list[permission_types.MappingRule] | None = None,
) -> run_context.CommandData:
    """Add mapped permissions for users with no explicit API grants."""
    created_after_filter: str | None = None
    if user_created_after is not None:
        created_after_filter = sourcegraph_datetime_filter(
            parse_cli_date(user_created_after, "--created-after")
        )
    with src.span(
        "cmd_set_additive_users_without_explicit_perms",
        input_path=str(run_paths.maps_path),
        user_created_after=user_created_after,
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ):
        mapping_rules = resolve_mapping_rules(mapping_rules, run_paths.maps_path)
        if not mapping_rules:
            log.warning("No maps defined in %s — nothing to do.", run_paths.maps_path)
            return _additive_command_data(None, [], retain_saml_group_users)
        context = load_mapping_context_discovery(
            client,
            mapping_rules,
            saml_groups_attribute_name_by_config_id,
        )
        include_user_emails = permissions_mapping.mapping_rules_need_user_emails(mapping_rules)
        include_user_account_data = (
            permissions_mapping.mapping_rules_need_saml_account_data(mapping_rules)
            or retain_saml_group_users
        )
        # Match mapping rules BEFORE the explicit-permission check: the
        # per-user `permissionsInfo.repositories(source: API, first: 1)`
        # probe costs ~0.2-0.4s of server CPU per user regardless of
        # batching (the resolver materializes every accessible repo before
        # the LIMIT applies), while rule matching is local. Checking only
        # rule-matched users keeps the expensive probes proportional to the
        # maps.yaml scope instead of the whole instance.
        candidates = permissions_sourcegraph.list_site_user_candidates(
            client,
            created_after_filter,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )
        all_users = _hydrate_site_user_candidates(
            client,
            candidates,
            include_emails=include_user_emails,
            include_account_data=include_user_account_data,
            include_organizations=retain_saml_group_users,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )
        matched_users = _users_matching_any_mapping_rule(context, all_users)
        log.info(
            "%d / %d active user(s) match a mapping rule's user selector.",
            len(matched_users),
            len(all_users),
        )
        explicit_user_ids: set[str] = set()
        if matched_users:
            log.info(
                "Checking %d matched user(s) for existing explicit repo permissions "
                "in batches of %d ...",
                len(matched_users),
                explicit_permissions_batch_size,
            )
            explicit_user_ids = permissions_sourcegraph.user_ids_with_explicit_repos(
                client,
                [user["id"] for user in matched_users],
                batch_size=explicit_permissions_batch_size,
                parallelism=parallelism,
                worker_pool=worker_pool,
            )
        users = [user for user in matched_users if user["id"] not in explicit_user_ids]
        log.info(
            "Selected %d matched user(s) without explicit repo permissions; "
            "skipped %d with existing explicit permissions.",
            len(users),
            len(explicit_user_ids),
        )
        if not users:
            _run_additive_apply(
                client,
                run_paths,
                users,
                [],
                dry_run=dry_run,
                parallelism=parallelism,
                bind_id_mode=bind_id_mode,
                do_backup=do_backup,
                worker_pool=worker_pool,
            )
            return _additive_command_data(context, users, retain_saml_group_users)

        matching_rules = _mapping_rules_matching_selected_users(context, users)
        log.info(
            "%d / %d mapping rule(s) match the selected user(s).",
            len(matching_rules),
            len(context.mapping_rules),
        )
        if not matching_rules:
            _run_additive_apply(
                client,
                run_paths,
                users,
                [],
                dry_run=dry_run,
                parallelism=parallelism,
                bind_id_mode=bind_id_mode,
                do_backup=do_backup,
                worker_pool=worker_pool,
            )
            return _additive_command_data(context, users, retain_saml_group_users)

        service_ids = _service_ids_required_by_mapping_rules(context, matching_rules)
        log.info(
            "Selected mapping rule(s) require repo scans for %d / %d code host connection(s).",
            len(service_ids),
            len(context.services_by_id),
        )
        context = load_repos_for_mapping_context(
            client,
            _mapping_context_with_rules(context, matching_rules),
            service_ids,
        )
        resolved_mappings = resolve_additive_mappings(context)
        additions: list[permissions_apply.PermissionAddition] = []
        started = time.perf_counter()
        progress_step = max(1, len(users) // 10) if users else 1
        next_progress_report = progress_step
        log.info("Planning additive grants for %d selected user(s) ...", len(users))
        for completed, user in enumerate(users, start=1):
            user_additions = _plan_additions_for_user(
                client,
                context,
                resolved_mappings,
                user,
                existing_repo_ids=set(),
            )
            additions.extend(user_additions)
            if completed >= next_progress_report or completed == len(users):
                _log_user_planning_progress(
                    completed,
                    len(users),
                    started,
                    grant_count=len(additions),
                )
                while next_progress_report <= completed:
                    next_progress_report += progress_step

        log.info(
            "Planned additive grants for %d user(s) with no explicit grants.",
            len(users),
        )
        _run_additive_apply(
            client,
            run_paths,
            users,
            additions,
            dry_run=dry_run,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            do_backup=do_backup,
            worker_pool=worker_pool,
        )
        return _additive_command_data(context, users, retain_saml_group_users)


def cmd_set_additive_created_after(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    user_created_after: str,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    retain_saml_group_users: bool = False,
    worker_pool: ThreadPoolExecutor | None = None,
    mapping_rules: list[permission_types.MappingRule] | None = None,
) -> run_context.CommandData:
    """Add missing mapped permissions for users created on or after a date."""
    created_after_filter = sourcegraph_datetime_filter(
        parse_cli_date(user_created_after, "--created-after")
    )
    with src.span(
        "cmd_set_additive_created_after",
        input_path=str(run_paths.maps_path),
        user_created_after=user_created_after,
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ):
        mapping_rules = resolve_mapping_rules(mapping_rules, run_paths.maps_path)
        if not mapping_rules:
            log.warning("No maps defined in %s — nothing to do.", run_paths.maps_path)
            return _additive_command_data(None, [], retain_saml_group_users)
        context = load_mapping_context_discovery(
            client,
            mapping_rules,
            saml_groups_attribute_name_by_config_id,
        )
        include_user_emails = permissions_mapping.mapping_rules_need_user_emails(mapping_rules)
        include_user_account_data = (
            permissions_mapping.mapping_rules_need_saml_account_data(mapping_rules)
            or retain_saml_group_users
        )
        candidates = permissions_sourcegraph.list_site_user_candidates(
            client,
            created_after_filter,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )
        log.info(
            "Selected %d active user candidate(s) created on or after %s.",
            len(candidates),
            user_created_after,
        )
        users = _hydrate_site_user_candidates(
            client,
            candidates,
            include_emails=include_user_emails,
            include_account_data=include_user_account_data,
            include_organizations=retain_saml_group_users,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )
        if not users:
            _run_additive_apply(
                client,
                run_paths,
                users,
                [],
                dry_run=dry_run,
                parallelism=parallelism,
                bind_id_mode=bind_id_mode,
                do_backup=do_backup,
                worker_pool=worker_pool,
            )
            return _additive_command_data(context, users, retain_saml_group_users)

        matching_rules = _mapping_rules_matching_selected_users(context, users)
        log.info(
            "%d / %d mapping rule(s) match the selected user(s).",
            len(matching_rules),
            len(context.mapping_rules),
        )
        if not matching_rules:
            _run_additive_apply(
                client,
                run_paths,
                users,
                [],
                dry_run=dry_run,
                parallelism=parallelism,
                bind_id_mode=bind_id_mode,
                do_backup=do_backup,
                worker_pool=worker_pool,
            )
            return _additive_command_data(context, users, retain_saml_group_users)

        service_ids = _service_ids_required_by_mapping_rules(context, matching_rules)
        log.info(
            "Selected mapping rule(s) require repo scans for %d / %d code host connection(s).",
            len(service_ids),
            len(context.services_by_id),
        )
        context = load_repos_for_mapping_context(
            client,
            _mapping_context_with_rules(context, matching_rules),
            service_ids,
        )
        resolved_mappings = resolve_additive_mappings(context)
        additions: list[permissions_apply.PermissionAddition] = []
        existing_repos_by_user_id = (
            _load_selected_user_explicit_repos(client, users) if do_backup else None
        )
        for user in users:
            existing_repo_ids = None
            if existing_repos_by_user_id is not None:
                existing_repo_ids = {
                    repository["id"] for repository in existing_repos_by_user_id[user["id"]]
                }
            additions.extend(
                _plan_additions_for_user(
                    client,
                    context,
                    resolved_mappings,
                    user,
                    existing_repo_ids=existing_repo_ids,
                )
            )
        _run_additive_apply(
            client,
            run_paths,
            users,
            additions,
            dry_run=dry_run,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            do_backup=do_backup,
            existing_repos_by_user_id=existing_repos_by_user_id,
            worker_pool=worker_pool,
        )
        return _additive_command_data(context, users, retain_saml_group_users)


def _resolve_user_identifiers(
    client: src.SourcegraphClient,
    user_identifiers: tuple[str, ...],
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    include_organizations: bool = False,
) -> list[shared_types.User]:
    """Resolve username/email inputs to distinct Sourcegraph users in caller order."""
    users: list[shared_types.User] = []
    seen_user_ids: set[str] = set()
    for user_identifier in user_identifiers:
        user = _resolve_user_identifier(
            client,
            user_identifier,
            include_emails=include_emails,
            include_account_data=include_account_data,
            include_organizations=include_organizations,
        )
        if user["id"] in seen_user_ids:
            continue
        seen_user_ids.add(user["id"])
        users.append(user)
    return users


def _resolve_user_identifier(
    client: src.SourcegraphClient,
    user_identifier: str,
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    include_organizations: bool = False,
) -> shared_types.User:
    """Resolve username/email input to one Sourcegraph user."""
    user: shared_types.User | None
    if "@" in user_identifier:
        user = permissions_sourcegraph.get_user_by_email(
            client,
            user_identifier,
            include_emails=include_emails,
            include_account_data=include_account_data,
            include_organizations=include_organizations,
        ) or permissions_sourcegraph.get_user_by_username(
            client,
            user_identifier,
            include_emails=include_emails,
            include_account_data=include_account_data,
            include_organizations=include_organizations,
        )
    else:
        user = permissions_sourcegraph.get_user_by_username(
            client,
            user_identifier,
            include_emails=include_emails,
            include_account_data=include_account_data,
            include_organizations=include_organizations,
        ) or permissions_sourcegraph.get_user_by_email(
            client,
            user_identifier,
            include_emails=include_emails,
            include_account_data=include_account_data,
            include_organizations=include_organizations,
        )
    if user is None:
        raise SystemExit(f"No Sourcegraph user found for {user_identifier!r}.")
    if user["username"] != user_identifier:
        log.info("Resolved %s to Sourcegraph username %s.", user_identifier, user["username"])
    return user


def _load_selected_user_explicit_repos(
    client: src.SourcegraphClient,
    users: list[shared_types.User],
) -> dict[str, list[permission_types.Repository]]:
    """Fetch selected users' explicit repos once for planning and snapshots."""
    with src.span("load_selected_user_explicit_repos", user_count=len(users)) as load_event:
        repos_by_user_id = {
            user["id"]: permissions_sourcegraph.list_user_explicit_repos(
                client,
                user["id"],
            )
            for user in users
        }
        load_event["total_grants"] = sum(len(repos) for repos in repos_by_user_id.values())
        return repos_by_user_id


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
        if not permissions_mapping.user_matches_user_selector(
            resolved_mapping.user_selector,
            user,
            context.providers,
            context.saml_groups_attribute_names,
        ):
            continue
        for repository in resolved_mapping.repos:
            desired_repos[repository["id"]] = repository

    if not desired_repos:
        log.info("User %s: no desired repo grants.", user["username"])
        return []

    if existing_repo_ids is None:
        existing_repo_ids = set(
            permissions_sourcegraph.list_user_explicit_repo_ids(client, user["id"])
        )
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


def _write_additive_initial_artifacts(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    snapshot_users: list[permission_snapshot.SnapshotUser],
    additions: list[permissions_apply.PermissionAddition],
    *,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    existing_repos_by_user_id: dict[str, list[permission_types.Repository]] | None = None,
    worker_pool: ThreadPoolExecutor | None = None,
) -> permission_snapshot.UserScopedSnapshot:
    """Capture before-snapshot and write dry-run/no-op additive artifacts."""
    if existing_repos_by_user_id is None:
        before_snapshot = permission_snapshot.build_user_scoped_snapshot(
            client,
            snapshot_users,
            parallelism,
            bind_id_mode,
            run_paths.maps_path,
            worker_pool=worker_pool,
        )
    else:
        before_snapshot = permission_snapshot.build_user_scoped_snapshot_from_repos(
            client,
            snapshot_users,
            existing_repos_by_user_id,
            bind_id_mode,
            run_paths.maps_path,
        )
    after_planned_snapshot = _user_scoped_snapshot_with_additions(
        before_snapshot,
        additions,
    )
    if run_paths.write_files:
        before_path = run_paths.artifact_path("before")
        permission_snapshot.write_user_scoped_snapshot(before_path, before_snapshot)
        log.info("Wrote scoped before-snapshot: %s", before_path)
        if dry_run or not additions:
            after_path = run_paths.artifact_path("after")
            permission_snapshot.write_user_scoped_snapshot(after_path, after_planned_snapshot)
            diff_path = write_user_scoped_snapshot_diff_file(
                run_paths,
                before_snapshot,
                after_planned_snapshot,
            )
            log.info("Wrote scoped after-snapshot: %s diff=%s", after_path, diff_path)
        maps_backup_path = write_maps_backup(run_paths.maps_path, run_paths)
        if maps_backup_path is not None:
            log.info("Wrote maps backup for additive run: %s", maps_backup_path)
    else:
        log.info("Skipping additive snapshot and maps backup files because --no-files is set.")
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
            src.decode_repository_id(addition.repo_id),
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
        "Additive apply done. %d succeeded, %d skipped, %d failed, %d canceled.",
        mutations.succeeded,
        mutations.skipped,
        mutations.failed,
        mutations.canceled,
    )
    # Structured counts, mirroring the full-set and restore command events so
    # every apply path reports mutations_succeeded in the run log.
    src.info(
        "additive_apply_done",
        mutations_succeeded=mutations.succeeded,
        mutations_skipped=mutations.skipped,
        mutations_failed=mutations.failed,
        mutations_canceled=mutations.canceled,
    )
    return mutations


def _finish_additive_apply_with_backup(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    snapshot_users: list[permission_snapshot.SnapshotUser],
    before_snapshot: permission_snapshot.UserScopedSnapshot,
    additions: list[permissions_apply.PermissionAddition],
    *,
    parallelism: int,
    bind_id_mode: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Capture and validate additive post-apply state."""
    after_snapshot = permission_snapshot.build_user_scoped_snapshot(
        client,
        snapshot_users,
        parallelism,
        bind_id_mode,
        run_paths.maps_path,
        worker_pool=worker_pool,
    )
    if run_paths.write_files:
        after_path = run_paths.artifact_path("after")
        permission_snapshot.write_user_scoped_snapshot(after_path, after_snapshot)
        diff_path = write_user_scoped_snapshot_diff_file(
            run_paths,
            before_snapshot,
            after_snapshot,
        )
        log.info("Wrote scoped after-snapshot: %s diff=%s", after_path, diff_path)
    else:
        log.info("Skipping scoped after-snapshot files because --no-files is set.")
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
    run_paths: backups.RunPaths,
    users: list[shared_types.User],
    additions: list[permissions_apply.PermissionAddition],
    *,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    do_backup: bool,
    existing_repos_by_user_id: dict[str, list[permission_types.Repository]] | None = None,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Snapshot, dry-run, apply, and validate an additive permission plan."""
    if not users:
        log.info("No users selected — nothing to do.")
        return

    snapshot_users = _snapshot_users_from_users(users)
    before_snapshot: permission_snapshot.UserScopedSnapshot | None = None
    if do_backup:
        before_snapshot = _write_additive_initial_artifacts(
            client,
            run_paths,
            snapshot_users,
            additions,
            dry_run=dry_run,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            existing_repos_by_user_id=existing_repos_by_user_id,
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
            run_paths,
            snapshot_users,
            before_snapshot,
            additions,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
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
            {"id": addition.user_id, "repos": []},
        )
        repositories = {repository["id"]: repository for repository in user_snapshot["repos"]}
        repositories[addition.repo_id] = {"id": addition.repo_id, "name": addition.repo_name}
        user_snapshot["repos"] = sorted(
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
            "repos": list(user_snapshot["repos"]),
        }
        for username, user_snapshot in snapshot["users"].items()
    }


def _copy_user_scoped_snapshot_with_users(
    snapshot: permission_snapshot.UserScopedSnapshot,
    users: dict[str, permission_snapshot.UserScopedUserSnapshot],
) -> permission_snapshot.UserScopedSnapshot:
    total_grants = sum(len(user_snapshot["repos"]) for user_snapshot in users.values())
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
                1 for user_snapshot in users.values() if user_snapshot["repos"]
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
        username: {repository["id"] for repository in user_snapshot["repos"]}
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
                src.decode_repository_id(addition.repo_id),
            )
        return
    log.info("VALIDATION OK: all %d requested additive grant(s) are present.", len(additions))


def cmd_restore_user_scoped(
    client: src.SourcegraphClient,
    restore_path: Path,
    run_paths: backups.RunPaths,
    *,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    do_backup: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Restore explicit permissions for the users present in a scoped snapshot."""
    permissions_restore.cmd_restore_user_scoped(
        client,
        restore_path,
        run_paths,
        dry_run=dry_run,
        parallelism=parallelism,
        bind_id_mode=bind_id_mode,
        do_backup=do_backup,
        worker_pool=worker_pool,
    )


def cmd_restore(
    client: src.SourcegraphClient,
    restore_path: Path,
    run_paths: backups.RunPaths,
    *,
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
        restore_path,
        run_paths,
        dry_run=dry_run,
        parallelism=parallelism,
        explicit_permissions_batch_size=explicit_permissions_batch_size,
        bind_id_mode=bind_id_mode,
        do_backup=do_backup,
        worker_pool=worker_pool,
    )
