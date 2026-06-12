"""Sourcegraph organization sync command handler."""

from __future__ import annotations

import datetime
import json
import logging
import time
from collections.abc import Iterable
from concurrent.futures import CancelledError, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import src_py_lib as src

from ..permissions import apply as permissions_apply
from ..shared import backups, run_context, saml_groups
from ..shared import sourcegraph as shared_sourcegraph
from ..shared import types as shared_types
from . import queries
from . import types as organization_types

log = logging.getLogger(__name__)

ORGANIZATION_LOOKUP_BATCH_SIZE: int = 50
ORGANIZATION_SEARCH_RESULT_LIMIT: int = 100
ORGANIZATION_MEMBER_PAGE_SIZE: int = 1000
ORGANIZATION_SNAPSHOT_SCHEMA_VERSION: int = 2
ORGANIZATION_SNAPSHOT_DIFF_SCHEMA_VERSION: int = 1
# One `organizations(query: "synced-")` search discovers every tool-managed
# org in a single request. Sourcegraph caps `first:` at 5000 on most
# connections; when an instance exceeds the returned page we fall back to
# per-name lookups (and skip orphaned-org cleanup) rather than miss orgs.
SYNCED_ORGANIZATION_SEARCH_LIMIT: int = 5000

_ALREADY_MEMBER_TEXT = "user is already a member of the organization"
_ORGANIZATION_EXISTS_TEXT = "organization name is already taken"

# Re-exported here for callers that think in org-sync terms; the naming
# rule lives in shared.saml_groups so user compaction can share it.
organization_name_for_saml_group = saml_groups.organization_name_for_saml_group


@dataclass(frozen=True)
class _OrganizationSyncState:
    """Loaded state and planned target for one SAML organization sync."""

    targets: dict[str, organization_types.TargetOrganization]
    current_user: organization_types.OrgMember
    current_states: dict[str, organization_types.OrganizationState]
    before_snapshot: organization_types.OrganizationSnapshot
    plan: organization_types.OrganizationPlan
    expected_snapshot: organization_types.OrganizationSnapshot


@dataclass(frozen=True)
class _OrganizationApplyResult:
    """Mutation counts for all organization sync phases."""

    creates: shared_types.MutationCounts
    additions: shared_types.MutationCounts
    removals: shared_types.MutationCounts


def _load_organization_sync_state(
    client: src.SourcegraphClient,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    parallelism: int,
    command_event: dict[str, Any],
    command_data: run_context.CommandData,
    worker_pool: ThreadPoolExecutor | None = None,
) -> _OrganizationSyncState | None:
    """Discover SAML org targets, live state, and the desired plan."""
    if command_data.auth_providers is None:
        log.info("Querying auth providers from %s ...", client.endpoint)
        providers = shared_sourcegraph.list_auth_providers(client)
    else:
        providers = command_data.auth_providers
        log.info("Reusing %d auth provider(s) loaded earlier in this run.", len(providers))
    saml_providers = [
        provider
        for provider in providers
        if provider["serviceType"] == saml_groups.SAML_SERVICE_TYPE
    ]
    if not saml_providers:
        log.warning("No SAML auth providers found — nothing to sync.")
        return None
    attribute_names_by_provider = saml_groups.attribute_names_by_provider_key(
        providers, saml_groups_attribute_name_by_config_id
    )
    log.info("Received %d SAML auth provider(s).", len(saml_providers))

    targets = _collect_target_organizations(
        providers,
        attribute_names_by_provider,
        client,
        command_data.saml_group_users,
    )

    discovered = _discover_synced_organization_states(client)
    if discovered is None:
        # Truncated discovery: resolve target names individually and skip
        # orphaned-org cleanup this run.
        if not targets:
            log.warning("No SAML group memberships found in user accountData — nothing to sync.")
            return None
        current_user, current_states = _load_current_organization_states(
            client,
            sorted(targets),
            parallelism,
            worker_pool,
        )
    else:
        current_user, synced_states = discovered
        for organization_name in sorted(set(synced_states) - set(targets)):
            # The SAML group behind this synced org is gone (or lost its
            # last member): remove every member but keep the org so admin
            # settings survive if the group comes back.
            targets[organization_name] = organization_types.TargetOrganization(
                name=organization_name,
                provider_config_id="",
                saml_group="",
            )
            log.info(
                "Synced org %s no longer matches any SAML group: "
                "removing all members, keeping the org.",
                organization_name,
            )
        if not targets:
            log.warning(
                "No SAML group memberships found in user accountData "
                "and no synced orgs exist — nothing to sync."
            )
            return None
        current_states = {
            organization_name: synced_states.get(organization_name)
            or organization_types.OrganizationState(
                id=None,
                name=organization_name,
                members_by_id={},
            )
            for organization_name in targets
        }
        with src.span(
            "load_current_organization_states",
            organization_count=len(targets),
            member_page_size=ORGANIZATION_MEMBER_PAGE_SIZE,
        ) as load_event:
            _fetch_members_into_states(client, current_states, parallelism, worker_pool, load_event)

    command_event["target_organizations"] = len(targets)
    command_event["desired_memberships"] = sum(
        len(target.desired_members_by_id) for target in targets.values()
    )
    before_snapshot = _snapshot_from_states(client.endpoint, targets, current_states)
    plan = _plan_organization_sync(targets, current_states, current_user)
    expected_states = _expected_states_from_targets(targets, current_states)
    expected_snapshot = _snapshot_from_states(client.endpoint, targets, expected_states)
    return _OrganizationSyncState(
        targets=targets,
        current_user=current_user,
        current_states=current_states,
        before_snapshot=before_snapshot,
        plan=plan,
        expected_snapshot=expected_snapshot,
    )


def _load_scoped_organization_sync_state(
    client: src.SourcegraphClient,
    scoped_users: list[shared_types.ScopedSamlGroupUser],
    parallelism: int,
    command_event: dict[str, Any],
    worker_pool: ThreadPoolExecutor | None = None,
) -> _OrganizationSyncState | None:
    """Plan a per-user org sync covering only the given users.

    Each user's `accountData` is the complete truth for that user's SAML
    groups, and their own org list is the complete truth for their current
    synced-org memberships — so additions AND removals are both safe per
    user. Users outside the scope are never touched, and neither full user
    streams nor org member pages are loaded.
    """
    log.info(
        "Scoped SAML org sync: planning membership for %d selected user(s) only; "
        "no other users' org memberships will change.",
        len(scoped_users),
    )
    command_event["scoped_user_count"] = len(scoped_users)
    targets: dict[str, organization_types.TargetOrganization] = {}
    collisions: set[str] = set()
    for scoped_user in scoped_users:
        _record_saml_group_user_memberships(targets, collisions, scoped_user)
    _raise_for_target_collisions(collisions)

    current_members_by_organization: dict[str, dict[str, organization_types.OrgMember]] = {}
    organization_ids_by_name: dict[str, str] = {}
    for scoped_user in scoped_users:
        for organization in scoped_user.synced_organizations:
            organization_ids_by_name[organization["name"]] = organization["id"]
            current_members_by_organization.setdefault(organization["name"], {})[
                scoped_user.user_id
            ] = {"id": scoped_user.user_id, "username": scoped_user.username}
    for organization_name in sorted(set(current_members_by_organization) - set(targets)):
        # In-scope user(s) are members of a synced org that matches none of
        # their SAML groups any more: plan their removal (org kept).
        targets[organization_name] = organization_types.TargetOrganization(
            name=organization_name,
            provider_config_id="",
            saml_group="",
        )

    command_event["target_organizations"] = len(targets)
    command_event["desired_memberships"] = sum(
        len(target.desired_members_by_id) for target in targets.values()
    )
    if not targets:
        log.info("Selected user(s) hold no SAML group or synced org memberships — nothing to sync.")
        return None

    # Org IDs for orgs the scoped users belong to come from their own org
    # lists; only the remaining target names need a lookup (also yielding
    # currentUser for the create path). No member pages are fetched.
    names_needing_lookup = sorted(set(targets) - set(organization_ids_by_name))
    current_user, looked_up_states = _lookup_organization_states(
        client,
        names_needing_lookup,
        parallelism,
        worker_pool,
    )
    current_states: dict[str, organization_types.OrganizationState] = {}
    for organization_name in targets:
        known_id = organization_ids_by_name.get(organization_name)
        if known_id is not None:
            state = organization_types.OrganizationState(
                id=known_id,
                name=organization_name,
                members_by_id={},
            )
        else:
            state = looked_up_states[organization_name]
        state.members_by_id = dict(current_members_by_organization.get(organization_name, {}))
        current_states[organization_name] = state

    before_snapshot = _snapshot_from_states(client.endpoint, targets, current_states, scope="users")
    plan = _plan_organization_sync(targets, current_states, current_user)
    expected_states = _expected_states_from_targets(targets, current_states)
    expected_snapshot = _snapshot_from_states(
        client.endpoint, targets, expected_states, scope="users"
    )
    return _OrganizationSyncState(
        targets=targets,
        current_user=current_user,
        current_states=current_states,
        before_snapshot=before_snapshot,
        plan=plan,
        expected_snapshot=expected_snapshot,
    )


def _log_organization_sync_plan(sync_state: _OrganizationSyncState) -> None:
    log.info(
        "Organization sync plan: create %d org(s), add %d member(s), remove %d member(s).",
        len(sync_state.plan["create_names"]),
        len(sync_state.plan["additions"]),
        len(sync_state.plan["removals"]),
    )
    log.info(
        "Diff (current → desired):\n%s",
        _render_organization_diff(sync_state.before_snapshot, sync_state.expected_snapshot),
    )


def _write_organization_snapshot_pair(
    run_paths: backups.RunPaths,
    before_snapshot: organization_types.OrganizationSnapshot,
    after_snapshot: organization_types.OrganizationSnapshot,
) -> tuple[Path, Path, Path]:
    before_path = _organization_snapshot_path(run_paths, "before")
    after_path = _organization_snapshot_path(run_paths, "after")
    diff_path = _organization_snapshot_path(run_paths, "diff")
    _write_organization_snapshot(before_path, before_snapshot)
    _write_organization_snapshot(after_path, after_snapshot)
    _write_organization_snapshot_diff(diff_path, before_snapshot, after_snapshot)
    return before_path, after_path, diff_path


def _finish_organization_dry_run(
    run_paths: backups.RunPaths,
    sync_state: _OrganizationSyncState,
    do_backup: bool,
) -> None:
    if not do_backup:
        log.info("Skipped dry-run org snapshots because --no-backup was set.")
    elif not run_paths.write_files:
        log.info("Skipping dry-run org snapshots because --no-files is set.")
    else:
        before_path, after_path, diff_path = _write_organization_snapshot_pair(
            run_paths,
            sync_state.before_snapshot,
            sync_state.expected_snapshot,
        )
        log.info(
            "Wrote dry-run org snapshots: before=%s after=%s diff=%s.",
            before_path,
            after_path,
            diff_path,
        )
    log.info("Dry run complete. Pass --apply to mutate organization membership.")


def _write_organization_apply_before_snapshot(
    run_paths: backups.RunPaths,
    before_snapshot: organization_types.OrganizationSnapshot,
) -> Path | None:
    if not run_paths.write_files:
        log.info("Skipping before org snapshot because --no-files is set.")
        return None
    before_path = _organization_snapshot_path(run_paths, "before")
    _write_organization_snapshot(before_path, before_snapshot)
    log.info("Wrote before org snapshot: %s.", before_path)
    return before_path


def _record_organization_apply_event(
    command_event: dict[str, Any],
    result: _OrganizationApplyResult,
) -> None:
    command_event["create_succeeded"] = result.creates.succeeded
    command_event["create_failed"] = result.creates.failed
    command_event["create_canceled"] = result.creates.canceled
    command_event["add_succeeded"] = result.additions.succeeded
    command_event["add_failed"] = result.additions.failed
    command_event["add_canceled"] = result.additions.canceled
    command_event["remove_succeeded"] = result.removals.succeeded
    command_event["remove_failed"] = result.removals.failed
    command_event["remove_canceled"] = result.removals.canceled


def _apply_organization_sync(
    client: src.SourcegraphClient,
    sync_state: _OrganizationSyncState,
    parallelism: int,
    command_event: dict[str, Any],
    worker_pool: ThreadPoolExecutor | None = None,
) -> _OrganizationApplyResult:
    """Apply creates first, then recompute and apply member changes."""
    with src.stage("apply"):
        create_counts = _apply_create_organizations(
            client,
            sync_state.plan["create_names"],
            sync_state.current_states,
            sync_state.current_user,
            parallelism,
            worker_pool,
        )
        if create_counts.failed or create_counts.canceled:
            result = _OrganizationApplyResult(
                creates=create_counts,
                additions=shared_types.MutationCounts(),
                removals=shared_types.MutationCounts(),
            )
            _record_organization_apply_event(command_event, result)
            raise SystemExit(1)

        membership_plan = _plan_organization_sync(
            sync_state.targets,
            sync_state.current_states,
            sync_state.current_user,
        )
        add_counts = _apply_user_changes(
            client,
            membership_plan["additions"],
            sync_state.current_states,
            "add",
            parallelism,
            worker_pool,
        )
        remove_counts = _apply_user_changes(
            client,
            membership_plan["removals"],
            sync_state.current_states,
            "remove",
            parallelism,
            worker_pool,
        )
    return _OrganizationApplyResult(
        creates=create_counts,
        additions=add_counts,
        removals=remove_counts,
    )


def _finish_organization_apply_with_backup(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    sync_state: _OrganizationSyncState,
    before_path: Path | None,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    current_user_after, after_states = _load_current_organization_states(
        client,
        sorted(sync_state.targets),
        parallelism,
        worker_pool,
    )
    if current_user_after["id"] != sync_state.current_user["id"]:
        log.warning(
            "Current user changed during org sync (%s → %s); validation still uses org members.",
            sync_state.current_user["username"],
            current_user_after["username"],
        )
    after_snapshot = _snapshot_from_states(client.endpoint, sync_state.targets, after_states)
    if run_paths.write_files:
        after_path, diff_path = _write_organization_after_snapshot(
            run_paths,
            sync_state.before_snapshot,
            after_snapshot,
        )
        log.info("Wrote after org snapshot: %s diff=%s.", after_path, diff_path)
    else:
        log.info("Skipping after and diff org snapshots because --no-files is set.")
    _validate_organization_sync(after_snapshot, sync_state.expected_snapshot)
    if before_path is not None:
        log.info("To inspect the pre-sync org membership state, read:\n  %s", before_path)


def _finish_scoped_organization_apply_with_backup(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    sync_state: _OrganizationSyncState,
    scoped_users: list[shared_types.ScopedSamlGroupUser],
    before_path: Path | None,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Validate a scoped apply by re-reading only the scoped users' org lists."""
    after_states = _load_scoped_after_states(
        client,
        sync_state,
        scoped_users,
        parallelism,
        worker_pool,
    )
    after_snapshot = _snapshot_from_states(
        client.endpoint, sync_state.targets, after_states, scope="users"
    )
    if run_paths.write_files:
        after_path, diff_path = _write_organization_after_snapshot(
            run_paths,
            sync_state.before_snapshot,
            after_snapshot,
        )
        log.info("Wrote after org snapshot: %s diff=%s.", after_path, diff_path)
    else:
        log.info("Skipping after and diff org snapshots because --no-files is set.")
    _validate_organization_sync(after_snapshot, sync_state.expected_snapshot)
    if before_path is not None:
        log.info("To inspect the pre-sync org membership state, read:\n  %s", before_path)


def _load_scoped_after_states(
    client: src.SourcegraphClient,
    sync_state: _OrganizationSyncState,
    scoped_users: list[shared_types.ScopedSamlGroupUser],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> dict[str, organization_types.OrganizationState]:
    """Rebuild target org states from the scoped users' refreshed org lists."""
    organizations_by_user_id = _fetch_users_organizations(
        client,
        [scoped_user.user_id for scoped_user in scoped_users],
        parallelism,
        worker_pool,
    )
    after_states = {
        organization_name: organization_types.OrganizationState(
            id=sync_state.current_states[organization_name].id,
            name=organization_name,
            members_by_id={},
        )
        for organization_name in sync_state.targets
    }
    for scoped_user in scoped_users:
        for organization in organizations_by_user_id.get(scoped_user.user_id, []):
            state = after_states.get(organization["name"])
            if state is not None:
                state.members_by_id[scoped_user.user_id] = {
                    "id": scoped_user.user_id,
                    "username": scoped_user.username,
                }
    return after_states


def _fetch_users_organizations(
    client: src.SourcegraphClient,
    user_ids: list[str],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> dict[str, list[shared_types.OrganizationReference]]:
    """Fetch many users' org memberships via aliased batch lookups."""

    def fetch_batch(
        batch: list[str],
    ) -> list[tuple[str, list[shared_types.OrganizationReference]]]:
        data = client.graphql(
            queries.users_organizations_batch_query(len(batch)),
            cast(src.JSONDict, {f"user{index}": user_id for index, user_id in enumerate(batch)}),
            follow_pages=False,
        )
        batch_organizations: list[tuple[str, list[shared_types.OrganizationReference]]] = []
        for index, user_id in enumerate(batch):
            node = cast(dict[str, Any] | None, data.get(f"user{index}"))
            organizations: list[shared_types.OrganizationReference] = []
            if node:
                organizations = cast(
                    list[shared_types.OrganizationReference],
                    node["organizations"]["nodes"],
                )
            batch_organizations.append((user_id, organizations))
        return batch_organizations

    organizations_by_user_id: dict[str, list[shared_types.OrganizationReference]] = {}
    for batch_results in run_context.parallel_map(
        fetch_batch,
        list(_chunks(user_ids, ORGANIZATION_LOOKUP_BATCH_SIZE)),
        parallelism=parallelism,
        worker_pool=worker_pool,
    ):
        for user_id, organizations in batch_results:
            organizations_by_user_id[user_id] = organizations
    return organizations_by_user_id


def _write_organization_after_snapshot(
    run_paths: backups.RunPaths,
    before_snapshot: organization_types.OrganizationSnapshot,
    after_snapshot: organization_types.OrganizationSnapshot,
) -> tuple[Path, Path]:
    after_path = _organization_snapshot_path(run_paths, "after")
    diff_path = _organization_snapshot_path(run_paths, "diff")
    _write_organization_snapshot(after_path, after_snapshot)
    _write_organization_snapshot_diff(diff_path, before_snapshot, after_snapshot)
    return after_path, diff_path


def _raise_for_failed_organization_sync(result: _OrganizationApplyResult) -> None:
    failed = result.additions.failed + result.removals.failed
    canceled = result.additions.canceled + result.removals.canceled
    if not (failed or canceled):
        return
    log.error(
        "SAML org sync failed: %d mutation(s) failed, %d canceled. "
        "Review the log file and org snapshots, then re-run.",
        failed,
        canceled,
    )
    raise SystemExit(1)


def cmd_sync_saml_organizations(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    *,
    dry_run: bool,
    parallelism: int,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    command_data: run_context.CommandData | None = None,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Create/update Sourcegraph orgs from discovered SAML groups.

    Org names are deterministic and config-free: the Sourcegraph-safe form
    of `synced-<auth provider configID>-<group name>`. Invalid org-name
    characters are converted to `-`; any resulting name collision fails
    before mutation so we never merge unrelated SAML groups accidentally.
    The `synced-` prefix marks tool ownership: only orgs carrying it are
    ever modified.

    Two modes, matching the permission-sync mode of the same run:

    - Full (standalone `sync-saml-orgs`, or after a full-overwrite set):
      converges every synced org to the complete user population,
      including emptying (but never deleting) synced orgs whose SAML
      group disappeared.
    - Scoped (`command_data.scoped_saml_group_users` is set, after an
      additive set): per-user additions and removals for exactly the
      selected users; no other users or orgs are touched and no full
      user stream or member pages are loaded.
    """
    resolved_command_data = command_data or run_context.CommandData()
    scoped_users = resolved_command_data.scoped_saml_group_users
    with src.span(
        "cmd_sync_saml_organizations",
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
        scoped=scoped_users is not None,
    ) as command_event:
        if scoped_users is not None:
            sync_state = _load_scoped_organization_sync_state(
                client,
                scoped_users,
                parallelism,
                command_event,
                worker_pool,
            )
        else:
            sync_state = _load_organization_sync_state(
                client,
                saml_groups_attribute_name_by_config_id,
                parallelism,
                command_event,
                resolved_command_data,
                worker_pool,
            )
        if sync_state is None:
            return

        _log_organization_sync_plan(sync_state)

        if dry_run:
            _finish_organization_dry_run(run_paths, sync_state, do_backup)
            return

        before_path: Path | None = None
        if do_backup:
            before_path = _write_organization_apply_before_snapshot(
                run_paths,
                sync_state.before_snapshot,
            )

        apply_result = _apply_organization_sync(
            client,
            sync_state,
            parallelism,
            command_event,
            worker_pool,
        )
        _record_organization_apply_event(command_event, apply_result)

        if do_backup:
            if scoped_users is not None:
                _finish_scoped_organization_apply_with_backup(
                    client,
                    run_paths,
                    sync_state,
                    scoped_users,
                    before_path,
                    parallelism,
                    worker_pool,
                )
            else:
                _finish_organization_apply_with_backup(
                    client,
                    run_paths,
                    sync_state,
                    before_path,
                    parallelism,
                    worker_pool,
                )

        _raise_for_failed_organization_sync(apply_result)


def _collect_target_organizations(
    providers: list[shared_types.AuthProvider],
    attribute_names_by_provider: saml_groups.SamlGroupsAttributeNameByProvider,
    client: src.SourcegraphClient,
    saml_group_users: Iterable[shared_types.SamlGroupUser] | None,
) -> dict[str, organization_types.TargetOrganization]:
    providers_by_account_key = saml_groups.saml_providers_by_account_key(providers)
    targets: dict[str, organization_types.TargetOrganization] = {}
    collisions: set[str] = set()
    started = time.perf_counter()
    progress_step = 1000
    if saml_group_users is None:
        log.info("Streaming users once and extracting SAML group memberships ...")
        for completed, user in enumerate(
            shared_sourcegraph.list_users_streaming(client, include_account_data=True),
            start=1,
        ):
            compact_user = saml_groups.compact_saml_group_user(
                user,
                providers_by_account_key,
                attribute_names_by_provider,
            )
            if compact_user is not None:
                _record_saml_group_user_memberships(targets, collisions, compact_user)
            if completed % progress_step == 0:
                _log_target_collection_progress(completed, started, targets)
    else:
        log.info(
            "Reusing %d precomputed SAML group user(s) loaded earlier in this run ...",
            len(saml_group_users) if isinstance(saml_group_users, list) else 0,
        )
        for completed, user in enumerate(saml_group_users, start=1):
            _record_saml_group_user_memberships(targets, collisions, user)
            if completed % progress_step == 0:
                _log_target_collection_progress(completed, started, targets)
    _raise_for_target_collisions(collisions)
    _log_target_collection_summary(targets)
    return targets


def _record_saml_group_user_memberships(
    targets: dict[str, organization_types.TargetOrganization],
    collisions: set[str],
    user: shared_types.SamlGroupUser | shared_types.ScopedSamlGroupUser,
) -> None:
    for membership in user.saml_group_memberships:
        _record_target_organization_membership(
            targets,
            collisions,
            membership.provider_config_id,
            membership.group_name,
            user,
        )


def _record_target_organization_membership(
    targets: dict[str, organization_types.TargetOrganization],
    collisions: set[str],
    provider_config_id: str,
    group_name: str,
    user: shared_types.SamlGroupUser | shared_types.ScopedSamlGroupUser,
) -> None:
    organization_name = organization_name_for_saml_group(provider_config_id, group_name)
    existing_target = targets.get(organization_name)
    if existing_target is not None and (
        existing_target.provider_config_id != provider_config_id
        or existing_target.saml_group != group_name
    ):
        collisions.add(
            f"{organization_name!r} maps both "
            f"{existing_target.provider_config_id!r}/{existing_target.saml_group!r} "
            f"and {provider_config_id!r}/{group_name!r}"
        )
        return

    target = existing_target or organization_types.TargetOrganization(
        name=organization_name,
        provider_config_id=provider_config_id,
        saml_group=group_name,
    )
    target.desired_members_by_id[user.user_id] = {
        "id": user.user_id,
        "username": user.username,
    }
    targets[organization_name] = target


def _log_target_collection_progress(
    completed: int,
    started: float,
    targets: dict[str, organization_types.TargetOrganization],
) -> None:
    elapsed = time.perf_counter() - started
    rate = completed / elapsed if elapsed > 0 else 0.0
    log.info(
        "Processed %d user record(s) for SAML groups in %.0fs "
        "(%.0f users/sec); found %d target org(s).",
        completed,
        elapsed,
        rate,
        len(targets),
    )


def _raise_for_target_collisions(collisions: set[str]) -> None:
    if not collisions:
        return
    bullet = "\n  - "
    raise SystemExit(
        "FATAL: SAML group org-name collision(s) after Sourcegraph-safe normalization:"
        + bullet
        + bullet.join(sorted(collisions))
    )


def _log_target_collection_summary(
    targets: dict[str, organization_types.TargetOrganization],
) -> None:
    log.info(
        "Found %d SAML-backed target org(s) covering %d desired membership(s).",
        len(targets),
        sum(len(target.desired_members_by_id) for target in targets.values()),
    )


def _load_current_organization_states(
    client: src.SourcegraphClient,
    organization_names: list[str],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> tuple[organization_types.OrgMember, dict[str, organization_types.OrganizationState]]:
    """Resolve target org IDs and load their full member lists."""
    with src.span(
        "load_current_organization_states",
        organization_count=len(organization_names),
        member_page_size=ORGANIZATION_MEMBER_PAGE_SIZE,
    ) as load_event:
        current_user, states = _lookup_organization_states(
            client,
            organization_names,
            parallelism,
            worker_pool,
        )
        _fetch_members_into_states(client, states, parallelism, worker_pool, load_event)
    return current_user, states


def _lookup_organization_states(
    client: src.SourcegraphClient,
    organization_names: list[str],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> tuple[organization_types.OrgMember, dict[str, organization_types.OrganizationState]]:
    """Resolve org names to IDs (no member pages) via aliased batch lookups."""
    states: dict[str, organization_types.OrganizationState] = {}
    current_user: organization_types.OrgMember | None = None
    name_batches = list(_chunks(organization_names, ORGANIZATION_LOOKUP_BATCH_SIZE))

    def fetch_organization_batch(
        batch: list[str],
    ) -> organization_types.OrganizationBatchLookup:
        return _fetch_organization_batch(client, batch)

    for result in run_context.parallel_map(
        fetch_organization_batch,
        name_batches,
        parallelism=parallelism,
        worker_pool=worker_pool,
    ):
        batch_current_user = result["current_user"]
        if current_user is None:
            current_user = batch_current_user
        elif current_user["id"] != batch_current_user["id"]:
            raise RuntimeError(
                "currentUser changed between organization lookup batches "
                f"({current_user['username']} vs {batch_current_user['username']})"
            )
        states.update(result["states"])

    if current_user is None:
        current_user = _fetch_current_user(client)
    return current_user, states


def _fetch_members_into_states(
    client: src.SourcegraphClient,
    states: dict[str, organization_types.OrganizationState],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None,
    load_event: dict[str, Any],
) -> None:
    """Page every existing org's full member list into its state."""
    existing_states = [state for state in states.values() if state.id is not None]
    load_event["existing_organizations_needing_member_pages"] = len(existing_states)

    def fetch_members(
        state: organization_types.OrganizationState,
    ) -> tuple[organization_types.OrganizationState, list[organization_types.OrgMember]]:
        return state, _fetch_all_members(client, state)

    for state, members in run_context.parallel_map(
        fetch_members,
        existing_states,
        parallelism=parallelism,
        worker_pool=worker_pool,
    ):
        for member in members:
            state.members_by_id[member["id"]] = member
    load_event["existing_organizations"] = len(existing_states)
    load_event["total_current_members"] = sum(len(state.members_by_id) for state in states.values())


def _fetch_current_user(client: src.SourcegraphClient) -> organization_types.OrgMember:
    data = client.graphql(queries.QUERY_CURRENT_USER)
    current_user = cast(organization_types.OrgMember | None, data.get("currentUser"))
    if current_user is None:
        raise RuntimeError("currentUser is null; SAML org sync requires an authenticated token")
    return current_user


def _discover_synced_organization_states(
    client: src.SourcegraphClient,
) -> tuple[organization_types.OrgMember, dict[str, organization_types.OrganizationState]] | None:
    """Find every existing `synced-` org (ID + name) in one search request.

    Returns None when the search result was truncated (more matches than
    `SYNCED_ORGANIZATION_SEARCH_LIMIT`); callers must then fall back to
    per-name lookups and skip orphaned-org cleanup.
    """
    with src.span("discover_synced_organizations") as discovery_event:
        data = client.graphql(
            queries.QUERY_SYNCED_ORGANIZATIONS,
            {
                "first": SYNCED_ORGANIZATION_SEARCH_LIMIT,
                "query": saml_groups.SYNCED_ORGANIZATION_NAME_PREFIX,
            },
        )
        current_user = cast(organization_types.OrgMember | None, data.get("currentUser"))
        if current_user is None:
            raise RuntimeError("currentUser is null; SAML org sync requires an authenticated token")
        connection = cast(dict[str, Any], data["organizations"])
        raw_organizations = cast(list[dict[str, Any]], connection["nodes"])
        total_count = cast(int, connection["totalCount"])
        discovery_event["total_count"] = total_count
        discovery_event["returned_count"] = len(raw_organizations)
        if total_count > len(raw_organizations):
            log.warning(
                "Synced-org discovery returned %d of %d matches; falling back to "
                "per-name lookups and skipping orphaned synced-org cleanup this run.",
                len(raw_organizations),
                total_count,
            )
            return None
        # The search also matches display names; keep only true synced- names.
        states = {
            raw_organization["name"]: organization_types.OrganizationState(
                id=cast(str, raw_organization["id"]),
                name=cast(str, raw_organization["name"]),
                members_by_id={},
            )
            for raw_organization in raw_organizations
            if saml_groups.is_synced_organization_name(cast(str, raw_organization["name"]))
        }
        discovery_event["synced_organizations"] = len(states)
    return current_user, states


def _fetch_organization_batch(
    client: src.SourcegraphClient,
    organization_names: list[str],
) -> organization_types.OrganizationBatchLookup:
    query = _organization_batch_query(len(organization_names))
    variables: dict[str, Any] = {
        "organizationFirst": ORGANIZATION_SEARCH_RESULT_LIMIT,
        "memberFirst": ORGANIZATION_MEMBER_PAGE_SIZE,
    }
    for index, organization_name in enumerate(organization_names):
        variables[f"name{index}"] = organization_name
    with src.span(
        "organization_batch_lookup",
        level="DEBUG",
        organization_count=len(organization_names),
    ) as lookup_event:
        data = client.graphql(query, variables)
        current_user = cast(organization_types.OrgMember | None, data.get("currentUser"))
        if current_user is None:
            raise RuntimeError("currentUser is null; SAML org sync requires an authenticated token")
        states: dict[str, organization_types.OrganizationState] = {}
        existing_count = 0
        for index, organization_name in enumerate(organization_names):
            raw_connection = cast(dict[str, Any] | None, data.get(f"organization{index}"))
            if raw_connection is None:
                raise RuntimeError(
                    f"organizations lookup alias organization{index} was missing from response"
                )
            raw_organizations = cast(list[dict[str, Any]], raw_connection["nodes"])
            raw_organization = next(
                (
                    organization
                    for organization in raw_organizations
                    if organization.get("name") == organization_name
                ),
                None,
            )
            if raw_organization is None:
                total_count = cast(int, raw_connection["totalCount"])
                if total_count >= ORGANIZATION_SEARCH_RESULT_LIMIT:
                    log.warning(
                        "Org lookup for %s returned %d search result(s) without an exact "
                        "match in the first %d; treating it as missing.",
                        organization_name,
                        total_count,
                        ORGANIZATION_SEARCH_RESULT_LIMIT,
                    )
                states[organization_name] = organization_types.OrganizationState(
                    id=None,
                    name=organization_name,
                    members_by_id={},
                )
                continue
            existing_count += 1
            states[organization_name] = organization_types.OrganizationState(
                id=cast(str, raw_organization["id"]),
                name=cast(str, raw_organization["name"]),
                members_by_id={},
            )
        lookup_event["existing_organizations"] = existing_count
        return {"current_user": current_user, "states": states}


def _organization_batch_query(organization_count: int) -> str:
    variable_definitions = ["$organizationFirst: Int!"] + [
        f"$name{index}: String!" for index in range(organization_count)
    ]
    fields = ["currentUser { id username }"]
    for index in range(organization_count):
        fields.append(
            f"""
  organization{index}: organizations(first: $organizationFirst, query: $name{index}) {{
    totalCount
    nodes {{
      id
      name
    }}
  }}"""
        )
    return (
        f"query SamlOrganizationLookup({', '.join(variable_definitions)}) {{\n"
        + "\n".join(fields)
        + "\n}\n"
    )


def _fetch_all_members(
    client: src.SourcegraphClient,
    state: organization_types.OrganizationState,
) -> list[organization_types.OrgMember]:
    if state.id is None:
        return []
    with src.span("organization_members", level="DEBUG", organization_name=state.name):
        return [
            cast(organization_types.OrgMember, node)
            for node in client.stream_connection_nodes(
                queries.QUERY_ORGANIZATION_MEMBERS_PAGE,
                {"id": state.id},
                connection_path=("node", "members"),
                page_size=ORGANIZATION_MEMBER_PAGE_SIZE,
            )
        ]


def _plan_organization_sync(
    targets: dict[str, organization_types.TargetOrganization],
    current_states: dict[str, organization_types.OrganizationState],
    current_user: organization_types.OrgMember,
) -> organization_types.OrganizationPlan:
    create_names: list[str] = []
    additions: list[organization_types.OrganizationUserChange] = []
    removals: list[organization_types.OrganizationUserChange] = []
    for organization_name, target in sorted(targets.items()):
        current_state = current_states[organization_name]
        current_members = dict(current_state.members_by_id)
        if current_state.id is None:
            create_names.append(organization_name)
            # createOrganization automatically adds the caller. Account for
            # that before planning adds/removes so we do not call add for the
            # caller or leave them in the org when they are not in the SAML group.
            current_members[current_user["id"]] = current_user
        for user_id, member in sorted(
            target.desired_members_by_id.items(), key=lambda item: item[1]["username"]
        ):
            if user_id not in current_members:
                additions.append(
                    organization_types.OrganizationUserChange(
                        organization_name=organization_name,
                        user_id=user_id,
                        username=member["username"],
                    )
                )
        for user_id, member in sorted(
            current_members.items(), key=lambda item: item[1]["username"]
        ):
            if user_id not in target.desired_members_by_id:
                removals.append(
                    organization_types.OrganizationUserChange(
                        organization_name=organization_name,
                        user_id=user_id,
                        username=member["username"],
                    )
                )
    return {"create_names": create_names, "additions": additions, "removals": removals}


def _expected_states_from_targets(
    targets: dict[str, organization_types.TargetOrganization],
    current_states: dict[str, organization_types.OrganizationState],
) -> dict[str, organization_types.OrganizationState]:
    return {
        organization_name: organization_types.OrganizationState(
            id=current_states[organization_name].id,
            name=organization_name,
            members_by_id=dict(target.desired_members_by_id),
        )
        for organization_name, target in targets.items()
    }


def _apply_create_organizations(
    client: src.SourcegraphClient,
    organization_names: list[str],
    current_states: dict[str, organization_types.OrganizationState],
    current_user: organization_types.OrgMember,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    if not organization_names:
        return shared_types.MutationCounts()
    with src.span(
        "apply_create_organizations",
        organization_count=len(organization_names),
        parallelism=parallelism,
    ) as batch_event:
        breaker = permissions_apply.CircuitBreaker()
        succeeded = 0
        failed = 0
        canceled = 0

        def create_organization(organization_name: str) -> organization_types.OrganizationState:
            return _create_organization(client, organization_name, current_user)

        def record_result(
            result: run_context.ParallelResult[str, organization_types.OrganizationState],
        ) -> None:
            nonlocal succeeded, failed, canceled
            organization_name = result.item
            if result.exception is None:
                state = result.value
                if state is None:
                    raise RuntimeError(f"create org {organization_name} returned no state")
                current_states[organization_name] = state
                succeeded += 1
                breaker.record(success=True)
                log.info("  OK create org %s.", organization_name)
                return
            if isinstance(result.exception, CancelledError):
                canceled += 1
                return
            failed += 1
            breaker.record(success=False)
            log.error("  FAIL create org %s: %s", organization_name, result.exception)

        summary = run_context.parallel_process(
            create_organization,
            organization_names,
            parallelism=parallelism,
            worker_pool=worker_pool,
            handle_result=record_result,
            should_stop=breaker.is_open,
        )
        if breaker.is_open():
            canceled += summary.unsubmitted_count
        batch_event["succeeded"] = succeeded
        batch_event["failed"] = failed
        batch_event["canceled"] = canceled
        batch_event["circuit_broken"] = breaker.is_open()
        return shared_types.MutationCounts(
            succeeded=succeeded,
            failed=failed,
            canceled=canceled,
        )


def _create_organization(
    client: src.SourcegraphClient,
    organization_name: str,
    current_user: organization_types.OrgMember,
) -> organization_types.OrganizationState:
    with src.span("create_organization", organization_name=organization_name):
        try:
            data = client.graphql(
                queries.MUTATION_CREATE_ORGANIZATION,
                {"name": organization_name, "displayName": None},
            )
        except src.GraphQLError as exception:
            if _ORGANIZATION_EXISTS_TEXT not in str(exception):
                raise
            log.warning(
                "createOrganization reported %s already exists; re-reading it and continuing.",
                organization_name,
            )
            return _fetch_single_organization_state(client, organization_name)
        created = cast(organization_types.CreatedOrganization, data["createOrganization"])
        return organization_types.OrganizationState(
            id=created["id"],
            name=created["name"],
            members_by_id={current_user["id"]: current_user},
        )


def _fetch_single_organization_state(
    client: src.SourcegraphClient,
    organization_name: str,
) -> organization_types.OrganizationState:
    lookup = _fetch_organization_batch(client, [organization_name])
    state = lookup["states"][organization_name]
    if state.id is None:
        raise RuntimeError(
            f"organization {organization_name!r} still does not exist after "
            "createOrganization conflict"
        )
    for member in _fetch_all_members(client, state):
        state.members_by_id[member["id"]] = member
    return state


def _apply_user_changes(
    client: src.SourcegraphClient,
    changes: list[organization_types.OrganizationUserChange],
    current_states: dict[str, organization_types.OrganizationState],
    change_kind: organization_types.OrganizationChangeKind,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    if not changes:
        return shared_types.MutationCounts()
    with src.span(
        "apply_organization_user_changes",
        change_kind=change_kind,
        change_count=len(changes),
        parallelism=parallelism,
    ) as batch_event:
        breaker = permissions_apply.CircuitBreaker()
        succeeded = 0
        failed = 0
        canceled = 0

        def apply_change(change: organization_types.OrganizationUserChange) -> None:
            _apply_user_change(
                client,
                change,
                current_states[change.organization_name],
                change_kind,
            )

        def record_result(
            result: run_context.ParallelResult[
                organization_types.OrganizationUserChange,
                None,
            ],
        ) -> None:
            nonlocal succeeded, failed, canceled
            change = result.item
            if result.exception is None:
                succeeded += 1
                breaker.record(success=True)
                log.info(
                    "  OK %s %s %s org %s.",
                    change_kind,
                    change.username,
                    "to" if change_kind == "add" else "from",
                    change.organization_name,
                )
                return
            if isinstance(result.exception, CancelledError):
                canceled += 1
                return
            failed += 1
            breaker.record(success=False)
            log.error(
                "  FAIL %s %s %s org %s: %s",
                change_kind,
                change.username,
                "to" if change_kind == "add" else "from",
                change.organization_name,
                result.exception,
            )

        summary = run_context.parallel_process(
            apply_change,
            changes,
            parallelism=parallelism,
            worker_pool=worker_pool,
            handle_result=record_result,
            should_stop=breaker.is_open,
        )
        if breaker.is_open():
            canceled += summary.unsubmitted_count
        batch_event["succeeded"] = succeeded
        batch_event["failed"] = failed
        batch_event["canceled"] = canceled
        batch_event["circuit_broken"] = breaker.is_open()
        return shared_types.MutationCounts(
            succeeded=succeeded,
            failed=failed,
            canceled=canceled,
        )


def _apply_user_change(
    client: src.SourcegraphClient,
    change: organization_types.OrganizationUserChange,
    state: organization_types.OrganizationState,
    change_kind: organization_types.OrganizationChangeKind,
) -> None:
    if state.id is None:
        raise RuntimeError(f"organization {change.organization_name!r} has no ID")
    if change_kind == "add":
        with src.span(
            "add_user_to_organization",
            organization_name=change.organization_name,
            username=change.username,
        ):
            try:
                client.graphql(
                    queries.MUTATION_ADD_USER_TO_ORGANIZATION,
                    {"organization": state.id, "username": change.username},
                )
            except src.GraphQLError as exception:
                if _ALREADY_MEMBER_TEXT in str(exception):
                    log.info(
                        "  Already a member: %s in org %s; treating as success.",
                        change.username,
                        change.organization_name,
                    )
                    return
                raise
        return
    with src.span(
        "remove_user_from_organization",
        organization_name=change.organization_name,
        username=change.username,
    ):
        client.graphql(
            queries.MUTATION_REMOVE_USER_FROM_ORGANIZATION,
            {"organization": state.id, "user": change.user_id},
        )


def _snapshot_from_states(
    endpoint: str,
    targets: dict[str, organization_types.TargetOrganization],
    states: dict[str, organization_types.OrganizationState],
    *,
    scope: organization_types.OrganizationSyncScope = "full",
) -> organization_types.OrganizationSnapshot:
    organizations: dict[str, organization_types.OrganizationSnapshotEntry] = {}
    for organization_name, target in sorted(targets.items()):
        state = states[organization_name]
        organizations[organization_name] = {
            "id": state.id,
            "provider_config_id": target.provider_config_id,
            "saml_group": target.saml_group,
            "members": _sorted_members(state.members_by_id),
            "desired_members": _sorted_members(target.desired_members_by_id),
        }
    return {
        "schema_version": ORGANIZATION_SNAPSHOT_SCHEMA_VERSION,
        "captured_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "endpoint": endpoint,
        # "users" snapshots cover only the scoped users' memberships per
        # org, not each org's full member list.
        "scope": scope,
        "stats": {
            "target_organizations": len(organizations),
            "existing_organizations": sum(
                1 for organization in organizations.values() if organization["id"] is not None
            ),
            "total_current_members": sum(
                len(organization["members"]) for organization in organizations.values()
            ),
            "total_desired_members": sum(
                len(organization["desired_members"]) for organization in organizations.values()
            ),
        },
        "organizations": organizations,
    }


def _sorted_members(
    members_by_id: dict[str, organization_types.OrgMember],
) -> list[organization_types.OrgMember]:
    return sorted(
        ({"id": member["id"], "username": member["username"]} for member in members_by_id.values()),
        key=lambda member: member["username"],
    )


def _render_organization_diff(
    before: organization_types.OrganizationSnapshot, after: organization_types.OrganizationSnapshot
) -> str:
    lines: list[str] = []
    total_added = 0
    total_removed = 0
    before_organizations = before["organizations"]
    after_organizations = after["organizations"]
    for organization_name in sorted(set(before_organizations) | set(after_organizations)):
        before_entry = before_organizations.get(organization_name)
        after_entry = after_organizations.get(organization_name)
        before_members = _snapshot_usernames(before_entry["members"] if before_entry else [])
        after_members = _snapshot_usernames(after_entry["members"] if after_entry else [])
        added = sorted(after_members - before_members)
        removed = sorted(before_members - after_members)
        if not added and not removed:
            continue
        lines.append(f"=== {organization_name} ===")
        if before_entry and before_entry["id"] is None:
            lines.append("  * organization does not exist yet")
        if added:
            lines.append(f"  + added ({len(added)}): {', '.join(added)}")
        if removed:
            lines.append(f"  - removed ({len(removed)}): {', '.join(removed)}")
        total_added += len(added)
        total_removed += len(removed)
    if not lines:
        return "No changes."
    lines.append("")
    lines.append(f"Summary: {total_added} member(s) added, {total_removed} member(s) removed.")
    return "\n".join(lines)


def _build_organization_snapshot_diff(
    before: organization_types.OrganizationSnapshot,
    after: organization_types.OrganizationSnapshot,
) -> organization_types.OrganizationSnapshotDiff:
    organizations: list[organization_types.OrganizationSnapshotDiffEntry] = []
    members_added = 0
    members_removed = 0
    before_organizations = before["organizations"]
    after_organizations = after["organizations"]
    for organization_name in sorted(set(before_organizations) | set(after_organizations)):
        before_entry = before_organizations.get(organization_name)
        after_entry = after_organizations.get(organization_name)
        before_members = _snapshot_usernames(before_entry["members"] if before_entry else [])
        after_members = _snapshot_usernames(after_entry["members"] if after_entry else [])
        added = sorted(after_members - before_members)
        removed = sorted(before_members - after_members)
        created = before_entry is None or before_entry["id"] is None
        if not added and not removed and not created:
            continue
        source_entry = after_entry or before_entry
        if source_entry is None:
            continue
        members_added += len(added)
        members_removed += len(removed)
        organizations.append(
            {
                "name": organization_name,
                "id": source_entry["id"],
                "provider_config_id": source_entry["provider_config_id"],
                "saml_group": source_entry["saml_group"],
                "created": created,
                "before_count": len(before_members),
                "after_count": len(after_members),
                "added": added,
                "removed": removed,
            }
        )
    return {
        "schema_version": ORGANIZATION_SNAPSHOT_DIFF_SCHEMA_VERSION,
        "diff_kind": "saml_organizations",
        "before_captured_at": before["captured_at"],
        "after_captured_at": after["captured_at"],
        "endpoint": after["endpoint"],
        "summary": {
            "organizations_changed": len(organizations),
            "organizations_created": sum(
                1 for organization in organizations if organization["created"]
            ),
            "members_added": members_added,
            "members_removed": members_removed,
        },
        "organizations": organizations,
    }


def _snapshot_usernames(members: list[organization_types.OrgMember]) -> set[str]:
    return {member["username"] for member in members}


def _validate_organization_sync(
    after_snapshot: organization_types.OrganizationSnapshot,
    expected_snapshot: organization_types.OrganizationSnapshot,
) -> None:
    diff = _render_organization_diff(after_snapshot, expected_snapshot)
    if diff == "No changes.":
        log.info("VALIDATION OK: all target org memberships match discovered SAML groups.")
        return
    log.warning("VALIDATION: target org memberships differ from desired SAML groups:\n%s", diff)


def _write_organization_snapshot(
    path: Path, snapshot: organization_types.OrganizationSnapshot
) -> None:
    with src.span(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="organization_snapshot",
    ) as disk_event:
        path.parent.mkdir(parents=True, exist_ok=True)
        contents = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
        path.write_text(contents)
        disk_event["bytes"] = len(contents)


def _write_organization_snapshot_diff(
    path: Path,
    before: organization_types.OrganizationSnapshot,
    after: organization_types.OrganizationSnapshot,
) -> None:
    with src.span(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="organization_snapshot_diff",
    ) as disk_event:
        path.parent.mkdir(parents=True, exist_ok=True)
        diff = _build_organization_snapshot_diff(before, after)
        contents = json.dumps(diff, indent=2, sort_keys=True) + "\n"
        path.write_text(contents)
        disk_event["bytes"] = len(contents)


def _organization_snapshot_path(run_paths: backups.RunPaths, state: str) -> Path:
    return run_paths.artifact_path(state, family="saml-organizations")


def _chunks(values: list[str], size: int) -> list[list[str]]:
    return [values[start : start + size] for start in range(0, len(values), size)]
