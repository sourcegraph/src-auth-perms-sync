"""Sourcegraph organization sync command handler."""

from __future__ import annotations

import datetime
import json
import logging
import re
import time
from collections.abc import Iterable
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
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
ORGANIZATION_NAME_MAX_LENGTH: int = 255
ORGANIZATION_SNAPSHOT_SCHEMA_VERSION: int = 1
ORGANIZATION_SNAPSHOT_DIFF_SCHEMA_VERSION: int = 1

_ORGANIZATION_NAME_PART_RE = re.compile(r"[^A-Za-z0-9]+")
_ORGANIZATION_NAME_DASH_RUN_RE = re.compile(r"-+")
_ALREADY_MEMBER_TEXT = "user is already a member of the organization"
_ORGANIZATION_EXISTS_TEXT = "organization name is already taken"


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
    command_event["target_organizations"] = len(targets)
    command_event["desired_memberships"] = sum(
        len(target.desired_members_by_id) for target in targets.values()
    )
    if not targets:
        log.warning("No SAML group memberships found in user accountData — nothing to sync.")
        return None

    current_user, current_states = _load_current_organization_states(
        client,
        sorted(targets),
        parallelism,
        worker_pool,
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
    timestamp: str,
    endpoint: str,
    command_name: str,
    before_snapshot: organization_types.OrganizationSnapshot,
    after_snapshot: organization_types.OrganizationSnapshot,
) -> tuple[Path, Path, Path]:
    before_path = _organization_snapshot_path(timestamp, endpoint, command_name, "before")
    after_path = _organization_snapshot_path(timestamp, endpoint, command_name, "after")
    diff_path = _organization_snapshot_path(timestamp, endpoint, command_name, "diff")
    _write_organization_snapshot(before_path, before_snapshot)
    _write_organization_snapshot(after_path, after_snapshot)
    _write_organization_snapshot_diff(diff_path, before_snapshot, after_snapshot)
    return before_path, after_path, diff_path


def _finish_organization_dry_run(
    endpoint: str,
    timestamp: str,
    sync_state: _OrganizationSyncState,
    do_backup: bool,
) -> None:
    if do_backup:
        before_path, after_path, diff_path = _write_organization_snapshot_pair(
            timestamp,
            endpoint,
            "sync-saml-orgs-dry-run",
            sync_state.before_snapshot,
            sync_state.expected_snapshot,
        )
        log.info(
            "Wrote dry-run org snapshots: before=%s after=%s diff=%s.",
            before_path,
            after_path,
            diff_path,
        )
    else:
        log.info("Skipped dry-run org snapshots because --no-backup was set.")
    log.info("Dry run complete. Pass --apply to mutate organization membership.")


def _write_organization_apply_before_snapshot(
    endpoint: str,
    timestamp: str,
    before_snapshot: organization_types.OrganizationSnapshot,
) -> Path:
    before_path = _organization_snapshot_path(
        timestamp,
        endpoint,
        "sync-saml-orgs-apply",
        "before",
    )
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
    timestamp: str,
    sync_state: _OrganizationSyncState,
    before_path: Path,
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
    after_path, diff_path = _write_organization_after_snapshot(
        timestamp,
        client.endpoint,
        sync_state.before_snapshot,
        after_snapshot,
    )
    log.info("Wrote after org snapshot: %s diff=%s.", after_path, diff_path)
    _validate_organization_sync(after_snapshot, sync_state.expected_snapshot)
    log.info("To inspect the pre-sync org membership state, read:\n  %s", before_path)


def _write_organization_after_snapshot(
    timestamp: str,
    endpoint: str,
    before_snapshot: organization_types.OrganizationSnapshot,
    after_snapshot: organization_types.OrganizationSnapshot,
) -> tuple[Path, Path]:
    after_path = _organization_snapshot_path(timestamp, endpoint, "sync-saml-orgs-apply", "after")
    diff_path = _organization_snapshot_path(timestamp, endpoint, "sync-saml-orgs-apply", "diff")
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
    *,
    dry_run: bool,
    parallelism: int,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    command_data: run_context.CommandData | None = None,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Create/update Sourcegraph orgs from every discovered SAML group.

    Org names are deterministic and config-free: the Sourcegraph-safe form
    of `<auth provider configID>-<group name>`. Invalid org-name
    characters are converted to `-`; any resulting name collision fails
    before mutation so we never merge unrelated SAML groups accidentally.
    """
    with src.span(
        "cmd_sync_saml_organizations",
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ) as command_event:
        sync_state = _load_organization_sync_state(
            client,
            saml_groups_attribute_name_by_config_id,
            parallelism,
            command_event,
            command_data or run_context.CommandData(),
            worker_pool,
        )
        if sync_state is None:
            return

        _log_organization_sync_plan(sync_state)

        timestamp = backups.backup_timestamp()
        if dry_run:
            _finish_organization_dry_run(client.endpoint, timestamp, sync_state, do_backup)
            return

        before_path: Path | None = None
        if do_backup:
            before_path = _write_organization_apply_before_snapshot(
                client.endpoint,
                timestamp,
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
            assert before_path is not None
            _finish_organization_apply_with_backup(
                client,
                timestamp,
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
        for completed, user in enumerate(shared_sourcegraph.list_users_streaming(client), start=1):
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
    user: shared_types.SamlGroupUser,
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
    user: shared_types.SamlGroupUser,
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


def organization_name_for_saml_group(provider_config_id: str, group_name: str) -> str:
    provider_part = _organization_name_part(provider_config_id, "auth provider configID")
    group_part = _organization_name_part(group_name, "SAML group name")
    organization_name = f"{provider_part}-{group_part}"
    if len(organization_name) > ORGANIZATION_NAME_MAX_LENGTH:
        raise SystemExit(
            f"FATAL: generated org name for configID={provider_config_id!r} "
            f"group={group_name!r} is {len(organization_name)} characters; "
            f"Sourcegraph org names must be <= {ORGANIZATION_NAME_MAX_LENGTH}."
        )
    return organization_name


def _organization_name_part(value: str, label: str) -> str:
    normalized = _ORGANIZATION_NAME_PART_RE.sub("-", value.strip())
    normalized = _ORGANIZATION_NAME_DASH_RUN_RE.sub("-", normalized).strip("-")
    if not normalized:
        raise SystemExit(
            f"FATAL: {label} {value!r} cannot be converted to a Sourcegraph org-name part."
        )
    return normalized


def _load_current_organization_states(
    client: src.SourcegraphClient,
    organization_names: list[str],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> tuple[organization_types.OrgMember, dict[str, organization_types.OrganizationState]]:
    states: dict[str, organization_types.OrganizationState] = {}
    current_user: organization_types.OrgMember | None = None
    name_batches = list(_chunks(organization_names, ORGANIZATION_LOOKUP_BATCH_SIZE))
    with src.span(
        "load_current_organization_states",
        organization_count=len(organization_names),
        lookup_batch_count=len(name_batches),
        member_page_size=ORGANIZATION_MEMBER_PAGE_SIZE,
    ) as load_event:
        with run_context.thread_pool(parallelism, worker_pool) as executor:
            futures = {
                src.submit_with_log_context(
                    executor, _fetch_organization_batch, client, batch
                ): batch
                for batch in name_batches
            }
            for future in as_completed(futures):
                result = future.result()
                batch_current_user = result["current_user"]
                if current_user is None:
                    current_user = batch_current_user
                elif current_user["id"] != batch_current_user["id"]:
                    raise RuntimeError(
                        "currentUser changed between organization lookup batches "
                        f"({current_user['username']} vs {batch_current_user['username']})"
                    )
                states.update(result["states"])

            existing_states = [state for state in states.values() if state.id is not None]
            load_event["existing_organizations_needing_member_pages"] = len(existing_states)
            if existing_states:
                member_futures = {
                    src.submit_with_log_context(
                        executor,
                        _fetch_all_members,
                        client,
                        state,
                    ): state
                    for state in existing_states
                }
                for future in as_completed(member_futures):
                    state = member_futures[future]
                    for member in future.result():
                        state.members_by_id[member["id"]] = member
        load_event["existing_organizations"] = sum(1 for state in states.values() if state.id)
        load_event["total_current_members"] = sum(
            len(state.members_by_id) for state in states.values()
        )

    if current_user is None:
        raise RuntimeError("currentUser was not returned while loading organizations")
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
        with run_context.thread_pool(parallelism, worker_pool) as executor:
            futures = {
                src.submit_with_log_context(
                    executor,
                    _create_organization,
                    client,
                    organization_name,
                    current_user,
                ): organization_name
                for organization_name in organization_names
            }
            for future in as_completed(futures):
                organization_name = futures[future]
                try:
                    state = future.result()
                    current_states[organization_name] = state
                    succeeded += 1
                    breaker.record(success=True)
                    log.info("  OK create org %s.", organization_name)
                except CancelledError:
                    canceled += 1
                    continue
                except Exception as exception:
                    failed += 1
                    breaker.record(success=False)
                    log.error("  FAIL create org %s: %s", organization_name, exception)
                if breaker.is_open():
                    for pending_future in futures:
                        if not pending_future.done():
                            pending_future.cancel()
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
        with run_context.thread_pool(parallelism, worker_pool) as executor:
            futures = {
                src.submit_with_log_context(
                    executor,
                    _apply_user_change,
                    client,
                    change,
                    current_states[change.organization_name],
                    change_kind,
                ): change
                for change in changes
            }
            for future in as_completed(futures):
                change = futures[future]
                try:
                    future.result()
                    succeeded += 1
                    breaker.record(success=True)
                    log.info(
                        "  OK %s %s %s org %s.",
                        change_kind,
                        change.username,
                        "to" if change_kind == "add" else "from",
                        change.organization_name,
                    )
                except CancelledError:
                    canceled += 1
                    continue
                except Exception as exception:
                    failed += 1
                    breaker.record(success=False)
                    log.error(
                        "  FAIL %s %s %s org %s: %s",
                        change_kind,
                        change.username,
                        "to" if change_kind == "add" else "from",
                        change.organization_name,
                        exception,
                    )
                if breaker.is_open():
                    for pending_future in futures:
                        if not pending_future.done():
                            pending_future.cancel()
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


def _organization_snapshot_path(
    timestamp: str,
    endpoint: str,
    command: str,
    state: str,
) -> Path:
    return backups.backup_path("saml-organizations", timestamp, endpoint, command, state)


def _chunks(values: list[str], size: int) -> list[list[str]]:
    return [values[start : start + size] for start in range(0, len(values), size)]
