"""Full-overwrite repo permission set workflow."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import src_py_lib as src

from ..shared import backups, id_codec, run_context, saml_groups
from ..shared import sourcegraph as shared_sourcegraph
from ..shared import types as shared_types
from . import apply as permissions_apply
from . import mapping as permissions_mapping
from . import snapshot as permission_snapshot
from . import types as permission_types
from .workflow import (
    load_mapping_context_for_rules,
    load_mapping_rules,
    render_projected_snapshot_diff,
    snapshot_path,
    user_ids_created_on_or_after,
    validate_post_apply,
    write_maps_backup,
    write_projected_snapshot,
    write_projected_snapshot_diff_file,
    write_snapshot_diff_file,
    write_snapshot_pair,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _FullSetUserState:
    """Full users and optional before-snapshot captured for planning."""

    users: list[shared_types.User]
    before_snapshot: permission_snapshot.Snapshot | None = None
    before_timestamp: str | None = None


@dataclass(frozen=True)
class _FullSetSnapshotState:
    """Compact users and optional before-snapshot retained after planning."""

    users: list[permission_snapshot.SnapshotUser]
    before_snapshot: permission_snapshot.Snapshot | None = None
    before_timestamp: str | None = None


@dataclass(frozen=True)
class _FullSetPlan:
    """Resolved full-set permission plan."""

    expected_users: dict[str, tuple[str, ...]]
    repo_names: dict[str, str]
    total_grants: int


@dataclass(frozen=True)
class _FullSetLoadedPlan:
    """Loaded full-set state plus reusable command data."""

    snapshot_state: _FullSetSnapshotState
    plan: _FullSetPlan
    command_data: run_context.CommandData
    apply_before_path: Path | None = None


@dataclass(frozen=True)
class _FullSetPlanFilter:
    """Full-set plans after removing repos that already match desired state."""

    overwrites: list[permission_types.RepositoryUsernameOverwrite]
    skipped_repo_ids: set[str]


@dataclass(frozen=True)
class _FullSetApplyResult:
    """Full-set mutation outcome."""

    mutations: shared_types.MutationCounts
    full_short_circuit: bool


def _set_full_command_name(dry_run: bool) -> str:
    return "set-dry-run" if dry_run else "set-apply"


def _capture_full_set_snapshot_state(
    client: src.SourcegraphClient,
    input_path: Path,
    parallelism: int,
    bind_id_mode: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> _FullSetUserState:
    """Load users while capturing the before-snapshot."""
    total_users = shared_sourcegraph.count_users(client)
    users: list[shared_types.User] = []
    log.info(
        "Streaming %d users from %s while capturing before-snapshot in parallel ...",
        total_users,
        client.endpoint,
    )
    before_timestamp = backups.backup_timestamp()
    before_snapshot = permission_snapshot.build_snapshot(
        client,
        shared_sourcegraph.list_users_streaming(client, collect_into=users),
        parallelism,
        bind_id_mode,
        input_path,
        total_users=total_users,
        worker_pool=worker_pool,
    )
    log.info(
        "Received %d total users; before-snapshot has %d repo(s) "
        "with explicit grants, %d total grant(s).",
        len(users),
        before_snapshot["stats"]["repos_with_explicit_grants"],
        before_snapshot["stats"]["total_grants"],
    )
    return _FullSetUserState(
        users=users,
        before_snapshot=before_snapshot,
        before_timestamp=before_timestamp,
    )


def _load_full_set_snapshot_state(
    client: src.SourcegraphClient,
    input_path: Path,
    parallelism: int,
    bind_id_mode: str,
    capture_before: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> _FullSetUserState:
    """Load all users, optionally with a before-snapshot."""
    if capture_before:
        return _capture_full_set_snapshot_state(
            client,
            input_path,
            parallelism,
            bind_id_mode,
            worker_pool,
        )

    log.info("Loading users from %s ...", client.endpoint)
    users = shared_sourcegraph.list_users_with_accounts(client)
    log.info("Received %d total users.", len(users))
    return _FullSetUserState(users=users)


def _filter_full_set_users_by_created_at(
    client: src.SourcegraphClient,
    users: list[shared_types.User],
    user_created_after: str | None,
) -> list[shared_types.User]:
    """Apply the optional created-after user filter."""
    if user_created_after is None:
        return users

    candidate_user_ids = user_ids_created_on_or_after(client, user_created_after)
    filtered_users = [user for user in users if user["id"] in candidate_user_ids]
    log.info(
        "Restricted users to %d / %d created on or after %s.",
        len(filtered_users),
        len(users),
        user_created_after,
    )
    return filtered_users


def _compact_full_set_snapshot_state(
    snapshot_state: _FullSetUserState,
    users: list[shared_types.User],
) -> _FullSetSnapshotState:
    """Return snapshot state with only fields needed for later capture."""
    return _FullSetSnapshotState(
        users=permission_snapshot.compact_snapshot_users(users),
        before_snapshot=snapshot_state.before_snapshot,
        before_timestamp=snapshot_state.before_timestamp,
    )


def _require_before_snapshot(
    snapshot_state: _FullSetUserState | _FullSetSnapshotState,
) -> tuple[permission_snapshot.Snapshot, str]:
    assert snapshot_state.before_snapshot is not None, (
        "snapshot writes require a prefetched before snapshot"
    )
    assert snapshot_state.before_timestamp is not None, (
        "snapshot writes require a prefetched before timestamp"
    )
    return snapshot_state.before_snapshot, snapshot_state.before_timestamp


def _write_full_set_snapshot_pair(
    input_path: Path,
    timestamp: str,
    endpoint: str,
    command_name: str,
    before_snapshot: permission_snapshot.Snapshot,
    after_snapshot: permission_snapshot.Snapshot,
) -> tuple[Path, Path, Path, Path | None]:
    """Write before/after/diff snapshots and the companion maps backup."""
    before_path, after_path, diff_path = write_snapshot_pair(
        input_path,
        timestamp,
        endpoint,
        command_name,
        before_snapshot,
        after_snapshot,
    )
    maps_backup_path = write_maps_backup(input_path, timestamp, endpoint, command_name)
    return before_path, after_path, diff_path, maps_backup_path


def _recordmaps_backup_path(command_event: dict[str, Any], maps_backup_path: Path | None) -> None:
    if maps_backup_path is not None:
        command_event["maps_backup_path"] = str(maps_backup_path)


def _write_noop_full_set_snapshots(
    input_path: Path,
    timestamp: str,
    endpoint: str,
    command_name: str,
    before_snapshot: permission_snapshot.Snapshot,
    dry_run: bool,
) -> tuple[Path, Path, Path, Path | None]:
    """Write identical before/after snapshots for a no-op full-set run."""
    before_path, after_path, diff_path, maps_backup_path = _write_full_set_snapshot_pair(
        input_path,
        timestamp,
        endpoint,
        command_name,
        before_snapshot,
        before_snapshot,
    )
    run_mode = "dry-run" if dry_run else "apply"
    log.info(
        "Wrote %s snapshots: before=%s after=%s diff=%s.",
        run_mode,
        before_path,
        after_path,
        diff_path,
    )
    return before_path, after_path, diff_path, maps_backup_path


def _plan_full_set_permissions(
    context: permission_types.MappingContext,
    users: list[shared_types.User],
) -> _FullSetPlan:
    """Resolve mapping rules into one repo-to-users overwrite plan."""
    repo_usernames: dict[str, set[str]] = {}
    repo_names: dict[str, str] = {}

    for mapping_index, mapping in enumerate(context.mapping_rules, start=1):
        name = mapping.get("name", f"<unnamed mapping #{mapping_index}>")
        log.info("=== Mapping %d / %d: %s ===", mapping_index, len(context.mapping_rules), name)

        users_section = cast(dict[str, object], mapping["users"])
        repos_section = cast(dict[str, object], mapping["repos"])

        matched_users = permissions_mapping.resolve_users(
            users_section,
            users,
            context.providers,
            context.saml_groups_attribute_names,
        )
        log.info("  Matched %d user(s).", len(matched_users))
        if not matched_users:
            log.warning("  No users matched — skipping rule.")
            continue

        matched_repos = permissions_mapping.resolve_repos(
            repos_section,
            context.services_by_id,
            context.repos_by_external_service_id,
            context.all_repos_by_id,
        )
        log.info("  Matched %d repo(s).", len(matched_repos))
        if not matched_repos:
            log.warning("  No repos matched — skipping rule.")
            continue

        matched_usernames = tuple(user["username"] for user in matched_users)
        for repo in matched_repos:
            bucket = repo_usernames.setdefault(repo["id"], set())
            repo_names[repo["id"]] = repo["name"]
            bucket.update(matched_usernames)

    expected_users = {
        repo_id: tuple(sorted(usernames)) for repo_id, usernames in repo_usernames.items()
    }
    total_grants = sum(len(usernames) for usernames in expected_users.values())
    if expected_users:
        log.info(
            "Resolved %d repo(s) covering %d (repo, user) grant(s) across %d mapping(s).",
            len(expected_users),
            total_grants,
            len(context.mapping_rules),
        )
    return _FullSetPlan(
        expected_users=expected_users,
        repo_names=repo_names,
        total_grants=total_grants,
    )


def _full_set_username_overwrites(
    plan: _FullSetPlan,
) -> list[permission_types.RepositoryUsernameOverwrite]:
    """Return per-repo overwrite plans without GraphQL payload dicts."""
    return [
        permission_types.RepositoryUsernameOverwrite(
            repository_id=repo_id,
            repository_name=plan.repo_names[repo_id],
            usernames=usernames,
        )
        for repo_id, usernames in plan.expected_users.items()
    ]


def _finish_full_set_dry_run(
    input_path: Path,
    endpoint: str,
    snapshot_state: _FullSetSnapshotState,
    plan: _FullSetPlan,
    command_event: dict[str, Any],
) -> None:
    """Write dry-run artifacts and log the planned mutations."""
    before_snapshot, timestamp = _require_before_snapshot(snapshot_state)
    before_path = snapshot_path(input_path, timestamp, endpoint, "set-dry-run", "before")
    after_path = snapshot_path(input_path, timestamp, endpoint, "set-dry-run", "after")
    after_snapshot = write_projected_snapshot(
        after_path,
        before_snapshot,
        plan.expected_users,
        plan.repo_names,
    )
    diff_path = write_projected_snapshot_diff_file(
        input_path,
        timestamp,
        endpoint,
        "set-dry-run",
        before_snapshot,
        after_snapshot,
        plan.expected_users,
        plan.repo_names,
    )
    log.info(
        "Wrote dry-run snapshots: before=%s after=%s diff=%s.",
        before_path,
        after_path,
        diff_path,
    )
    log.info(
        "Diff (before → dry-run after):\n%s",
        render_projected_snapshot_diff(
            before_snapshot,
            after_snapshot,
            plan.expected_users,
            plan.repo_names,
        ),
    )
    for repo_id, usernames in plan.expected_users.items():
        log.info(
            "[DRY RUN] Would set %d users on repo %s (id=%d).",
            len(usernames),
            plan.repo_names[repo_id],
            id_codec.decode_repository_id(repo_id),
        )
    log.info("Dry run complete. Pass --apply to mutate state.")


def _filter_full_set_plans(
    before_snapshot: permission_snapshot.Snapshot | None,
    plan: _FullSetPlan,
    command_event: dict[str, Any],
) -> _FullSetPlanFilter:
    """Drop mutation plans for repos already at desired state."""
    overwrites = _full_set_username_overwrites(plan)
    if before_snapshot is None or not overwrites:
        return _FullSetPlanFilter(overwrites=overwrites, skipped_repo_ids=set())

    skipped_repo_ids: set[str] = set()
    with src.event(
        "short_circuit_filter",
        repos_planned=len(overwrites),
    ) as short_circuit_event:
        before_repos_map = before_snapshot["repos"]
        pending_overwrites: list[permission_types.RepositoryUsernameOverwrite] = []
        for overwrite in overwrites:
            current_repo = before_repos_map.get(overwrite.repository_id)
            current_usernames = current_repo["explicit_permissions_users"] if current_repo else []
            expected_list = list(overwrite.usernames)
            if current_usernames == expected_list or sorted(current_usernames) == expected_list:
                skipped_repo_ids.add(overwrite.repository_id)
            else:
                pending_overwrites.append(overwrite)
        short_circuit_event["repos_skipped"] = len(skipped_repo_ids)
        short_circuit_event["repos_to_apply"] = len(pending_overwrites)

    if skipped_repo_ids:
        log.info(
            "Short-circuit: %d / %d planned repo(s) already at the "
            "desired explicit-permissions state — skipping their "
            "setRepositoryPermissionsForUsers calls.",
            len(skipped_repo_ids),
            len(overwrites),
        )
    command_event["repos_short_circuited"] = len(skipped_repo_ids)
    return _FullSetPlanFilter(
        overwrites=pending_overwrites,
        skipped_repo_ids=skipped_repo_ids,
    )


def _write_full_set_before_snapshot(
    input_path: Path,
    timestamp: str,
    endpoint: str,
    command_name: str,
    before_snapshot: permission_snapshot.Snapshot,
    command_event: dict[str, Any],
) -> Path:
    """Persist the before-snapshot and maps backup before planning mutations."""
    before_path = snapshot_path(input_path, timestamp, endpoint, command_name, "before")
    permission_snapshot.write_snapshot(before_path, before_snapshot)
    maps_backup_path = write_maps_backup(input_path, timestamp, endpoint, command_name)
    _recordmaps_backup_path(command_event, maps_backup_path)
    log.info(
        "Wrote before-snapshot: %s (%d repo(s) with explicit grants, %d total grant(s)).",
        before_path,
        before_snapshot["stats"]["repos_with_explicit_grants"],
        before_snapshot["stats"]["total_grants"],
    )
    return before_path


def _apply_full_set_plans(
    client: src.SourcegraphClient,
    overwrites: list[permission_types.RepositoryUsernameOverwrite],
    skipped_repo_ids: set[str],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> _FullSetApplyResult:
    """Apply full-set plans unless all were short-circuited."""
    full_short_circuit = bool(skipped_repo_ids) and not overwrites
    if full_short_circuit:
        log.info(
            "All %d planned repo(s) already at the desired state — nothing to apply.",
            len(skipped_repo_ids),
        )
        return _FullSetApplyResult(
            mutations=shared_types.MutationCounts(),
            full_short_circuit=True,
        )

    log.info(
        "Applying %d setRepositoryPermissionsForUsers mutation(s) with parallelism=%d ...",
        len(overwrites),
        parallelism,
    )
    with src.stage("apply"):
        mutations = permissions_apply.apply_username_overwrites(
            client,
            overwrites,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )
    log.info(
        "Apply done. %d succeeded, %d failed, %d canceled.",
        mutations.succeeded,
        mutations.failed,
        mutations.canceled,
    )
    return _FullSetApplyResult(
        mutations=mutations,
        full_short_circuit=False,
    )


def _record_full_set_event_fields(
    command_event: dict[str, Any],
    mapping_count: int,
    plan: _FullSetPlan,
    apply_result: _FullSetApplyResult,
) -> None:
    command_event["mapping_count"] = mapping_count
    command_event["repo_count"] = len(plan.expected_users)
    command_event["total_grants"] = plan.total_grants
    command_event["mutations_succeeded"] = apply_result.mutations.succeeded
    command_event["mutations_failed"] = apply_result.mutations.failed
    command_event["mutations_canceled"] = apply_result.mutations.canceled
    command_event["full_short_circuit"] = apply_result.full_short_circuit


def _finish_full_set_apply_with_backup(
    client: src.SourcegraphClient,
    input_path: Path,
    timestamp: str,
    before_path: Path,
    before_snapshot: permission_snapshot.Snapshot,
    snapshot_state: _FullSetSnapshotState,
    plan: _FullSetPlan,
    apply_result: _FullSetApplyResult,
    parallelism: int,
    bind_id_mode: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Capture after-snapshot, write diff, validate, and print rollback hint."""
    if apply_result.full_short_circuit:
        after_snapshot = before_snapshot
    else:
        log.info("Capturing after-snapshot for %d users ...", len(snapshot_state.users))
        after_snapshot = permission_snapshot.build_snapshot(
            client,
            snapshot_state.users,
            parallelism,
            bind_id_mode,
            input_path,
            total_users=len(snapshot_state.users),
            worker_pool=worker_pool,
        )

    after_path = snapshot_path(input_path, timestamp, client.endpoint, "set-apply", "after")
    permission_snapshot.write_snapshot(after_path, after_snapshot)
    diff_path = write_snapshot_diff_file(
        input_path,
        timestamp,
        client.endpoint,
        "set-apply",
        before_snapshot,
        after_snapshot,
    )
    log.info(
        "Wrote after-snapshot: %s diff=%s (%d repo(s) with explicit grants, %d total grant(s)).",
        after_path,
        diff_path,
        after_snapshot["stats"]["repos_with_explicit_grants"],
        after_snapshot["stats"]["total_grants"],
    )
    log.info(
        "Diff (before → after):\n%s",
        permission_snapshot.render_snapshot_diff(before_snapshot, after_snapshot),
    )

    validate_post_apply(after_snapshot, plan.expected_users, set(plan.expected_users))
    log.info(
        "To roll back the explicit-permissions state captured in "
        "the before-snapshot, run:\n"
        "  uv run src-auth-perms-sync --restore %s --apply",
        before_path,
    )


def _raise_for_failed_full_set_apply(
    apply_result: _FullSetApplyResult,
    overwrite_count: int,
) -> None:
    if not (apply_result.mutations.failed or apply_result.mutations.canceled):
        return
    log.error(
        "RUN FAILED: %d mutation(s) failed, %d canceled by circuit "
        "breaker (out of %d planned). Review the log file and the "
        "before/after snapshots for details, then re-run --set --apply "
        "(after addressing the underlying cause) to retry the "
        "remaining work.",
        apply_result.mutations.failed,
        apply_result.mutations.canceled,
        overwrite_count,
    )
    raise SystemExit(1)


def _write_noop_full_set_artifacts(
    input_path: Path,
    endpoint: str,
    command_name: str,
    snapshot_state: _FullSetUserState | _FullSetSnapshotState,
    dry_run: bool,
    command_event: dict[str, Any],
) -> None:
    """Write no-op before/after snapshots for an empty full-set run."""
    before_snapshot, timestamp = _require_before_snapshot(snapshot_state)
    *_, maps_backup_path = _write_noop_full_set_snapshots(
        input_path,
        timestamp,
        endpoint,
        command_name,
        before_snapshot,
        dry_run,
    )
    _recordmaps_backup_path(command_event, maps_backup_path)


def _finish_empty_full_set_mapping_rules(
    client: src.SourcegraphClient,
    input_path: Path,
    command_name: str,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    do_backup: bool,
    command_event: dict[str, Any],
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    log.warning("No maps defined in %s — nothing to do.", input_path)
    if not (dry_run or do_backup):
        return

    snapshot_state = _capture_full_set_snapshot_state(
        client,
        input_path,
        parallelism,
        bind_id_mode,
        worker_pool,
    )
    _write_noop_full_set_artifacts(
        input_path,
        client.endpoint,
        command_name,
        snapshot_state,
        dry_run,
        command_event,
    )


def _load_full_set_plan(
    client: src.SourcegraphClient,
    input_path: Path,
    mapping_rules: list[permission_types.MappingRule],
    user_created_after: str | None,
    parallelism: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    capture_before: bool,
    command_name: str,
    command_event: dict[str, Any],
    retain_saml_group_users: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> _FullSetLoadedPlan:
    user_state = _load_full_set_snapshot_state(
        client,
        input_path,
        parallelism,
        bind_id_mode,
        capture_before=capture_before,
        worker_pool=worker_pool,
    )
    before_path: Path | None = None
    if capture_before:
        before_snapshot, before_timestamp = _require_before_snapshot(user_state)
        before_path = _write_full_set_before_snapshot(
            input_path,
            before_timestamp,
            client.endpoint,
            command_name,
            before_snapshot,
            command_event,
        )

    context = load_mapping_context_for_rules(
        client,
        mapping_rules,
        saml_groups_attribute_name_by_config_id,
    )
    users = _filter_full_set_users_by_created_at(
        client,
        user_state.users,
        user_created_after,
    )
    plan = _plan_full_set_permissions(context, users)
    snapshot_state = _compact_full_set_snapshot_state(user_state, users)
    saml_group_users = (
        saml_groups.compact_saml_group_users(
            user_state.users,
            context.providers,
            context.saml_groups_attribute_names,
        )
        if retain_saml_group_users
        else None
    )
    return _FullSetLoadedPlan(
        snapshot_state=snapshot_state,
        plan=plan,
        command_data=run_context.CommandData(
            auth_providers=context.providers,
            saml_group_users=saml_group_users,
        ),
        apply_before_path=before_path,
    )


def _finish_empty_full_set_plan(
    input_path: Path,
    endpoint: str,
    command_name: str,
    snapshot_state: _FullSetSnapshotState,
    dry_run: bool,
    do_backup: bool,
    command_event: dict[str, Any],
) -> None:
    log.warning("No repos resolved across any mapping — nothing to do.")
    if dry_run or do_backup:
        _write_noop_full_set_artifacts(
            input_path,
            endpoint,
            command_name,
            snapshot_state,
            dry_run,
            command_event,
        )


def _run_full_set_apply(
    client: src.SourcegraphClient,
    input_path: Path,
    snapshot_state: _FullSetSnapshotState,
    plan: _FullSetPlan,
    mapping_count: int,
    parallelism: int,
    bind_id_mode: str,
    do_backup: bool,
    before_path: Path | None,
    command_event: dict[str, Any],
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Filter, apply, snapshot, validate, and raise for a full-set apply."""
    filtered_plans = _filter_full_set_plans(
        snapshot_state.before_snapshot,
        plan,
        command_event,
    )
    before_snapshot: permission_snapshot.Snapshot | None = None
    if do_backup:
        before_snapshot, before_timestamp = _require_before_snapshot(snapshot_state)
        assert before_path is not None
    else:
        before_timestamp = backups.backup_timestamp()

    apply_result = _apply_full_set_plans(
        client,
        filtered_plans.overwrites,
        filtered_plans.skipped_repo_ids,
        parallelism,
        worker_pool,
    )
    _record_full_set_event_fields(command_event, mapping_count, plan, apply_result)
    if do_backup:
        assert before_path is not None and before_snapshot is not None
        _finish_full_set_apply_with_backup(
            client,
            input_path,
            before_timestamp,
            before_path,
            before_snapshot,
            snapshot_state,
            plan,
            apply_result,
            parallelism,
            bind_id_mode,
            worker_pool,
        )

    _raise_for_failed_full_set_apply(apply_result, len(filtered_plans.overwrites))


def cmd_set_full(
    client: src.SourcegraphClient,
    input_path: Path,
    user_created_after: str | None,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    retain_saml_group_users: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> run_context.CommandData:
    """Overwrite each mapped repo with the union of users from all rules."""
    with src.event(
        "cmd_set",
        input_path=str(input_path),
        user_created_after=user_created_after,
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ) as command_event:
        mapping_rules = load_mapping_rules(input_path)
        command_name = _set_full_command_name(dry_run)
        if not mapping_rules:
            _finish_empty_full_set_mapping_rules(
                client,
                input_path,
                command_name,
                dry_run,
                parallelism,
                bind_id_mode,
                do_backup,
                command_event,
                worker_pool,
            )
            return run_context.CommandData()

        loaded_plan = _load_full_set_plan(
            client,
            input_path,
            mapping_rules,
            user_created_after,
            parallelism,
            bind_id_mode,
            saml_groups_attribute_name_by_config_id,
            capture_before=dry_run or do_backup,
            command_name=command_name,
            command_event=command_event,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
        )
        snapshot_state = loaded_plan.snapshot_state
        plan = loaded_plan.plan
        if not plan.expected_users:
            _finish_empty_full_set_plan(
                input_path,
                client.endpoint,
                command_name,
                snapshot_state,
                dry_run,
                do_backup,
                command_event,
            )
            return loaded_plan.command_data

        if dry_run:
            _finish_full_set_dry_run(
                input_path,
                client.endpoint,
                snapshot_state,
                plan,
                command_event,
            )
            return loaded_plan.command_data

        _run_full_set_apply(
            client,
            input_path,
            snapshot_state,
            plan,
            len(mapping_rules),
            parallelism,
            bind_id_mode,
            do_backup,
            loaded_plan.apply_before_path,
            command_event,
            worker_pool,
        )
        return loaded_plan.command_data
