"""Full-overwrite repo permission set workflow."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import src_py_lib as src

from ..shared import backups, run_context, saml_groups
from ..shared import sourcegraph as shared_sourcegraph
from ..shared import types as shared_types
from . import apply as permissions_apply
from . import mapping as permissions_mapping
from . import snapshot as permission_snapshot
from . import sourcegraph as permissions_sourcegraph
from . import types as permission_types
from .workflow import (
    load_mapping_context_discovery,
    load_mapping_context_for_rules,
    load_mapping_rules,
    load_repository_candidates_by_names,
    load_repository_candidates_created_on_or_after,
    mapping_context_with_repository_candidates,
    projected_snapshot_shell,
    render_projected_snapshot_diff,
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


@dataclass(frozen=True)
class _FullSetSnapshotState:
    """Compact users and optional before-snapshot retained after planning."""

    users: list[permission_snapshot.SnapshotUser]
    before_snapshot: permission_snapshot.Snapshot | None = None
    selected_repository_ids: set[str] | None = None


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


def _capture_full_set_snapshot_state(
    client: src.SourcegraphClient,
    input_path: Path,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    worker_pool: ThreadPoolExecutor | None = None,
    include_user_emails: bool = False,
    include_user_account_data: bool = True,
    selected_repository_ids: set[str] | None = None,
) -> _FullSetUserState:
    """Load users while capturing the before-snapshot."""
    expected_user_count = shared_sourcegraph.count_users(client)
    users: list[shared_types.User] = []
    log.info(
        "Streaming %d users from %s while capturing before-snapshot in parallel ...",
        expected_user_count,
        client.endpoint,
    )
    before_snapshot = permission_snapshot.build_snapshot(
        client,
        shared_sourcegraph.list_users_streaming(
            client,
            collect_into=users,
            include_emails=include_user_emails,
            include_account_data=include_user_account_data,
        ),
        parallelism,
        bind_id_mode,
        input_path,
        expected_user_count=expected_user_count,
        explicit_permissions_batch_size=explicit_permissions_batch_size,
        worker_pool=worker_pool,
        selected_repository_ids=selected_repository_ids,
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
    )


def _load_full_set_snapshot_state(
    client: src.SourcegraphClient,
    input_path: Path,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    capture_before: bool,
    worker_pool: ThreadPoolExecutor | None = None,
    include_user_emails: bool = False,
    include_user_account_data: bool = True,
    selected_repository_ids: set[str] | None = None,
) -> _FullSetUserState:
    """Load all users, optionally with a before-snapshot."""
    if capture_before:
        return _capture_full_set_snapshot_state(
            client,
            input_path,
            parallelism,
            explicit_permissions_batch_size,
            bind_id_mode,
            worker_pool,
            include_user_emails=include_user_emails,
            include_user_account_data=include_user_account_data,
            selected_repository_ids=selected_repository_ids,
        )

    log.info("Loading users from %s ...", client.endpoint)
    users = shared_sourcegraph.list_users_with_accounts(
        client,
        include_emails=include_user_emails,
        include_account_data=include_user_account_data,
    )
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


def _repository_ids(
    candidates: list[permissions_sourcegraph.RepositoryCandidate],
) -> set[str]:
    """Return Sourcegraph repository node IDs from candidates."""
    return {candidate.repository["id"] for candidate in candidates}


def _load_pre_snapshot_repository_candidates(
    client: src.SourcegraphClient,
    repository_names: tuple[str, ...],
    repository_created_after: str | None,
) -> list[permissions_sourcegraph.RepositoryCandidate] | None:
    """Load repo filters that do not depend on current explicit grants."""
    if repository_names:
        return load_repository_candidates_by_names(client, repository_names)
    if repository_created_after is not None:
        return load_repository_candidates_created_on_or_after(
            client,
            repository_created_after,
            "--repos-created-after",
        )
    return None


def _load_repositories_without_explicit_permissions(
    client: src.SourcegraphClient,
    before_snapshot: permission_snapshot.Snapshot,
) -> list[permissions_sourcegraph.RepositoryCandidate]:
    """Load repo candidates without any explicit API grants."""
    candidates = permissions_sourcegraph.list_repository_candidates(client)
    explicit_repository_ids = set(before_snapshot["repos"])
    selected_candidates = [
        candidate
        for candidate in candidates
        if candidate.repository["id"] not in explicit_repository_ids
    ]
    log.info(
        "Selected %d / %d repo(s) without explicit repo permissions.",
        len(selected_candidates),
        len(candidates),
    )
    return selected_candidates


def _filter_full_set_user_state_snapshot(
    snapshot_state: _FullSetUserState,
    selected_repository_ids: set[str] | None,
) -> _FullSetUserState:
    """Return user state with before-snapshot scoped to selected repos."""
    if snapshot_state.before_snapshot is None or selected_repository_ids is None:
        return snapshot_state
    return _FullSetUserState(
        users=snapshot_state.users,
        before_snapshot=permission_snapshot.snapshot_with_repository_filter(
            snapshot_state.before_snapshot,
            selected_repository_ids,
        ),
    )


def _compact_full_set_snapshot_state(
    snapshot_state: _FullSetUserState,
    users: list[shared_types.User],
    selected_repository_ids: set[str] | None = None,
) -> _FullSetSnapshotState:
    """Return snapshot state with only fields needed for later capture."""
    return _FullSetSnapshotState(
        users=permission_snapshot.compact_snapshot_users(users),
        before_snapshot=snapshot_state.before_snapshot,
        selected_repository_ids=selected_repository_ids,
    )


def _require_before_snapshot(
    snapshot_state: _FullSetUserState | _FullSetSnapshotState,
) -> permission_snapshot.Snapshot:
    assert snapshot_state.before_snapshot is not None, (
        "snapshot writes require a prefetched before snapshot"
    )
    return snapshot_state.before_snapshot


def _recordmaps_backup_path(command_event: dict[str, Any], maps_backup_path: Path | None) -> None:
    if maps_backup_path is not None:
        command_event["maps_backup_path"] = str(maps_backup_path)


def plan_full_set_permissions(
    context: permission_types.MappingContext,
    users: list[shared_types.User],
) -> _FullSetPlan:
    """Resolve mapping rules into one repo-to-users overwrite plan."""
    expected_users: dict[str, tuple[str, ...]] = {}
    union_usernames_by_repo_id: dict[str, set[str]] = {}
    repo_names: dict[str, str] = {}

    for mapping_index, mapping in enumerate(context.mapping_rules, start=1):
        name = mapping.get("name", f"<unnamed mapping #{mapping_index}>")
        log.info("=== Mapping %d / %d: %s ===", mapping_index, len(context.mapping_rules), name)

        user_selector = mapping["users"]
        repository_selector = mapping["repos"]

        matched_users = permissions_mapping.resolve_users(
            user_selector,
            users,
            context.providers,
            context.saml_groups_attribute_names,
        )
        log.info("  Matched %d user(s).", len(matched_users))
        if not matched_users:
            log.warning("  No users matched — skipping rule.")
            continue

        matched_repos = permissions_mapping.resolve_repos(
            repository_selector,
            context.services_by_id,
            context.repos_by_external_service_id,
            context.all_repos_by_id,
        )
        log.info("  Matched %d repo(s).", len(matched_repos))
        if not matched_repos:
            log.warning("  No repos matched — skipping rule.")
            continue

        matched_usernames = tuple(sorted({user["username"] for user in matched_users}))
        for repo in matched_repos:
            repo_id = repo["id"]
            repo_names[repo_id] = repo["name"]
            union_usernames = union_usernames_by_repo_id.get(repo_id)
            if union_usernames is not None:
                union_usernames.update(matched_usernames)
                continue

            existing_usernames = expected_users.get(repo_id)
            if existing_usernames is not None:
                union_usernames = set(existing_usernames)
                union_usernames.update(matched_usernames)
                union_usernames_by_repo_id[repo_id] = union_usernames
                del expected_users[repo_id]
                continue

            expected_users[repo_id] = matched_usernames

    for repo_id, usernames in union_usernames_by_repo_id.items():
        expected_users[repo_id] = tuple(sorted(usernames))

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
    run_paths: backups.RunPaths,
    snapshot_state: _FullSetSnapshotState,
    plan: _FullSetPlan,
    command_event: dict[str, Any],
) -> None:
    """Write dry-run artifacts and log the planned mutations."""
    before_snapshot = _require_before_snapshot(snapshot_state)
    if run_paths.write_files:
        after_path = run_paths.artifact_path("after")
        after_snapshot = write_projected_snapshot(
            after_path,
            before_snapshot,
            plan.expected_users,
            plan.repo_names,
        )
        diff_path = write_projected_snapshot_diff_file(
            run_paths,
            before_snapshot,
            after_snapshot,
            plan.expected_users,
            plan.repo_names,
        )
        log.info(
            "Wrote dry-run snapshots: before=%s after=%s diff=%s.",
            run_paths.artifact_path("before"),
            after_path,
            diff_path,
        )
    else:
        after_snapshot = projected_snapshot_shell(before_snapshot, plan.expected_users)
        log.info("Skipping dry-run snapshot files because --no-files is set.")
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
            src.decode_repository_id(repo_id),
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
    with src.span(
        "short_circuit_filter",
        repos_planned=len(overwrites),
    ) as short_circuit_event:
        before_repos_map = before_snapshot["repos"]
        pending_overwrites: list[permission_types.RepositoryUsernameOverwrite] = []
        for overwrite in overwrites:
            current_repo = before_repos_map.get(overwrite.repository_id)
            current_usernames = current_repo["users"] if current_repo else []
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


def _overwrites_with_preserved_pending(
    overwrites: list[permission_types.RepositoryUsernameOverwrite],
    pending_bind_ids_by_repository_id: dict[str, list[str]],
) -> list[permission_types.RepositoryUsernameOverwrite]:
    """Resend each repo's pending bindIDs so overwrites don't delete them.

    `setRepositoryPermissionsForUsers` replaces a repo's whole explicit
    list — real grants AND pending ones. Appending the repo's current
    pending bindIDs to the payload re-creates the same pending rows in the
    same transaction, so the script neither creates nor loses them.
    """
    if not pending_bind_ids_by_repository_id:
        return overwrites
    preserved_overwrites: list[permission_types.RepositoryUsernameOverwrite] = []
    preserved_repo_count = 0
    preserved_grant_count = 0
    for overwrite in overwrites:
        pending_bind_ids = [
            bind_id
            for bind_id in pending_bind_ids_by_repository_id.get(overwrite.repository_id, [])
            if bind_id not in overwrite.usernames
        ]
        if not pending_bind_ids:
            preserved_overwrites.append(overwrite)
            continue
        preserved_repo_count += 1
        preserved_grant_count += len(pending_bind_ids)
        preserved_overwrites.append(
            permission_types.RepositoryUsernameOverwrite(
                repository_id=overwrite.repository_id,
                repository_name=overwrite.repository_name,
                usernames=overwrite.usernames + tuple(pending_bind_ids),
            )
        )
    if preserved_repo_count:
        log.info(
            "Preserving %d pending bindID grant(s) across %d repo(s) in overwrite payloads.",
            preserved_grant_count,
            preserved_repo_count,
        )
    return preserved_overwrites


def _write_full_set_before_snapshot(
    run_paths: backups.RunPaths,
    before_snapshot: permission_snapshot.Snapshot,
    command_event: dict[str, Any],
) -> Path:
    """Persist the before-snapshot and maps backup before planning mutations."""
    before_path = run_paths.artifact_path("before")
    if not run_paths.write_files:
        log.info("Skipping before-snapshot and maps backup files because --no-files is set.")
        return before_path
    permission_snapshot.write_snapshot(before_path, before_snapshot)
    maps_backup_path = write_maps_backup(run_paths.maps_path, run_paths)
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
        "Apply done. %d succeeded, %d skipped, %d failed, %d canceled.",
        mutations.succeeded,
        mutations.skipped,
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
    command_event["mutations_skipped"] = apply_result.mutations.skipped
    command_event["mutations_failed"] = apply_result.mutations.failed
    command_event["mutations_canceled"] = apply_result.mutations.canceled
    command_event["full_short_circuit"] = apply_result.full_short_circuit


def _finish_full_set_apply_with_backup(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    before_path: Path,
    before_snapshot: permission_snapshot.Snapshot,
    snapshot_state: _FullSetSnapshotState,
    plan: _FullSetPlan,
    apply_result: _FullSetApplyResult,
    parallelism: int,
    explicit_permissions_batch_size: int,
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
            run_paths.maps_path,
            expected_user_count=len(snapshot_state.users),
            explicit_permissions_batch_size=explicit_permissions_batch_size,
            worker_pool=worker_pool,
            selected_repository_ids=snapshot_state.selected_repository_ids,
        )

    if run_paths.write_files:
        after_path = run_paths.artifact_path("after")
        permission_snapshot.write_snapshot(after_path, after_snapshot)
        diff_path = write_snapshot_diff_file(run_paths, before_snapshot, after_snapshot)
        log.info(
            "Wrote after-snapshot: %s diff=%s "
            "(%d repo(s) with explicit grants, %d total grant(s)).",
            after_path,
            diff_path,
            after_snapshot["stats"]["repos_with_explicit_grants"],
            after_snapshot["stats"]["total_grants"],
        )
    else:
        log.info("Skipping after-snapshot and diff files because --no-files is set.")
    log.info(
        "Diff (before → after):\n%s",
        permission_snapshot.render_snapshot_diff(before_snapshot, after_snapshot),
    )

    validate_post_apply(
        after_snapshot,
        plan.expected_users,
        set(plan.expected_users),
        expected_pending_users=before_snapshot["pending_users"],
    )
    if run_paths.write_files:
        log.info(
            "To roll back the explicit-permissions state captured in "
            "the before-snapshot, run:\n"
            "  uv run src-auth-perms-sync restore --restore-path %s --apply",
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
        "before/after snapshots for details, then re-run set --apply "
        "(after addressing the underlying cause) to retry the "
        "remaining work.",
        apply_result.mutations.failed,
        apply_result.mutations.canceled,
        overwrite_count,
    )
    raise SystemExit(1)


def _write_noop_full_set_artifacts(
    run_paths: backups.RunPaths,
    snapshot_state: _FullSetUserState | _FullSetSnapshotState,
    dry_run: bool,
    command_event: dict[str, Any],
) -> None:
    """Write no-op before/after snapshots for an empty full-set run."""
    before_snapshot = _require_before_snapshot(snapshot_state)
    if not run_paths.write_files:
        log.info("Skipping no-op snapshot files because --no-files is set.")
        return
    before_path, after_path, diff_path = write_snapshot_pair(
        run_paths,
        before_snapshot,
        before_snapshot,
    )
    maps_backup_path = write_maps_backup(run_paths.maps_path, run_paths)
    _recordmaps_backup_path(command_event, maps_backup_path)
    log.info(
        "Wrote %s snapshots: before=%s after=%s diff=%s.",
        "dry-run" if dry_run else "apply",
        before_path,
        after_path,
        diff_path,
    )


def _finish_empty_full_set_mapping_rules(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    dry_run: bool,
    repository_names: tuple[str, ...],
    repositories_without_explicit_perms: bool,
    repository_created_after: str | None,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    do_backup: bool,
    command_event: dict[str, Any],
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    log.warning("No maps defined in %s — nothing to do.", run_paths.maps_path)
    if not (dry_run or do_backup):
        return

    selected_repository_candidates = _load_pre_snapshot_repository_candidates(
        client,
        repository_names,
        repository_created_after,
    )
    selected_repository_ids = (
        _repository_ids(selected_repository_candidates)
        if selected_repository_candidates is not None
        else None
    )
    snapshot_state = _capture_full_set_snapshot_state(
        client,
        run_paths.maps_path,
        parallelism,
        explicit_permissions_batch_size,
        bind_id_mode,
        worker_pool,
        include_user_account_data=False,
        selected_repository_ids=selected_repository_ids,
    )
    if repositories_without_explicit_perms:
        before_snapshot = _require_before_snapshot(snapshot_state)
        selected_repository_candidates = _load_repositories_without_explicit_permissions(
            client,
            before_snapshot,
        )
        snapshot_state = _filter_full_set_user_state_snapshot(
            snapshot_state,
            _repository_ids(selected_repository_candidates),
        )
    _write_noop_full_set_artifacts(
        run_paths,
        snapshot_state,
        dry_run,
        command_event,
    )


def _load_full_set_plan(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    mapping_rules: list[permission_types.MappingRule],
    user_created_after: str | None,
    repository_names: tuple[str, ...],
    repositories_without_explicit_perms: bool,
    repository_created_after: str | None,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    capture_before: bool,
    write_before_snapshot: bool,
    command_event: dict[str, Any],
    retain_saml_group_users: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> _FullSetLoadedPlan:
    include_user_emails = permissions_mapping.mapping_rules_need_user_emails(mapping_rules)
    include_user_account_data = (
        permissions_mapping.mapping_rules_need_saml_account_data(mapping_rules)
        or retain_saml_group_users
    )
    selected_repository_candidates = _load_pre_snapshot_repository_candidates(
        client,
        repository_names,
        repository_created_after,
    )
    selected_repository_ids = (
        _repository_ids(selected_repository_candidates)
        if selected_repository_candidates is not None
        else None
    )
    user_state = _load_full_set_snapshot_state(
        client,
        run_paths.maps_path,
        parallelism,
        explicit_permissions_batch_size,
        bind_id_mode,
        capture_before=capture_before,
        worker_pool=worker_pool,
        include_user_emails=include_user_emails,
        include_user_account_data=include_user_account_data,
        selected_repository_ids=selected_repository_ids,
    )
    if repositories_without_explicit_perms:
        before_snapshot = _require_before_snapshot(user_state)
        selected_repository_candidates = _load_repositories_without_explicit_permissions(
            client,
            before_snapshot,
        )
        selected_repository_ids = _repository_ids(selected_repository_candidates)
        user_state = _filter_full_set_user_state_snapshot(
            user_state,
            selected_repository_ids,
        )

    before_path: Path | None = None
    if write_before_snapshot:
        before_snapshot = _require_before_snapshot(user_state)
        before_path = _write_full_set_before_snapshot(
            run_paths,
            before_snapshot,
            command_event,
        )

    if selected_repository_candidates is None:
        context = load_mapping_context_for_rules(
            client,
            mapping_rules,
            saml_groups_attribute_name_by_config_id,
        )
    else:
        context = mapping_context_with_repository_candidates(
            load_mapping_context_discovery(
                client,
                mapping_rules,
                saml_groups_attribute_name_by_config_id,
            ),
            selected_repository_candidates,
        )

    if selected_repository_ids is not None:
        command_event["selected_repo_count"] = len(selected_repository_ids)

    users = _filter_full_set_users_by_created_at(
        client,
        user_state.users,
        user_created_after,
    )
    plan = plan_full_set_permissions(context, users)
    snapshot_state = _compact_full_set_snapshot_state(
        user_state,
        users,
        selected_repository_ids,
    )
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
    run_paths: backups.RunPaths,
    snapshot_state: _FullSetSnapshotState,
    dry_run: bool,
    do_backup: bool,
    command_event: dict[str, Any],
) -> None:
    log.warning("No repos resolved across any mapping — nothing to do.")
    if dry_run or do_backup:
        _write_noop_full_set_artifacts(
            run_paths,
            snapshot_state,
            dry_run,
            command_event,
        )


def _run_full_set_apply(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    snapshot_state: _FullSetSnapshotState,
    plan: _FullSetPlan,
    mapping_count: int,
    parallelism: int,
    explicit_permissions_batch_size: int,
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
        before_snapshot = _require_before_snapshot(snapshot_state)
        assert before_path is not None

    # The before-snapshot's pending grants are already scoped to any repo
    # selection; without one (--no-backup), fetch the live pending state so
    # the overwrites still preserve it.
    if snapshot_state.before_snapshot is not None:
        pending_users = snapshot_state.before_snapshot["pending_users"]
    else:
        pending_users = permissions_sourcegraph.list_pending_users_with_repos(client)
    overwrites = _overwrites_with_preserved_pending(
        filtered_plans.overwrites,
        permission_snapshot.pending_bind_ids_by_repository_id(pending_users),
    )

    apply_result = _apply_full_set_plans(
        client,
        overwrites,
        filtered_plans.skipped_repo_ids,
        parallelism,
        worker_pool,
    )
    _record_full_set_event_fields(command_event, mapping_count, plan, apply_result)
    if do_backup:
        assert before_path is not None and before_snapshot is not None
        _finish_full_set_apply_with_backup(
            client,
            run_paths,
            before_path,
            before_snapshot,
            snapshot_state,
            plan,
            apply_result,
            parallelism,
            explicit_permissions_batch_size,
            bind_id_mode,
            worker_pool,
        )

    _raise_for_failed_full_set_apply(apply_result, len(filtered_plans.overwrites))


def cmd_set_full(
    client: src.SourcegraphClient,
    run_paths: backups.RunPaths,
    user_created_after: str | None,
    repository_names: tuple[str, ...],
    repositories_without_explicit_perms: bool,
    repository_created_after: str | None,
    dry_run: bool,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    saml_groups_attribute_name_by_config_id: dict[str, str],
    do_backup: bool,
    retain_saml_group_users: bool,
    worker_pool: ThreadPoolExecutor | None = None,
) -> run_context.CommandData:
    """Overwrite each mapped repo with the union of users from all rules."""
    with src.span(
        "cmd_set",
        input_path=str(run_paths.maps_path),
        user_created_after=user_created_after,
        repository_names=repository_names or None,
        repositories_without_explicit_perms=(True if repositories_without_explicit_perms else None),
        repository_created_after=repository_created_after,
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ) as command_event:
        mapping_rules = load_mapping_rules(run_paths.maps_path)
        if not mapping_rules:
            _finish_empty_full_set_mapping_rules(
                client,
                run_paths,
                dry_run,
                repository_names,
                repositories_without_explicit_perms,
                repository_created_after,
                parallelism,
                explicit_permissions_batch_size,
                bind_id_mode,
                do_backup,
                command_event,
                worker_pool,
            )
            return run_context.CommandData()

        loaded_plan = _load_full_set_plan(
            client,
            run_paths,
            mapping_rules,
            user_created_after,
            repository_names,
            repositories_without_explicit_perms,
            repository_created_after,
            parallelism,
            explicit_permissions_batch_size,
            bind_id_mode,
            saml_groups_attribute_name_by_config_id,
            capture_before=dry_run or do_backup or repositories_without_explicit_perms,
            write_before_snapshot=dry_run or do_backup,
            command_event=command_event,
            retain_saml_group_users=retain_saml_group_users,
            worker_pool=worker_pool,
        )
        snapshot_state = loaded_plan.snapshot_state
        plan = loaded_plan.plan
        if not plan.expected_users:
            _finish_empty_full_set_plan(
                run_paths,
                snapshot_state,
                dry_run,
                do_backup,
                command_event,
            )
            return loaded_plan.command_data

        if dry_run:
            _finish_full_set_dry_run(
                run_paths,
                snapshot_state,
                plan,
                command_event,
            )
            return loaded_plan.command_data

        _run_full_set_apply(
            client,
            run_paths,
            snapshot_state,
            plan,
            len(mapping_rules),
            parallelism,
            explicit_permissions_batch_size,
            bind_id_mode,
            do_backup,
            loaded_plan.apply_before_path,
            command_event,
            worker_pool,
        )
        return loaded_plan.command_data
