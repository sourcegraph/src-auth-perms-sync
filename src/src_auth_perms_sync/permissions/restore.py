"""Repo permission restore workflows."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import src_py_lib as src

from ..shared import backups
from ..shared import sourcegraph as shared_sourcegraph
from ..shared import types as shared_types
from . import apply as permissions_apply
from . import snapshot as permission_snapshot
from . import types as permission_types
from .workflow import (
    write_snapshot_diff_file,
    write_snapshot_pair,
    write_user_scoped_snapshot_diff_file,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RestoreSnapshotState:
    """Target and live snapshots needed for a full restore."""

    target_snapshot: permission_snapshot.Snapshot
    current_snapshot: permission_snapshot.Snapshot
    users: list[permission_snapshot.SnapshotUser]


@dataclass(frozen=True)
class RestorePlan:
    """Per-repo overwrite plan for a full restore."""

    overwrites: list[permission_types.RepositoryUsernameOverwrite]
    snapshot_repo_count: int
    extra_repo_count: int
    skipped_repo_count: int


@dataclass(frozen=True)
class _UserScopedRestoreState:
    """Target and live snapshots needed for a user-scoped restore."""

    target_snapshot: permission_snapshot.UserScopedSnapshot
    current_snapshot: permission_snapshot.UserScopedSnapshot
    snapshot_users: list[permission_snapshot.SnapshotUser]


@dataclass(frozen=True)
class _UserScopedRestorePlan:
    """Add/remove plan for a user-scoped restore."""

    additions: list[permissions_apply.PermissionAddition]
    removals: list[permissions_apply.PermissionRemoval]


@dataclass(frozen=True)
class _UserScopedRestoreMutationResult:
    """Mutation results for both user-scoped restore phases."""

    additions: shared_types.MutationCounts
    removals: shared_types.MutationCounts


def cmd_restore_user_scoped(
    client: src.SourcegraphClient,
    snapshot_path: Path,
    run_paths: backups.RunPaths,
    *,
    dry_run: bool,
    parallelism: int,
    bind_id_mode: str,
    do_backup: bool,
    target_snapshot: permission_snapshot.UserScopedSnapshot | None = None,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Restore explicit permissions for the users present in a scoped snapshot."""
    with src.span(
        "cmd_restore_user_scoped",
        snapshot_path=str(snapshot_path),
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ):
        if target_snapshot is None:
            target_snapshot = permission_snapshot.read_user_scoped_snapshot(snapshot_path)
        _validate_user_scoped_restore_snapshot_context(
            client,
            target_snapshot,
            snapshot_path,
            bind_id_mode,
        )
        snapshot_state = _capture_user_scoped_restore_state(
            client,
            snapshot_path,
            target_snapshot,
            parallelism,
            bind_id_mode,
            worker_pool,
        )
        plan = _plan_user_scoped_restore(
            snapshot_state.current_snapshot,
            snapshot_state.target_snapshot,
        )
        _log_user_scoped_restore_plan(snapshot_state, plan)

        if dry_run or do_backup:
            _write_user_scoped_restore_initial_artifacts(
                run_paths,
                snapshot_state.current_snapshot,
                snapshot_state.target_snapshot,
                dry_run,
            )

        if dry_run:
            log.info("Dry run complete. Pass --apply to mutate state.")
            return
        if not plan.additions and not plan.removals:
            _finish_empty_user_scoped_restore_plan(
                run_paths,
                snapshot_state.current_snapshot,
                do_backup,
            )
            return

        mutations = _apply_user_scoped_restore(client, plan, parallelism, worker_pool)

        if do_backup:
            _finish_user_scoped_restore_apply_with_backup(
                client,
                snapshot_path,
                run_paths,
                snapshot_state,
                parallelism,
                bind_id_mode,
                worker_pool,
            )

        _raise_for_failed_user_scoped_restore(mutations)
        _log_user_scoped_restore_done(mutations)


def _snapshot_users_from_user_scoped_snapshot(
    snapshot: permission_snapshot.UserScopedSnapshot,
) -> list[permission_snapshot.SnapshotUser]:
    return [
        {"id": user_snapshot["id"], "username": username}
        for username, user_snapshot in sorted(snapshot["users"].items())
    ]


def _plan_user_scoped_restore(
    current_snapshot: permission_snapshot.UserScopedSnapshot,
    target_snapshot: permission_snapshot.UserScopedSnapshot,
) -> _UserScopedRestorePlan:
    additions: list[permissions_apply.PermissionAddition] = []
    removals: list[permissions_apply.PermissionRemoval] = []
    for username, target_user in target_snapshot["users"].items():
        current_user = current_snapshot["users"].get(username)
        current_repos = {
            repository["id"]: repository["name"]
            for repository in (current_user["repos"] if current_user else [])
        }
        target_repos = {repository["id"]: repository["name"] for repository in target_user["repos"]}
        for repo_id in sorted(
            set(target_repos) - set(current_repos),
            key=lambda value: target_repos[value],
        ):
            additions.append(
                permissions_apply.PermissionAddition(
                    user_id=target_user["id"],
                    username=username,
                    repo_id=repo_id,
                    repo_name=target_repos[repo_id],
                )
            )
        for repo_id in sorted(
            set(current_repos) - set(target_repos),
            key=lambda value: current_repos[value],
        ):
            removals.append(
                permissions_apply.PermissionRemoval(
                    user_id=target_user["id"],
                    username=username,
                    repo_id=repo_id,
                    repo_name=current_repos[repo_id],
                )
            )
    return _UserScopedRestorePlan(additions=additions, removals=removals)


def _validate_user_scoped_restore_snapshot_context(
    client: src.SourcegraphClient,
    target_snapshot: permission_snapshot.UserScopedSnapshot,
    snapshot_path: Path,
    bind_id_mode: str,
) -> None:
    """Warn when a user-scoped restore target differs from the current context."""
    if target_snapshot["bindID_mode"] != bind_id_mode:
        log.warning(
            "Snapshot bindID_mode=%s differs from live bindID_mode=%s - "
            "captured usernames may not resolve to the same users.",
            target_snapshot["bindID_mode"],
            bind_id_mode,
        )
    if target_snapshot["endpoint"] != client.endpoint:
        log.warning(
            "Snapshot endpoint=%s differs from live endpoint=%s - restoring "
            "across instances. Proceeding anyway; review the plan diff.",
            target_snapshot["endpoint"],
            client.endpoint,
        )


def _capture_user_scoped_restore_state(
    client: src.SourcegraphClient,
    snapshot_path: Path,
    target_snapshot: permission_snapshot.UserScopedSnapshot,
    parallelism: int,
    bind_id_mode: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> _UserScopedRestoreState:
    """Capture live state for the users present in a scoped snapshot."""
    snapshot_users = _snapshot_users_from_user_scoped_snapshot(target_snapshot)
    current_snapshot = permission_snapshot.build_user_scoped_snapshot(
        client,
        snapshot_users,
        parallelism,
        bind_id_mode,
        snapshot_path,
        worker_pool=worker_pool,
    )
    return _UserScopedRestoreState(
        target_snapshot=target_snapshot,
        current_snapshot=current_snapshot,
        snapshot_users=snapshot_users,
    )


def _log_user_scoped_restore_plan(
    snapshot_state: _UserScopedRestoreState,
    plan: _UserScopedRestorePlan,
) -> None:
    log.info(
        "Scoped restore plan: %d grant(s) to add, %d grant(s) to remove.",
        len(plan.additions),
        len(plan.removals),
    )
    log.info(
        "Diff (current -> scoped snapshot):\n%s",
        permission_snapshot.render_user_scoped_diff(
            snapshot_state.current_snapshot,
            snapshot_state.target_snapshot,
        ),
    )


def _write_user_scoped_restore_initial_artifacts(
    run_paths: backups.RunPaths,
    current_snapshot: permission_snapshot.UserScopedSnapshot,
    target_snapshot: permission_snapshot.UserScopedSnapshot,
    dry_run: bool,
) -> None:
    """Write before-snapshot and optional dry-run target artifacts."""
    if not run_paths.write_files:
        log.info("Skipping scoped restore snapshot files because --no-files is set.")
        return
    before_restore_path = run_paths.artifact_path("before")
    permission_snapshot.write_user_scoped_snapshot(before_restore_path, current_snapshot)
    log.info("Wrote scoped restore before-snapshot: %s", before_restore_path)
    if not dry_run:
        return

    after_restore_path = run_paths.artifact_path("after")
    permission_snapshot.write_user_scoped_snapshot(after_restore_path, target_snapshot)
    diff_path = write_user_scoped_snapshot_diff_file(
        run_paths,
        current_snapshot,
        target_snapshot,
    )
    log.info("Wrote scoped restore after-snapshot: %s diff=%s", after_restore_path, diff_path)


def _finish_empty_user_scoped_restore_plan(
    run_paths: backups.RunPaths,
    current_snapshot: permission_snapshot.UserScopedSnapshot,
    do_backup: bool,
) -> None:
    log.info("Scoped restore target already matches current state - nothing to apply.")
    if not do_backup:
        return
    if not run_paths.write_files:
        log.info("Skipping scoped restore snapshot files because --no-files is set.")
        return

    after_restore_path = run_paths.artifact_path("after")
    permission_snapshot.write_user_scoped_snapshot(after_restore_path, current_snapshot)
    diff_path = write_user_scoped_snapshot_diff_file(
        run_paths,
        current_snapshot,
        current_snapshot,
    )
    log.info("Wrote scoped restore after-snapshot: %s diff=%s", after_restore_path, diff_path)


def _apply_user_scoped_restore_removals(
    client: src.SourcegraphClient,
    removals: list[permissions_apply.PermissionRemoval],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    if not removals:
        return shared_types.MutationCounts()

    log.info(
        "Applying %d removeRepositoryPermissionForUser mutation(s) with parallelism=%d ...",
        len(removals),
        parallelism,
    )
    with src.stage("apply_removals"):
        return permissions_apply.apply_removals(
            client,
            removals,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )


def _apply_user_scoped_restore_additions(
    client: src.SourcegraphClient,
    additions: list[permissions_apply.PermissionAddition],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    if not additions:
        return shared_types.MutationCounts()

    log.info(
        "Applying %d addRepositoryPermissionForUser mutation(s) with parallelism=%d ...",
        len(additions),
        parallelism,
    )
    with src.stage("apply_additions"):
        return permissions_apply.apply_additions(
            client,
            additions,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )


def _apply_user_scoped_restore(
    client: src.SourcegraphClient,
    plan: _UserScopedRestorePlan,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> _UserScopedRestoreMutationResult:
    """Apply scoped restore removals before additions."""
    removals = _apply_user_scoped_restore_removals(
        client,
        plan.removals,
        parallelism,
        worker_pool,
    )
    additions = _apply_user_scoped_restore_additions(
        client,
        plan.additions,
        parallelism,
        worker_pool,
    )
    return _UserScopedRestoreMutationResult(additions=additions, removals=removals)


def _finish_user_scoped_restore_apply_with_backup(
    client: src.SourcegraphClient,
    snapshot_path: Path,
    run_paths: backups.RunPaths,
    snapshot_state: _UserScopedRestoreState,
    parallelism: int,
    bind_id_mode: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Capture scoped post-restore state and validate against the target."""
    after_restore_snapshot = permission_snapshot.build_user_scoped_snapshot(
        client,
        snapshot_state.snapshot_users,
        parallelism,
        bind_id_mode,
        snapshot_path,
        worker_pool=worker_pool,
    )
    if run_paths.write_files:
        after_restore_path = run_paths.artifact_path("after")
        permission_snapshot.write_user_scoped_snapshot(after_restore_path, after_restore_snapshot)
        diff_path = write_user_scoped_snapshot_diff_file(
            run_paths,
            snapshot_state.current_snapshot,
            after_restore_snapshot,
        )
        log.info("Wrote scoped restore after-snapshot: %s diff=%s", after_restore_path, diff_path)
    else:
        log.info("Skipping scoped restore after-snapshot files because --no-files is set.")
    residual = permission_snapshot.render_user_scoped_diff(
        after_restore_snapshot,
        snapshot_state.target_snapshot,
    )
    if residual != "No changes.":
        log.warning(
            "VALIDATION: scoped restore does NOT match target snapshot. Residual diff:\n%s",
            residual,
        )
    else:
        log.info("VALIDATION OK: scoped restore matches the target snapshot.")


def _raise_for_failed_user_scoped_restore(
    mutations: _UserScopedRestoreMutationResult,
) -> None:
    failed = mutations.removals.failed + mutations.additions.failed
    canceled = mutations.removals.canceled + mutations.additions.canceled
    if not (failed or canceled):
        return
    log.error(
        "SCOPED RESTORE FAILED: %d mutation(s) failed, %d canceled by circuit breaker.",
        failed,
        canceled,
    )
    raise SystemExit(1)


def _log_user_scoped_restore_done(mutations: _UserScopedRestoreMutationResult) -> None:
    log.info(
        "Scoped restore done. add=%d remove=%d succeeded.",
        mutations.additions.succeeded,
        mutations.removals.succeeded,
    )
    skipped = mutations.additions.skipped + mutations.removals.skipped
    if skipped:
        log.warning(
            "Scoped restore skipped %d vanished repo/user mutation(s); the next run will re-plan.",
            skipped,
        )


def _validate_restore_snapshot_context(
    client: src.SourcegraphClient,
    target_snapshot: permission_snapshot.Snapshot,
    snapshot_path: Path,
    bind_id_mode: str,
) -> None:
    """Warn when a full restore target differs from the current context."""
    log.info(
        "Received snapshot %s (captured_at=%s endpoint=%s bindID_mode=%s %d repo(s) %d grant(s)).",
        snapshot_path,
        target_snapshot["captured_at"],
        target_snapshot["endpoint"],
        target_snapshot["bindID_mode"],
        target_snapshot["stats"]["repos_with_explicit_grants"],
        target_snapshot["stats"]["total_grants"],
    )
    if target_snapshot["bindID_mode"] != bind_id_mode:
        log.warning(
            "Snapshot bindID_mode=%s differs from live bindID_mode=%s - "
            "captured bindIDs may not resolve to the same users. Proceeding "
            "anyway; review the plan diff carefully.",
            target_snapshot["bindID_mode"],
            bind_id_mode,
        )
    if target_snapshot["endpoint"] != client.endpoint:
        log.warning(
            "Snapshot endpoint=%s differs from live endpoint=%s - restoring "
            "across instances. Proceeding anyway; review the plan diff.",
            target_snapshot["endpoint"],
            client.endpoint,
        )


def _capture_restore_snapshot_state(
    client: src.SourcegraphClient,
    snapshot_path: Path,
    target_snapshot: permission_snapshot.Snapshot,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> RestoreSnapshotState:
    """Capture the live full-instance state needed to plan a restore."""
    expected_user_count = shared_sourcegraph.count_users(client)
    log.info(
        "Streaming %d users from %s and capturing current explicit-permissions "
        "state in parallel ...",
        expected_user_count,
        client.endpoint,
    )
    users: list[shared_types.User] = []
    current_snapshot = permission_snapshot.build_snapshot(
        client,
        shared_sourcegraph.list_users_streaming(
            client,
            collect_into=users,
            include_account_data=False,
        ),
        parallelism,
        bind_id_mode,
        snapshot_path,
        expected_user_count=expected_user_count,
        explicit_permissions_batch_size=explicit_permissions_batch_size,
        worker_pool=worker_pool,
    )
    log.info(
        "Received %d total users; current state: %d repo(s) with explicit "
        "grants, %d total grant(s).",
        len(users),
        current_snapshot["stats"]["repos_with_explicit_grants"],
        current_snapshot["stats"]["total_grants"],
    )
    return RestoreSnapshotState(
        target_snapshot=target_snapshot,
        current_snapshot=current_snapshot,
        users=permission_snapshot.compact_snapshot_users(users),
    )


def plan_full_restore(snapshot_state: RestoreSnapshotState) -> RestorePlan:
    """Build only the per-repo overwrite plans needed to match the snapshot.

    Each overwrite carries the target's real usernames PLUS the target's
    pending bindIDs for that repo: `setRepositoryPermissionsForUsers`
    replaces both kinds in one transaction, and unresolved bindIDs become
    pending rows again - restoring pending grants exactly as captured.
    """
    target_snapshot = snapshot_state.target_snapshot
    current_snapshot = snapshot_state.current_snapshot
    target_repos = target_snapshot["repos"]
    current_repos = current_snapshot["repos"]
    target_pending = permission_snapshot.pending_bind_ids_by_repository_id(
        target_snapshot["pending_users"]
    )
    current_pending = permission_snapshot.pending_bind_ids_by_repository_id(
        current_snapshot["pending_users"]
    )
    pending_repository_names = {
        **permission_snapshot.pending_repository_names_by_id(current_snapshot["pending_users"]),
        **permission_snapshot.pending_repository_names_by_id(target_snapshot["pending_users"]),
    }

    def repository_name(repo_id: str) -> str:
        for repos in (target_repos, current_repos):
            repo_snapshot = repos.get(repo_id)
            if repo_snapshot is not None:
                return repo_snapshot["name"]
        return pending_repository_names[repo_id]

    overwrites: list[permission_types.RepositoryUsernameOverwrite] = []
    skipped_repo_count = 0
    planned_repo_ids = (
        set(target_repos) | set(current_repos) | set(target_pending) | set(current_pending)
    )
    extra_repo_ids = planned_repo_ids - set(target_repos) - set(target_pending)
    for repo_id in sorted(planned_repo_ids, key=repository_name):
        target_repo = target_repos.get(repo_id)
        target_usernames = list(target_repo["users"]) if target_repo else []
        current_repo = current_repos.get(repo_id)
        current_usernames = current_repo["users"] if current_repo else []
        target_pending_bind_ids = target_pending.get(repo_id, [])
        usernames_match = (
            current_usernames == target_usernames or sorted(current_usernames) == target_usernames
        )
        if usernames_match and current_pending.get(repo_id, []) == target_pending_bind_ids:
            skipped_repo_count += 1
            continue
        pending_bind_ids = [
            bind_id for bind_id in target_pending_bind_ids if bind_id not in target_usernames
        ]
        overwrites.append(
            permission_types.RepositoryUsernameOverwrite(
                repository_id=repo_id,
                repository_name=repository_name(repo_id),
                usernames=tuple(target_usernames) + tuple(pending_bind_ids),
            )
        )
    return RestorePlan(
        overwrites=overwrites,
        snapshot_repo_count=len(set(target_repos) | set(target_pending)),
        extra_repo_count=len(extra_repo_ids),
        skipped_repo_count=skipped_repo_count,
    )


def _finish_empty_restore_plan(
    run_paths: backups.RunPaths,
    current_snapshot: permission_snapshot.Snapshot,
    dry_run: bool,
    do_backup: bool,
) -> None:
    """Handle a restore where live explicit grants already match the target."""
    log.info("Nothing to restore: current explicit-permissions state already matches snapshot.")
    if not (dry_run or do_backup):
        return
    if not run_paths.write_files:
        log.info("Skipping restore snapshot files because --no-files is set.")
        return

    before_restore_path, after_restore_path, diff_path = write_snapshot_pair(
        run_paths,
        current_snapshot,
        current_snapshot,
    )
    run_mode = "dry-run" if dry_run else "apply"
    log.info(
        "Wrote restore %s snapshots: before=%s after=%s diff=%s.",
        run_mode,
        before_restore_path,
        after_restore_path,
        diff_path,
    )


def _log_full_restore_plan(snapshot_state: RestoreSnapshotState, plan: RestorePlan) -> None:
    log.info(
        "Restore plan: %d mutation(s) (%d snapshot repo(s), %d unchanged skipped, "
        "%d extra repo(s) to wipe).",
        len(plan.overwrites),
        plan.snapshot_repo_count,
        plan.skipped_repo_count,
        plan.extra_repo_count,
    )
    log.info(
        "Diff (current -> snapshot):\n%s",
        permission_snapshot.render_snapshot_diff(
            snapshot_state.current_snapshot,
            snapshot_state.target_snapshot,
        ),
    )


def _finish_restore_dry_run(
    run_paths: backups.RunPaths,
    snapshot_state: RestoreSnapshotState,
) -> None:
    """Write dry-run restore artifacts and stop before mutation."""
    if run_paths.write_files:
        before_restore_path, after_restore_path, diff_path = write_snapshot_pair(
            run_paths,
            snapshot_state.current_snapshot,
            snapshot_state.target_snapshot,
        )
        log.info(
            "Wrote restore dry-run snapshots: before=%s after=%s diff=%s.",
            before_restore_path,
            after_restore_path,
            diff_path,
        )
    else:
        log.info("Skipping restore dry-run snapshot files because --no-files is set.")
    log.info("Dry run complete. Pass --apply to mutate state.")


def _write_restore_apply_before_snapshot(
    run_paths: backups.RunPaths,
    current_snapshot: permission_snapshot.Snapshot,
) -> None:
    """Persist the pre-restore state so the restore is reversible."""
    if not run_paths.write_files:
        log.info("Skipping pre-restore snapshot because --no-files is set.")
        return
    before_restore_path = run_paths.artifact_path("before")
    permission_snapshot.write_snapshot(before_restore_path, current_snapshot)
    log.info(
        "Wrote pre-restore snapshot: %s (%d repo(s) with explicit grants, %d total grant(s)).",
        before_restore_path,
        current_snapshot["stats"]["repos_with_explicit_grants"],
        current_snapshot["stats"]["total_grants"],
    )


def _apply_restore_overwrites(
    client: src.SourcegraphClient,
    overwrites: list[permission_types.RepositoryUsernameOverwrite],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    """Apply the full restore overwrite plans."""
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
        "Restore done. %d succeeded, %d skipped, %d failed, %d canceled.",
        mutations.succeeded,
        mutations.skipped,
        mutations.failed,
        mutations.canceled,
    )
    return mutations


def _record_restore_event_fields(
    command_event: dict[str, Any],
    snapshot_state: RestoreSnapshotState,
    plan: RestorePlan,
    mutations: shared_types.MutationCounts,
) -> None:
    command_event["plan_size"] = len(plan.overwrites)
    command_event["snapshot_repos"] = plan.snapshot_repo_count
    command_event["repos_short_circuited"] = plan.skipped_repo_count
    command_event["snapshot_grants"] = snapshot_state.target_snapshot["stats"]["total_grants"]
    command_event["mutations_succeeded"] = mutations.succeeded
    command_event["mutations_skipped"] = mutations.skipped
    command_event["mutations_failed"] = mutations.failed
    command_event["mutations_canceled"] = mutations.canceled


def _finish_restore_apply_with_backup(
    client: src.SourcegraphClient,
    snapshot_path: Path,
    run_paths: backups.RunPaths,
    snapshot_state: RestoreSnapshotState,
    parallelism: int,
    explicit_permissions_batch_size: int,
    bind_id_mode: str,
    worker_pool: ThreadPoolExecutor | None = None,
) -> None:
    """Capture post-restore state, write artifacts, and validate residual diff."""
    log.info("Capturing post-restore snapshot for %d users ...", len(snapshot_state.users))
    after_restore_snapshot = permission_snapshot.build_snapshot(
        client,
        snapshot_state.users,
        parallelism,
        bind_id_mode,
        snapshot_path,
        expected_user_count=len(snapshot_state.users),
        explicit_permissions_batch_size=explicit_permissions_batch_size,
        worker_pool=worker_pool,
    )
    if run_paths.write_files:
        after_restore_path = run_paths.artifact_path("after")
        permission_snapshot.write_snapshot(after_restore_path, after_restore_snapshot)
        diff_path = write_snapshot_diff_file(
            run_paths,
            snapshot_state.current_snapshot,
            after_restore_snapshot,
        )
        log.info(
            "Wrote post-restore snapshot: %s diff=%s "
            "(%d repo(s) with explicit grants, %d total grant(s)).",
            after_restore_path,
            diff_path,
            after_restore_snapshot["stats"]["repos_with_explicit_grants"],
            after_restore_snapshot["stats"]["total_grants"],
        )
    else:
        log.info("Skipping post-restore snapshot files because --no-files is set.")
    residual = permission_snapshot.render_snapshot_diff(
        after_restore_snapshot,
        snapshot_state.target_snapshot,
    )
    if residual != "No changes.":
        log.warning(
            "VALIDATION: post-restore state does NOT match the target "
            "snapshot exactly. Residual diff (post-restore -> snapshot):\n%s",
            residual,
        )
    else:
        log.info("VALIDATION OK: post-restore state matches the snapshot exactly.")


def _raise_for_failed_restore(mutations: shared_types.MutationCounts, overwrite_count: int) -> None:
    if not (mutations.failed or mutations.canceled):
        return
    log.error(
        "RESTORE FAILED: %d mutation(s) failed, %d canceled by "
        "circuit breaker (out of %d planned). Review the log file "
        "and the pre-/post-restore snapshots for details.",
        mutations.failed,
        mutations.canceled,
        overwrite_count,
    )
    raise SystemExit(1)


def cmd_restore(
    client: src.SourcegraphClient,
    snapshot_path: Path,
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
    target_snapshot = permission_snapshot.read_snapshot_file(snapshot_path)
    if target_snapshot.get("snapshot_kind") == permission_snapshot.USER_SCOPED_SNAPSHOT_KIND:
        cmd_restore_user_scoped(
            client,
            snapshot_path,
            run_paths,
            dry_run=dry_run,
            parallelism=parallelism,
            bind_id_mode=bind_id_mode,
            do_backup=do_backup,
            target_snapshot=cast(permission_snapshot.UserScopedSnapshot, target_snapshot),
            worker_pool=worker_pool,
        )
        return
    target_full_snapshot = cast(permission_snapshot.Snapshot, target_snapshot)

    with src.span(
        "cmd_restore",
        snapshot_path=str(snapshot_path),
        dry_run=dry_run,
        parallelism=parallelism,
        do_backup=do_backup,
    ) as command_event:
        _validate_restore_snapshot_context(
            client,
            target_full_snapshot,
            snapshot_path,
            bind_id_mode,
        )
        snapshot_state = _capture_restore_snapshot_state(
            client,
            snapshot_path,
            target_full_snapshot,
            parallelism,
            explicit_permissions_batch_size,
            bind_id_mode,
            worker_pool,
        )
        plan = plan_full_restore(snapshot_state)
        if not plan.overwrites:
            _finish_empty_restore_plan(
                run_paths,
                snapshot_state.current_snapshot,
                dry_run,
                do_backup,
            )
            return

        _log_full_restore_plan(snapshot_state, plan)
        if dry_run:
            _finish_restore_dry_run(run_paths, snapshot_state)
            return

        if do_backup:
            _write_restore_apply_before_snapshot(
                run_paths,
                snapshot_state.current_snapshot,
            )

        mutations = _apply_restore_overwrites(client, plan.overwrites, parallelism, worker_pool)
        _record_restore_event_fields(command_event, snapshot_state, plan, mutations)

        if do_backup:
            _finish_restore_apply_with_backup(
                client,
                snapshot_path,
                run_paths,
                snapshot_state,
                parallelism,
                explicit_permissions_batch_size,
                bind_id_mode,
                worker_pool,
            )

        _raise_for_failed_restore(mutations, len(plan.overwrites))
