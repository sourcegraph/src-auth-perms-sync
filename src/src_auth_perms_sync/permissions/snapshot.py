"""Repo-permission snapshots: capture / diff / file I/O."""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TextIO, TypeAlias, TypedDict, cast

import src_py_lib as src

from ..shared import run_context
from ..shared import types as shared_types
from . import sourcegraph as permissions_sourcegraph
from . import types as permission_types

log = logging.getLogger(__name__)


class RepoSnapshot(TypedDict):
    name: str
    explicit_permissions_users: list[str]


class SnapshotStats(TypedDict):
    total_users_scanned: int
    users_with_explicit_grants: int
    repos_with_explicit_grants: int
    total_grants: int


class Snapshot(TypedDict):
    schema_version: int
    captured_at: str
    endpoint: str
    bindID_mode: str  # "USERNAME" or "EMAIL", from the GraphQL enum
    config_file: str | None  # absolute path of the YAML, if known
    config_sha256: str | None  # sha256 of the YAML at capture time
    pending_bindIDs: list[str]
    stats: SnapshotStats
    repos: dict[str, RepoSnapshot]


class SnapshotUser(TypedDict):
    id: str
    username: str


SnapshotUserInput: TypeAlias = shared_types.User | SnapshotUser


def compact_snapshot_users(users: Iterable[shared_types.User]) -> list[SnapshotUser]:
    """Keep only the user fields needed for later snapshot capture."""
    return [{"id": user["id"], "username": user["username"]} for user in users]


class UserScopedUserSnapshot(TypedDict):
    id: str
    explicit_repositories: list[permission_types.Repository]


class UserScopedSnapshotStats(TypedDict):
    total_users_scanned: int
    users_with_explicit_grants: int
    total_grants: int


class UserScopedSnapshot(TypedDict):
    schema_version: int
    snapshot_kind: Literal["user_scope"]
    captured_at: str
    endpoint: str
    bindID_mode: str
    config_file: str | None
    config_sha256: str | None
    stats: UserScopedSnapshotStats
    users: dict[str, UserScopedUserSnapshot]


class SnapshotDiffSide(TypedDict):
    captured_at: str
    endpoint: str
    bindID_mode: str
    config_file: str | None
    config_sha256: str | None


class SnapshotDiffPendingBindIDs(TypedDict):
    added: list[str]
    removed: list[str]


class SnapshotDiffSummary(TypedDict):
    repos_changed: int
    grants_added: int
    grants_removed: int
    pending_bindIDs_added: int
    pending_bindIDs_removed: int


class RepositoryPermissionDiffEntry(TypedDict):
    id: int
    name: str
    before_count: int
    after_count: int
    added: list[str]
    removed: list[str]


class SnapshotDiff(TypedDict):
    schema_version: int
    diff_kind: Literal["repo_permissions"]
    before: SnapshotDiffSide
    after: SnapshotDiffSide
    summary: SnapshotDiffSummary
    pending_bindIDs: SnapshotDiffPendingBindIDs
    repos: list[RepositoryPermissionDiffEntry]


class SnapshotDiffRepository(TypedDict):
    id: int
    name: str


class UserScopedSnapshotDiffSummary(TypedDict):
    users_changed: int
    grants_added: int
    grants_removed: int


class UserScopedSnapshotDiffEntry(TypedDict):
    username: str
    id: str
    before_count: int
    after_count: int
    added_repositories: list[SnapshotDiffRepository]
    removed_repositories: list[SnapshotDiffRepository]


class UserScopedSnapshotDiff(TypedDict):
    schema_version: int
    diff_kind: Literal["user_scoped_permissions"]
    before: SnapshotDiffSide
    after: SnapshotDiffSide
    summary: UserScopedSnapshotDiffSummary
    users: list[UserScopedSnapshotDiffEntry]


SNAPSHOT_SCHEMA_VERSION: int = 3
USER_SCOPED_SNAPSHOT_KIND = "user_scope"
SNAPSHOT_DIFF_SCHEMA_VERSION: int = 1


def capture_explicit_grants(
    client: src.SourcegraphClient,
    users: Iterable[SnapshotUserInput],
    parallelism: int,
    explicit_permissions_batch_size: int,
    total_users: int | None = None,
    worker_pool: ThreadPoolExecutor | None = None,
) -> tuple[dict[str, RepoSnapshot], int]:
    """Build the per-repo inverse index of explicit-API grants.

    Fetches `user.permissionsInfo.repositories(source: API)` for batches of
    users in parallel via a thread pool, then inverts to `repo_id → RepoSnapshot`.

    Accepts any `Iterable[User]` — including a streaming generator from
    `list_users_streaming`. When passed a streaming source, this function
    submits batched UserExplicitRepos calls **while** iterating, so the
    submission loop blocking on the next ListUsers page overlaps with
    workers consuming previously-submitted UserExplicitRepos batches. At
    scale this overlaps the entire ListUsers pagination time with capture
    work, removing it from the critical path.

    `total_users`, when supplied, enables percentage + ETA in the
    progress log lines. Callers that have already paid for `count_users()`
    (e.g. `cmd_set` / `cmd_restore` in their --apply branches) should pass
    it through; otherwise progress reports just show running counts and
    rate. Reports fire at every ~10% of `total_users` (or every 1000
    completed when total is unknown).

    Sourcegraph only supports READ repository permissions, so snapshots
    store only the usernames that have explicit repository grants.

    Returns `(repos, user_count)` so callers (e.g. `build_snapshot`)
    that need the user-count statistic don't have to materialize the
    iterator twice or measure it themselves.
    """
    # Invert directly as each per-user fetch completes. Store only repo IDs
    # first, then hydrate each unique repo name once after all users complete.
    usernames_by_repository_id: dict[str, list[str]] = {}

    def _fetch(
        batch_users: list[SnapshotUserInput],
    ) -> tuple[dict[str, list[str]], int]:
        # High-frequency (one per user-batch):
        #   - log the whole event (start + end) at DEBUG; failures still
        #     get bumped to ERROR by the event() helper
        #   - drop the per-event `status="ok"` / `error_type=null` noise on
        #     successes (failures still carry both fields)
        #   - omit user IDs since usernames are far more readable
        with src.event(
            "user_explicit_repos_batch_fetch",
            level="DEBUG",
            omit_success_status=True,
            user_count=len(batch_users),
        ) as fetch_event:
            try:
                repository_ids_by_user_id = permissions_sourcegraph.list_users_explicit_repo_ids(
                    client,
                    [user["id"] for user in batch_users],
                    batch_size=explicit_permissions_batch_size,
                )
                failures = 0
            except Exception as exception:
                log.warning(
                    "Failed to batch-fetch explicit grants for %d user(s): %s. "
                    "Falling back to one query per user.",
                    len(batch_users),
                    exception,
                )
                repository_ids_by_user_id, failures = _fetch_one_user_at_a_time(batch_users)
            repository_ids_by_username = {
                user["username"]: repository_ids_by_user_id.get(user["id"], [])
                for user in batch_users
            }
            fetch_event["repo_count"] = sum(
                len(repository_ids) for repository_ids in repository_ids_by_username.values()
            )
            fetch_event["per_user_failures"] = failures
            return repository_ids_by_username, failures

    def _fetch_one_user_at_a_time(
        batch_users: list[SnapshotUserInput],
    ) -> tuple[dict[str, list[str]], int]:
        repository_ids_by_user_id: dict[str, list[str]] = {}
        failures = 0
        for user in batch_users:
            try:
                repository_ids_by_user_id[user["id"]] = (
                    permissions_sourcegraph.list_user_explicit_repo_ids(
                        client,
                        user["id"],
                    )
                )
            except Exception as exception:
                failures += 1
                log.warning(
                    "Failed to fetch explicit grants for user=%s: %s",
                    user["username"],
                    exception,
                )
                repository_ids_by_user_id[user["id"]] = []
        return repository_ids_by_user_id, failures

    with src.event(
        "capture_explicit_grants",
        total_users=total_users,
        explicit_permissions_batch_size=explicit_permissions_batch_size,
    ) as capture_event:
        capture_failures = 0
        futures: dict[Any, list[SnapshotUserInput]] = {}
        submitted_user_count = 0
        max_pending_batches = max(1, parallelism * 2)

        def _submit_batch(
            executor: ThreadPoolExecutor,
            batch_users: list[SnapshotUserInput],
        ) -> None:
            nonlocal submitted_user_count
            if not batch_users:
                return
            submitted_batch = list(batch_users)
            submitted_user_count += len(submitted_batch)
            future = src.submit_with_log_context(executor, _fetch, submitted_batch)
            futures[future] = submitted_batch

        # Progress reporting: every 10% when total is known (max 10
        # lines), every 1000 otherwise. Avoids drowning the operator on
        # tiny instances and gives steady feedback on large ones.
        progress_step = max(1, total_users // 10) if total_users else 1000
        # Start the timer BEFORE submission. The submit-while-iterating
        # loop blocks on ListUsers pagination, but workers process
        # already-submitted tasks during those blocks — so by the time
        # the submit loop finishes, many futures may already be done.
        # Anchoring `progress_started` here means the first progress
        # line shows real wall-clock work time, not zero.
        progress_started = time.perf_counter()
        completed = 0
        next_progress_report = progress_step
        all_users_submitted = False

        def _record_completed_futures(done_futures: Iterable[Any]) -> None:
            nonlocal capture_failures, completed, next_progress_report
            for future in done_futures:
                submitted_batch = futures.pop(future)
                completed += len(submitted_batch)
                try:
                    repository_ids_by_username, failures = future.result()
                    capture_failures += failures
                    for username, repository_ids in repository_ids_by_username.items():
                        for repository_id in repository_ids:
                            usernames_by_repository_id.setdefault(
                                repository_id,
                                [],
                            ).append(username)
                except Exception as exception:
                    # Don't blow up the whole capture; warn so the operator
                    # can see the users whose grants were treated as empty.
                    capture_failures += len(submitted_batch)
                    log.warning(
                        "Failed to fetch explicit grants for %d user(s): %s",
                        len(submitted_batch),
                        exception,
                    )

                if completed >= next_progress_report or (
                    all_users_submitted and completed == submitted_user_count
                ):
                    elapsed = time.perf_counter() - progress_started
                    rate = completed / elapsed if elapsed > 0 else 0.0
                    if total_users:
                        remaining = max(total_users - completed, 0)
                        eta_seconds = remaining / rate if rate > 0 else 0.0
                        log.info(
                            "Captured explicit permissions for %d / %d users (%.0f%%) "
                            "in %.0fs (%.0f users/sec, ETA %.0fs).",
                            completed,
                            total_users,
                            100.0 * completed / total_users,
                            elapsed,
                            rate,
                            eta_seconds,
                        )
                    else:
                        log.info(
                            "Captured explicit permissions for %d users in %.0fs (%.0f users/sec).",
                            completed,
                            elapsed,
                            rate,
                        )
                    while next_progress_report <= completed:
                        next_progress_report += progress_step

        # Submit-while-iterating. Iterating `users` may block on each
        # ListUsers page when a streaming iterator is passed; during those
        # blocks, workers continue processing already-submitted tasks.
        with run_context.thread_pool(parallelism, worker_pool) as executor:
            batch_users: list[SnapshotUserInput] = []
            for user in users:
                batch_users.append(user)
                if len(batch_users) >= explicit_permissions_batch_size:
                    _submit_batch(executor, batch_users)
                    batch_users = []
                    if len(futures) >= max_pending_batches:
                        done_futures, _ = wait(futures, return_when=FIRST_COMPLETED)
                        _record_completed_futures(done_futures)
            _submit_batch(executor, batch_users)
            all_users_submitted = True

            while futures:
                done_futures, _ = wait(futures, return_when=FIRST_COMPLETED)
                _record_completed_futures(done_futures)
        capture_event["user_count"] = submitted_user_count
        capture_event["per_user_failures"] = capture_failures
        capture_event["max_pending_batches"] = max_pending_batches

    # Stable sort: users alphabetical within each repo.
    for usernames in usernames_by_repository_id.values():
        usernames.sort()

    with src.event(
        "hydrate_explicit_repository_names",
        repository_count=len(usernames_by_repository_id),
    ) as hydrate_event:
        repositories_by_id = permissions_sourcegraph.list_repositories_by_ids(
            client,
            usernames_by_repository_id.keys(),
        )
        hydrate_event["hydrated_repository_count"] = len(repositories_by_id)

    repos_out: dict[str, RepoSnapshot] = {}
    for repository_id, usernames in usernames_by_repository_id.items():
        repos_out[repository_id] = {
            "name": _snapshot_repository_name(repositories_by_id, repository_id),
            "explicit_permissions_users": usernames,
        }

    return repos_out, submitted_user_count


def _snapshot_repository_name(
    repositories_by_id: dict[str, permission_types.Repository],
    repository_id: str,
) -> str:
    repository = repositories_by_id.get(repository_id)
    if repository is not None:
        return repository["name"]
    try:
        decoded_repository_id = src.decode_repository_id(repository_id)
        return f"<repository id={decoded_repository_id}>"
    except ValueError:
        return f"<repository id={repository_id}>"


def build_snapshot(
    client: src.SourcegraphClient,
    users: Iterable[SnapshotUserInput],
    parallelism: int,
    bind_id_mode: str,
    config_path: Path | None = None,
    *,
    total_users: int | None = None,
    explicit_permissions_batch_size: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> Snapshot:
    """Capture a full Snapshot: explicit grants + pending-bindIDs + metadata.

    `users` may be a streaming iterator (see `list_users_streaming`); this
    function delegates iteration to `capture_explicit_grants` which submits
    batched work as the iterator yields, so ListUsers pagination overlaps
    with UserExplicitRepos work.

    `total_users`, when known, drives percentage + ETA in the per-batch
    progress log lines emitted by `capture_explicit_grants`.
    """
    with src.event("build_snapshot", bind_id_mode=bind_id_mode) as build_event:
        repos, user_count = capture_explicit_grants(
            client,
            users,
            parallelism,
            explicit_permissions_batch_size,
            total_users=total_users,
            worker_pool=worker_pool,
        )
        pending = permissions_sourcegraph.list_pending_bind_ids(client)

        config_sha: str | None = None
        if config_path is not None and config_path.exists():
            config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest()

        distinct_users: set[str] = set()
        total_grants = 0
        for repo in repos.values():
            for username in repo["explicit_permissions_users"]:
                distinct_users.add(username)
                total_grants += 1
        build_event["user_count"] = user_count
        build_event["repos_with_explicit_grants"] = len(repos)
        build_event["users_with_explicit_grants"] = len(distinct_users)
        build_event["total_grants"] = total_grants
        build_event["pending_bindIDs_count"] = len(pending)

        return {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "captured_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
            "endpoint": client.endpoint,
            "bindID_mode": bind_id_mode,
            "config_file": str(config_path.resolve()) if config_path else None,
            "config_sha256": config_sha,
            "pending_bindIDs": sorted(pending),
            "stats": {
                "total_users_scanned": user_count,
                "users_with_explicit_grants": len(distinct_users),
                "repos_with_explicit_grants": len(repos),
                "total_grants": total_grants,
            },
            "repos": dict(sorted(repos.items())),  # sort by repo_id for stable file
        }


def capture_user_scoped_explicit_grants(
    client: src.SourcegraphClient,
    users: Iterable[SnapshotUser],
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> dict[str, UserScopedUserSnapshot]:
    """Capture explicit API grants for only the supplied users."""
    scoped_users: dict[str, UserScopedUserSnapshot] = {}

    def _fetch(user: SnapshotUser) -> tuple[SnapshotUser, list[permission_types.Repository]]:
        with src.event(
            "user_scoped_explicit_repos_fetch",
            level="DEBUG",
            omit_success_status=True,
            username=user["username"],
        ) as fetch_event:
            repos = permissions_sourcegraph.list_user_explicit_repos(client, user["id"])
            fetch_event["repo_count"] = len(repos)
            return user, repos

    with src.event("capture_user_scoped_explicit_grants") as capture_event:
        futures: dict[Any, SnapshotUser] = {}
        with run_context.thread_pool(parallelism, worker_pool) as executor:
            for user in users:
                futures[src.submit_with_log_context(executor, _fetch, user)] = user
            for future in as_completed(futures):
                user = futures[future]
                fetched_user: SnapshotUser
                repos: list[permission_types.Repository]
                try:
                    fetched_user, repos = future.result()
                except Exception as exception:
                    log.warning(
                        "Failed to fetch scoped explicit grants for user=%s: %s",
                        user["username"],
                        exception,
                    )
                    fetched_user, repos = user, []
                scoped_users[fetched_user["username"]] = {
                    "id": fetched_user["id"],
                    "explicit_repositories": sorted(repos, key=lambda repo: repo["name"]),
                }
        capture_event["user_count"] = len(scoped_users)
        capture_event["total_grants"] = sum(
            len(user_snapshot["explicit_repositories"]) for user_snapshot in scoped_users.values()
        )
    return dict(sorted(scoped_users.items()))


def build_user_scoped_snapshot(
    client: src.SourcegraphClient,
    users: Iterable[SnapshotUser],
    parallelism: int,
    bind_id_mode: str,
    config_path: Path | None = None,
    worker_pool: ThreadPoolExecutor | None = None,
) -> UserScopedSnapshot:
    """Capture a reversible snapshot for only the supplied users."""
    with src.event("build_user_scoped_snapshot", bind_id_mode=bind_id_mode) as build_event:
        scoped_users = capture_user_scoped_explicit_grants(
            client,
            users,
            parallelism,
            worker_pool=worker_pool,
        )
        config_sha: str | None = None
        if config_path is not None and config_path.exists():
            config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest()

        total_grants = sum(
            len(user_snapshot["explicit_repositories"]) for user_snapshot in scoped_users.values()
        )
        users_with_explicit_grants = sum(
            1 for user_snapshot in scoped_users.values() if user_snapshot["explicit_repositories"]
        )
        build_event["user_count"] = len(scoped_users)
        build_event["users_with_explicit_grants"] = users_with_explicit_grants
        build_event["total_grants"] = total_grants

        return {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "snapshot_kind": USER_SCOPED_SNAPSHOT_KIND,
            "captured_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
            "endpoint": client.endpoint,
            "bindID_mode": bind_id_mode,
            "config_file": str(config_path.resolve()) if config_path else None,
            "config_sha256": config_sha,
            "stats": {
                "total_users_scanned": len(scoped_users),
                "users_with_explicit_grants": users_with_explicit_grants,
                "total_grants": total_grants,
            },
            "users": scoped_users,
        }


def _write_pretty_json(path: Path, value: Any) -> int:
    """Write pretty JSON without materializing the encoded string first."""
    with path.open("w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=False)
        output.write("\n")
    return path.stat().st_size


def _write_top_level_json_field(
    output: TextIO,
    name: str,
    value: object,
    *,
    first: bool,
) -> None:
    if not first:
        output.write(",\n")
    output.write(f"  {json.dumps(name)}: ")
    output.write(json.dumps(value, indent=2).replace("\n", "\n  "))


def _write_string_list(output: TextIO, values: Sequence[str], indent: int) -> None:
    if not values:
        output.write("[]")
        return
    output.write("[\n")
    value_indent = " " * (indent + 2)
    for index, value in enumerate(values):
        if index:
            output.write(",\n")
        output.write(value_indent)
        json.dump(value, output)
    output.write("\n" + " " * indent + "]")


def _write_repo_snapshot_value(output: TextIO, repo: RepoSnapshot, indent: int) -> None:
    field_indent = " " * (indent + 2)
    output.write("{\n")
    output.write(f'{field_indent}"name": ')
    json.dump(repo["name"], output)
    output.write(",\n")
    output.write(f'{field_indent}"explicit_permissions_users": ')
    _write_string_list(output, repo["explicit_permissions_users"], indent + 2)
    output.write("\n" + " " * indent + "}")


def _write_repository_value(output: TextIO, repository: permission_types.Repository) -> None:
    output.write("{")
    output.write('"id": ')
    json.dump(src.decode_repository_id(repository["id"]), output)
    output.write(', "name": ')
    json.dump(repository["name"], output)
    output.write("}")


def _write_repository_list(
    output: TextIO,
    repositories: Sequence[permission_types.Repository],
    indent: int,
) -> None:
    if not repositories:
        output.write("[]")
        return
    output.write("[\n")
    value_indent = " " * (indent + 2)
    for index, repository in enumerate(repositories):
        if index:
            output.write(",\n")
        output.write(value_indent)
        _write_repository_value(output, repository)
    output.write("\n" + " " * indent + "]")


def _write_user_scoped_snapshot_value(
    output: TextIO,
    user_snapshot: UserScopedUserSnapshot,
    indent: int,
) -> None:
    field_indent = " " * (indent + 2)
    output.write("{\n")
    output.write(f'{field_indent}"id": ')
    json.dump(user_snapshot["id"], output)
    output.write(",\n")
    output.write(f'{field_indent}"explicit_repositories": ')
    _write_repository_list(output, user_snapshot["explicit_repositories"], indent + 2)
    output.write("\n" + " " * indent + "}")


def _write_snapshot_json(
    path: Path,
    snapshot: Snapshot,
    repos: Iterable[tuple[str, RepoSnapshot]],
) -> int:
    """Write a full snapshot without duplicating the repo map for ID decoding."""
    with path.open("w", encoding="utf-8") as output:
        output.write("{\n")
        first = True
        fields: tuple[tuple[str, object], ...] = (
            ("schema_version", snapshot["schema_version"]),
            ("captured_at", snapshot["captured_at"]),
            ("endpoint", snapshot["endpoint"]),
            ("bindID_mode", snapshot["bindID_mode"]),
            ("config_file", snapshot["config_file"]),
            ("config_sha256", snapshot["config_sha256"]),
            ("pending_bindIDs", snapshot["pending_bindIDs"]),
            ("stats", snapshot["stats"]),
        )
        for field_name, value in fields:
            _write_top_level_json_field(
                output,
                field_name,
                value,
                first=first,
            )
            first = False

        output.write(',\n  "repos": {')
        wrote_repo = False
        for repo_id, repo in repos:
            if wrote_repo:
                output.write(",")
            output.write("\n    ")
            json.dump(str(src.decode_repository_id(repo_id)), output)
            output.write(": ")
            _write_repo_snapshot_value(output, repo, 4)
            wrote_repo = True
        if wrote_repo:
            output.write("\n  }")
        else:
            output.write("}")
        output.write("\n}\n")
    return path.stat().st_size


def write_snapshot_with_repos(
    path: Path,
    snapshot: Snapshot,
    repos: Iterable[tuple[str, RepoSnapshot]],
) -> None:
    """Persist a full snapshot from an iterable of repo entries."""
    with src.event(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="snapshot",
    ) as disk_event:
        path.parent.mkdir(parents=True, exist_ok=True)
        disk_event["bytes"] = _write_snapshot_json(path, snapshot, repos)


def write_snapshot(path: Path, snapshot: Snapshot) -> None:
    """Persist a snapshot to disk as pretty-printed JSON with stable ordering.

    Repo IDs are decoded from their opaque GraphQL Node form
    (`Repository:<int>` base64) to plain integer DB primary keys before
    write — they're far easier to grep, diff, and read by eye.
    `read_snapshot` re-encodes them on load so the in-memory shape (and
    every consumer of `Snapshot`) keeps using opaque IDs unchanged.
    """
    write_snapshot_with_repos(path, snapshot, snapshot["repos"].items())


def write_user_scoped_snapshot(path: Path, snapshot: UserScopedSnapshot) -> None:
    """Persist a user-scoped snapshot with readable repository IDs."""
    with src.event(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="user_scoped_snapshot",
    ) as disk_event:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as output:
            output.write("{\n")
            first = True
            fields: tuple[tuple[str, object], ...] = (
                ("schema_version", snapshot["schema_version"]),
                ("snapshot_kind", snapshot["snapshot_kind"]),
                ("captured_at", snapshot["captured_at"]),
                ("endpoint", snapshot["endpoint"]),
                ("bindID_mode", snapshot["bindID_mode"]),
                ("config_file", snapshot["config_file"]),
                ("config_sha256", snapshot["config_sha256"]),
                ("stats", snapshot["stats"]),
            )
            for field_name, value in fields:
                _write_top_level_json_field(
                    output,
                    field_name,
                    value,
                    first=first,
                )
                first = False

            output.write(',\n  "users": {')
            wrote_user = False
            for username, user_snapshot in snapshot["users"].items():
                if wrote_user:
                    output.write(",")
                output.write("\n    ")
                json.dump(username, output)
                output.write(": ")
                _write_user_scoped_snapshot_value(output, user_snapshot, 4)
                wrote_user = True
            if wrote_user:
                output.write("\n  }")
            else:
                output.write("}")
            output.write("\n}\n")
        disk_event["bytes"] = path.stat().st_size


def _read_snapshot_raw(path: Path, file_kind: str) -> dict[str, Any]:
    with src.event(
        "disk_io",
        level="DEBUG",
        op="read",
        path=str(path),
        file_kind=file_kind,
    ) as disk_event:
        disk_event["bytes"] = path.stat().st_size
        with path.open(encoding="utf-8") as snapshot_file:
            return cast(dict[str, Any], json.load(snapshot_file))


def _validate_snapshot_schema_version(path: Path, version: object) -> None:
    """Validate snapshot schema version."""
    if version == SNAPSHOT_SCHEMA_VERSION:
        return
    raise SystemExit(
        f"{path}: snapshot schema_version is {version!r}, "
        f"expected {SNAPSHOT_SCHEMA_VERSION}. Refusing to load."
    )


def _encode_full_snapshot_raw(path: Path, raw: dict[str, Any]) -> Snapshot:
    _validate_snapshot_schema_version(path, raw.get("schema_version"))
    if raw.get("snapshot_kind") == USER_SCOPED_SNAPSHOT_KIND:
        raise SystemExit(f"{path}: snapshot_kind is 'user_scope', expected full repo snapshot.")
    on_disk_repos = cast(dict[str, RepoSnapshot], raw.get("repos", {}))
    raw["repos"] = {
        src.encode_repository_id(int(repo_id)): repo for repo_id, repo in on_disk_repos.items()
    }
    return cast(Snapshot, raw)


def _encode_user_scoped_snapshot_raw(path: Path, raw: dict[str, Any]) -> UserScopedSnapshot:
    _validate_snapshot_schema_version(path, raw.get("schema_version"))
    kind = raw.get("snapshot_kind")
    if kind != USER_SCOPED_SNAPSHOT_KIND:
        raise SystemExit(f"{path}: snapshot_kind is {kind!r}, expected 'user_scope'.")

    on_disk_users = cast(dict[str, dict[str, Any]], raw.get("users", {}))
    raw["users"] = {
        username: {
            "id": user_snapshot["id"],
            "explicit_repositories": [
                {
                    "id": src.encode_repository_id(int(repo["id"])),
                    "name": cast(str, repo["name"]),
                }
                for repo in cast(list[dict[str, Any]], user_snapshot["explicit_repositories"])
            ],
        }
        for username, user_snapshot in on_disk_users.items()
    }
    return cast(UserScopedSnapshot, raw)


def read_snapshot_file(path: Path) -> Snapshot | UserScopedSnapshot:
    """Load either supported snapshot kind from disk with one JSON parse."""
    raw = _read_snapshot_raw(path, "snapshot")
    if raw.get("snapshot_kind") == USER_SCOPED_SNAPSHOT_KIND:
        return _encode_user_scoped_snapshot_raw(path, raw)
    return _encode_full_snapshot_raw(path, raw)


def read_snapshot(path: Path) -> Snapshot:
    """Load a snapshot from disk. Validates schema_version.

    Re-encodes integer repo IDs from disk back to opaque GraphQL Node
    IDs (`Repository:<int>` base64) so callers see the same shape that
    `build_snapshot` produces in memory.
    """
    return _encode_full_snapshot_raw(path, _read_snapshot_raw(path, "snapshot"))


def read_user_scoped_snapshot(path: Path) -> UserScopedSnapshot:
    """Load a user-scoped snapshot and re-encode repository IDs."""
    return _encode_user_scoped_snapshot_raw(
        path,
        _read_snapshot_raw(path, "user_scoped_snapshot"),
    )


class RepoDiff(TypedDict):
    name: str
    added: list[str]
    removed: list[str]


@dataclass(frozen=True)
class _SnapshotDiffPlan:
    changed_repo_ids: list[str]
    grants_added: int
    grants_removed: int
    pending_added: list[str]
    pending_removed: list[str]


def _sorted_usernames(values: Sequence[str]) -> Sequence[str]:
    if all(values[index - 1] <= values[index] for index in range(1, len(values))):
        return values
    return sorted(values)


def _repo_usernames(repo: RepoSnapshot | None) -> Sequence[str]:
    if repo is None:
        return ()
    return repo["explicit_permissions_users"]


def _sorted_username_diff_counts(
    before_usernames: Sequence[str],
    after_usernames: Sequence[str],
) -> tuple[int, int]:
    if before_usernames == after_usernames:
        return 0, 0
    before_sorted = _sorted_usernames(before_usernames)
    after_sorted = _sorted_usernames(after_usernames)
    before_index = 0
    after_index = 0
    added = 0
    removed = 0
    while before_index < len(before_sorted) and after_index < len(after_sorted):
        before_username = before_sorted[before_index]
        after_username = after_sorted[after_index]
        if before_username == after_username:
            before_index += 1
            after_index += 1
        elif before_username < after_username:
            removed += 1
            before_index += 1
        else:
            added += 1
            after_index += 1
    removed += len(before_sorted) - before_index
    added += len(after_sorted) - after_index
    return added, removed


def _sorted_username_diff_values(
    before_usernames: Sequence[str],
    after_usernames: Sequence[str],
) -> tuple[list[str], list[str]]:
    if before_usernames == after_usernames:
        return [], []
    before_sorted = _sorted_usernames(before_usernames)
    after_sorted = _sorted_usernames(after_usernames)
    before_index = 0
    after_index = 0
    added: list[str] = []
    removed: list[str] = []
    while before_index < len(before_sorted) and after_index < len(after_sorted):
        before_username = before_sorted[before_index]
        after_username = after_sorted[after_index]
        if before_username == after_username:
            before_index += 1
            after_index += 1
        elif before_username < after_username:
            removed.append(before_username)
            before_index += 1
        else:
            added.append(after_username)
            after_index += 1
    removed.extend(before_sorted[before_index:])
    added.extend(after_sorted[after_index:])
    return added, removed


def diff_snapshots(
    before: dict[str, RepoSnapshot],
    after: dict[str, RepoSnapshot],
) -> dict[str, RepoDiff]:
    """Compute per-repo {added, removed} bindID lists.

    Repos present in only one side appear with the appropriate users
    in `added` (after-only) or `removed` (before-only). Repos with
    identical user lists on both sides are omitted entirely from the result.
    """
    diff: dict[str, RepoDiff] = {}
    for repo_id in set(before) | set(after):
        before_entry = before.get(repo_id)
        after_entry = after.get(repo_id)
        added, removed = _sorted_username_diff_values(
            _repo_usernames(before_entry),
            _repo_usernames(after_entry),
        )
        if not added and not removed:
            continue
        # prefer post-state name
        name = (after_entry or before_entry or {"name": "<unknown>"})["name"]
        diff[repo_id] = {
            "name": name,
            "added": added,
            "removed": removed,
        }
    return diff


def _snapshot_diff_repo_name(
    before: Snapshot,
    after_repo_for_id: Callable[[str], RepoSnapshot | None],
    repo_id: str,
) -> str:
    after_repo = after_repo_for_id(repo_id)
    before_repo = before["repos"].get(repo_id)
    return (after_repo or before_repo or {"name": "<unknown>"})["name"]


def _plan_snapshot_diff(
    before: Snapshot,
    after: Snapshot,
    repo_ids: Iterable[str],
    after_repo_for_id: Callable[[str], RepoSnapshot | None],
) -> _SnapshotDiffPlan:
    changed_repo_ids: list[str] = []
    grants_added = 0
    grants_removed = 0
    for repo_id in repo_ids:
        before_repo = before["repos"].get(repo_id)
        after_repo = after_repo_for_id(repo_id)
        added_count, removed_count = _sorted_username_diff_counts(
            _repo_usernames(before_repo),
            _repo_usernames(after_repo),
        )
        if not added_count and not removed_count:
            continue
        changed_repo_ids.append(repo_id)
        grants_added += added_count
        grants_removed += removed_count

    changed_repo_ids.sort(
        key=lambda repo_id: _snapshot_diff_repo_name(before, after_repo_for_id, repo_id)
    )
    before_pending = set(before["pending_bindIDs"])
    after_pending = set(after["pending_bindIDs"])
    return _SnapshotDiffPlan(
        changed_repo_ids=changed_repo_ids,
        grants_added=grants_added,
        grants_removed=grants_removed,
        pending_added=sorted(after_pending - before_pending),
        pending_removed=sorted(before_pending - after_pending),
    )


def _snapshot_diff_entry(
    before: Snapshot,
    after_repo_for_id: Callable[[str], RepoSnapshot | None],
    repo_id: str,
) -> RepositoryPermissionDiffEntry:
    before_repo = before["repos"].get(repo_id)
    after_repo = after_repo_for_id(repo_id)
    added, removed = _sorted_username_diff_values(
        _repo_usernames(before_repo),
        _repo_usernames(after_repo),
    )
    return {
        "id": src.decode_repository_id(repo_id),
        "name": _snapshot_diff_repo_name(before, after_repo_for_id, repo_id),
        "before_count": _permission_count(before_repo),
        "after_count": _permission_count(after_repo),
        "added": added,
        "removed": removed,
    }


def _snapshot_diff_summary(plan: _SnapshotDiffPlan) -> SnapshotDiffSummary:
    return {
        "repos_changed": len(plan.changed_repo_ids),
        "grants_added": plan.grants_added,
        "grants_removed": plan.grants_removed,
        "pending_bindIDs_added": len(plan.pending_added),
        "pending_bindIDs_removed": len(plan.pending_removed),
    }


def _snapshot_diff_pending_bind_ids(
    plan: _SnapshotDiffPlan,
) -> SnapshotDiffPendingBindIDs:
    return {"added": plan.pending_added, "removed": plan.pending_removed}


def build_snapshot_diff(before: Snapshot, after: Snapshot) -> SnapshotDiff:
    """Return a compact JSON-serializable diff between two full snapshots."""
    after_repo_for_id = after["repos"].get
    plan = _plan_snapshot_diff(
        before,
        after,
        set(before["repos"]) | set(after["repos"]),
        after_repo_for_id,
    )
    repos = [
        _snapshot_diff_entry(before, after_repo_for_id, repo_id)
        for repo_id in plan.changed_repo_ids
    ]
    return {
        "schema_version": SNAPSHOT_DIFF_SCHEMA_VERSION,
        "diff_kind": "repo_permissions",
        "before": _snapshot_diff_side(before),
        "after": _snapshot_diff_side(after),
        "summary": _snapshot_diff_summary(plan),
        "pending_bindIDs": _snapshot_diff_pending_bind_ids(plan),
        "repos": repos,
    }


def _write_snapshot_diff_entry(
    output: TextIO,
    entry: RepositoryPermissionDiffEntry,
    indent: int,
) -> None:
    field_indent = " " * (indent + 2)
    output.write("{\n")
    fields: tuple[tuple[str, object], ...] = (
        ("id", entry["id"]),
        ("name", entry["name"]),
        ("before_count", entry["before_count"]),
        ("after_count", entry["after_count"]),
    )
    for index, (field_name, value) in enumerate(fields):
        if index:
            output.write(",\n")
        output.write(f"{field_indent}{json.dumps(field_name)}: ")
        json.dump(value, output)
    output.write(",\n")
    output.write(f'{field_indent}"added": ')
    _write_string_list(output, entry["added"], indent + 2)
    output.write(",\n")
    output.write(f'{field_indent}"removed": ')
    _write_string_list(output, entry["removed"], indent + 2)
    output.write("\n" + " " * indent + "}")


def _write_snapshot_diff_json(
    path: Path,
    before: Snapshot,
    after: Snapshot,
    plan: _SnapshotDiffPlan,
    after_repo_for_id: Callable[[str], RepoSnapshot | None],
) -> int:
    with path.open("w", encoding="utf-8") as output:
        output.write("{\n")
        fields: tuple[tuple[str, object], ...] = (
            ("schema_version", SNAPSHOT_DIFF_SCHEMA_VERSION),
            ("diff_kind", "repo_permissions"),
            ("before", _snapshot_diff_side(before)),
            ("after", _snapshot_diff_side(after)),
            ("summary", _snapshot_diff_summary(plan)),
            ("pending_bindIDs", _snapshot_diff_pending_bind_ids(plan)),
        )
        first = True
        for field_name, value in fields:
            _write_top_level_json_field(output, field_name, value, first=first)
            first = False

        output.write(',\n  "repos": [')
        wrote_repo = False
        for repo_id in plan.changed_repo_ids:
            if wrote_repo:
                output.write(",")
            output.write("\n    ")
            _write_snapshot_diff_entry(
                output,
                _snapshot_diff_entry(before, after_repo_for_id, repo_id),
                4,
            )
            wrote_repo = True
        if wrote_repo:
            output.write("\n  ]")
        else:
            output.write("]")
        output.write("\n}\n")
    return path.stat().st_size


def write_snapshot_diff_from_snapshot_parts(
    path: Path,
    before: Snapshot,
    after: Snapshot,
    repo_ids: Iterable[str],
    after_repo_for_id: Callable[[str], RepoSnapshot | None],
) -> None:
    """Persist a full-snapshot diff without materializing every repo diff."""
    plan = _plan_snapshot_diff(before, after, repo_ids, after_repo_for_id)
    with src.event(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="snapshot_diff",
    ) as disk_event:
        path.parent.mkdir(parents=True, exist_ok=True)
        disk_event["bytes"] = _write_snapshot_diff_json(
            path,
            before,
            after,
            plan,
            after_repo_for_id,
        )


def write_snapshot_diff_from_snapshots(path: Path, before: Snapshot, after: Snapshot) -> None:
    """Persist a compact diff between two full snapshots."""
    write_snapshot_diff_from_snapshot_parts(
        path,
        before,
        after,
        set(before["repos"]) | set(after["repos"]),
        after["repos"].get,
    )


def write_snapshot_diff(path: Path, diff: SnapshotDiff) -> None:
    """Persist a compact full-snapshot diff as pretty-printed JSON."""
    with src.event(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="snapshot_diff",
    ) as disk_event:
        path.parent.mkdir(parents=True, exist_ok=True)
        disk_event["bytes"] = _write_pretty_json(path, diff)


def build_user_scoped_snapshot_diff(
    before: UserScopedSnapshot,
    after: UserScopedSnapshot,
) -> UserScopedSnapshotDiff:
    """Return a compact JSON-serializable diff between two scoped snapshots."""
    users: list[UserScopedSnapshotDiffEntry] = []
    grants_added = 0
    grants_removed = 0
    for username in sorted(set(before["users"]) | set(after["users"])):
        before_user = before["users"].get(username)
        after_user = after["users"].get(username)
        before_repositories = _repositories_by_id(before_user)
        after_repositories = _repositories_by_id(after_user)
        before_ids = set(before_repositories)
        after_ids = set(after_repositories)
        added_ids = sorted(after_ids - before_ids, key=lambda repo_id: after_repositories[repo_id])
        removed_ids = sorted(
            before_ids - after_ids,
            key=lambda repo_id: before_repositories[repo_id],
        )
        if not added_ids and not removed_ids:
            continue
        grants_added += len(added_ids)
        grants_removed += len(removed_ids)
        if after_user is not None:
            user_id = after_user["id"]
        elif before_user is not None:
            user_id = before_user["id"]
        else:
            continue
        users.append(
            {
                "username": username,
                "id": user_id,
                "before_count": len(before_repositories),
                "after_count": len(after_repositories),
                "added_repositories": [
                    _snapshot_diff_repository(repo_id, after_repositories[repo_id])
                    for repo_id in added_ids
                ],
                "removed_repositories": [
                    _snapshot_diff_repository(repo_id, before_repositories[repo_id])
                    for repo_id in removed_ids
                ],
            }
        )
    return {
        "schema_version": SNAPSHOT_DIFF_SCHEMA_VERSION,
        "diff_kind": "user_scoped_permissions",
        "before": _snapshot_diff_side(before),
        "after": _snapshot_diff_side(after),
        "summary": {
            "users_changed": len(users),
            "grants_added": grants_added,
            "grants_removed": grants_removed,
        },
        "users": users,
    }


def write_user_scoped_snapshot_diff(path: Path, diff: UserScopedSnapshotDiff) -> None:
    """Persist a compact user-scoped snapshot diff as pretty-printed JSON."""
    with src.event(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="user_scoped_snapshot_diff",
    ) as disk_event:
        path.parent.mkdir(parents=True, exist_ok=True)
        disk_event["bytes"] = _write_pretty_json(path, diff)


MAX_RENDERED_DIFF_ENTRIES = 50
MAX_RENDERED_DIFF_VALUES = 50


def _render_limited_values(values: list[str], max_values: int) -> str:
    if len(values) <= max_values:
        return ", ".join(values)
    visible_values = values[:max_values]
    omitted_count = len(values) - max_values
    return f"{', '.join(visible_values)}, ... ({omitted_count} more)"


def render_diff(
    diff: dict[str, RepoDiff],
    max_repos: int = MAX_RENDERED_DIFF_ENTRIES,
    max_usernames_per_section: int = MAX_RENDERED_DIFF_VALUES,
) -> str:
    """Format a diff dict as a human-readable multi-line string."""
    if not diff:
        return "No changes."
    lines: list[str] = []
    sorted_diff = sorted(diff.items(), key=lambda item: item[1]["name"])
    total_added = sum(len(repo_diff["added"]) for repo_diff in diff.values())
    total_removed = sum(len(repo_diff["removed"]) for repo_diff in diff.values())
    for repo_id, repo_diff in sorted_diff[:max_repos]:
        lines.append(f"=== {repo_diff['name']} (id={src.decode_repository_id(repo_id)}) ===")
        if repo_diff["added"]:
            lines.append(
                "  + added ({count}): {usernames}".format(
                    count=len(repo_diff["added"]),
                    usernames=_render_limited_values(
                        repo_diff["added"],
                        max_usernames_per_section,
                    ),
                )
            )
        if repo_diff["removed"]:
            lines.append(
                "  - removed ({count}): {usernames}".format(
                    count=len(repo_diff["removed"]),
                    usernames=_render_limited_values(
                        repo_diff["removed"],
                        max_usernames_per_section,
                    ),
                )
            )
    omitted_repos = len(sorted_diff) - max_repos
    if omitted_repos > 0:
        lines.append(
            f"... {omitted_repos} more repo(s) omitted from log output; "
            "see diff.json for full added/removed lists."
        )
    lines.append("")
    lines.append(
        f"Summary: {len(diff)} repo(s) changed; "
        f"{total_added} grant(s) added, {total_removed} grant(s) removed."
    )
    return "\n".join(lines)


def render_snapshot_diff_from_snapshot_parts(
    before: Snapshot,
    after: Snapshot,
    repo_ids: Iterable[str],
    after_repo_for_id: Callable[[str], RepoSnapshot | None],
    max_repos: int = MAX_RENDERED_DIFF_ENTRIES,
    max_usernames_per_section: int = MAX_RENDERED_DIFF_VALUES,
) -> str:
    """Format a capped human diff without materializing the full diff."""
    plan = _plan_snapshot_diff(before, after, repo_ids, after_repo_for_id)
    if not plan.changed_repo_ids:
        return "No changes."

    lines: list[str] = []
    for repo_id in plan.changed_repo_ids[:max_repos]:
        entry = _snapshot_diff_entry(before, after_repo_for_id, repo_id)
        lines.append(f"=== {entry['name']} (id={entry['id']}) ===")
        if entry["added"]:
            lines.append(
                "  + added ({count}): {usernames}".format(
                    count=len(entry["added"]),
                    usernames=_render_limited_values(
                        entry["added"],
                        max_usernames_per_section,
                    ),
                )
            )
        if entry["removed"]:
            lines.append(
                "  - removed ({count}): {usernames}".format(
                    count=len(entry["removed"]),
                    usernames=_render_limited_values(
                        entry["removed"],
                        max_usernames_per_section,
                    ),
                )
            )
    omitted_repos = len(plan.changed_repo_ids) - max_repos
    if omitted_repos > 0:
        lines.append(
            f"... {omitted_repos} more repo(s) omitted from log output; "
            "see diff.json for full added/removed lists."
        )
    lines.append("")
    lines.append(
        f"Summary: {len(plan.changed_repo_ids)} repo(s) changed; "
        f"{plan.grants_added} grant(s) added, {plan.grants_removed} grant(s) removed."
    )
    return "\n".join(lines)


def render_snapshot_diff(
    before: Snapshot,
    after: Snapshot,
    max_repos: int = MAX_RENDERED_DIFF_ENTRIES,
    max_usernames_per_section: int = MAX_RENDERED_DIFF_VALUES,
) -> str:
    """Format a capped human diff between two full snapshots."""
    return render_snapshot_diff_from_snapshot_parts(
        before,
        after,
        set(before["repos"]) | set(after["repos"]),
        after["repos"].get,
        max_repos,
        max_usernames_per_section,
    )


def render_user_scoped_diff(
    before: UserScopedSnapshot,
    after: UserScopedSnapshot,
    max_users: int = MAX_RENDERED_DIFF_ENTRIES,
    max_repositories_per_section: int = MAX_RENDERED_DIFF_VALUES,
) -> str:
    """Format a user-scoped snapshot diff as human-readable text."""
    lines: list[str] = []
    total_added = 0
    total_removed = 0
    changed_users = 0
    for username in sorted(set(before["users"]) | set(after["users"])):
        before_repositories = _repositories_by_id(before["users"].get(username))
        after_repositories = _repositories_by_id(after["users"].get(username))
        before_ids = set(before_repositories)
        after_ids = set(after_repositories)
        added_ids = sorted(after_ids - before_ids, key=lambda repo_id: after_repositories[repo_id])
        removed_ids = sorted(
            before_ids - after_ids,
            key=lambda repo_id: before_repositories[repo_id],
        )
        if not added_ids and not removed_ids:
            continue
        changed_users += 1
        total_added += len(added_ids)
        total_removed += len(removed_ids)
        if changed_users > max_users:
            continue
        lines.append(f"=== {username} ===")
        if added_ids:
            lines.append(
                "  + added ({count}): {repos}".format(
                    count=len(added_ids),
                    repos=_render_limited_values(
                        [after_repositories[repo_id] for repo_id in added_ids],
                        max_repositories_per_section,
                    ),
                )
            )
        if removed_ids:
            lines.append(
                "  - removed ({count}): {repos}".format(
                    count=len(removed_ids),
                    repos=_render_limited_values(
                        [before_repositories[repo_id] for repo_id in removed_ids],
                        max_repositories_per_section,
                    ),
                )
            )
    if not lines:
        return "No changes."
    omitted_users = changed_users - max_users
    if omitted_users > 0:
        lines.append(
            f"... {omitted_users} more user(s) omitted from log output; "
            "see diff.json for full added/removed lists."
        )
    lines.append("")
    lines.append(f"Summary: {total_added} grant(s) added, {total_removed} grant(s) removed.")
    return "\n".join(lines)


def _repositories_by_id(
    user_snapshot: UserScopedUserSnapshot | None,
) -> dict[str, str]:
    if user_snapshot is None:
        return {}
    return {
        repository["id"]: repository["name"]
        for repository in user_snapshot["explicit_repositories"]
    }


def _permission_count(repo_snapshot: RepoSnapshot | None) -> int:
    if repo_snapshot is None:
        return 0
    return len(repo_snapshot["explicit_permissions_users"])


def _snapshot_diff_side(snapshot: Snapshot | UserScopedSnapshot) -> SnapshotDiffSide:
    return {
        "captured_at": snapshot["captured_at"],
        "endpoint": snapshot["endpoint"],
        "bindID_mode": snapshot["bindID_mode"],
        "config_file": snapshot["config_file"],
        "config_sha256": snapshot["config_sha256"],
    }


def _snapshot_diff_repository(repo_id: str, repo_name: str) -> SnapshotDiffRepository:
    return {"id": src.decode_repository_id(repo_id), "name": repo_name}
