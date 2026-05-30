"""Repo-permission mutation application."""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Sequence
from concurrent.futures import (
    FIRST_COMPLETED,
    CancelledError,
    Future,
    ThreadPoolExecutor,
    as_completed,
    wait,
)
from dataclasses import dataclass, field
from typing import TypeAlias, cast

import src_py_lib as src

from ..shared import run_context
from ..shared import types as shared_types
from . import queries
from . import types as permission_types

log = logging.getLogger(__name__)


@dataclass
class CircuitBreaker:
    """Sliding-window circuit breaker for the apply phase.

    Tracks the most recent `window_size` mutation outcomes (success or
    failure). Once `failure_rate` over that window exceeds
    `failure_threshold` AND we have at least `min_samples` outcomes
    recorded, the breaker opens and `is_open()` returns True for the rest
    of the run (no half-open / reset logic — once we decide the backend
    is too unhealthy, we stay tripped).

    Designed to bail out of a hopeless run (e.g., backend down or
    severely rate-limiting) instead of grinding through every remaining
    mutation, retrying each request repeatedly, and burning hours of
    wall-clock in retries while making things worse for the server.

    Used by the apply helpers: each completed mutation calls
    `breaker.record(success=...)`, then `is_open()` is checked between
    completions; once open, the remaining queued futures are cancelled
    and the loop exits, leaving the operator a clear ERROR log + a
    non-zero exit code.
    """

    window_size: int = 50
    failure_threshold: float = 0.25  # fraction; 0.25 == 25%
    min_samples: int = 20
    _outcomes: deque[bool] = field(init=False)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)
    _opened: bool = field(init=False, default=False)
    total_successes: int = field(init=False, default=0)
    total_failures: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self._outcomes = deque(maxlen=self.window_size)

    def record(self, success: bool) -> None:
        with self._lock:
            self._outcomes.append(success)
            if success:
                self.total_successes += 1
            else:
                self.total_failures += 1
            if self._opened:
                return
            if len(self._outcomes) < self.min_samples:
                return
            failures = sum(1 for outcome in self._outcomes if not outcome)
            rate = failures / len(self._outcomes)
            if rate >= self.failure_threshold:
                self._opened = True
                src.info(
                    "circuit_breaker_open",
                    window_size=len(self._outcomes),
                    recent_failures=failures,
                    failure_rate=round(rate, 3),
                    total_successes=self.total_successes,
                    total_failures=self.total_failures,
                )
                log.error(
                    "Circuit breaker OPEN: %d/%d (%.0f%%) of last %d "
                    "mutations failed; halting apply to avoid hammering "
                    "a struggling instance. Remaining work will be "
                    "cancelled; the run will continue with the after-"
                    "snapshot+validation, then exit 1.",
                    failures,
                    len(self._outcomes),
                    100 * rate,
                    len(self._outcomes),
                )

    def is_open(self) -> bool:
        with self._lock:
            return self._opened


@dataclass(frozen=True, slots=True)
class PermissionAddition(shared_types.UserIdentity):
    """One explicit repository permission to add for one user."""

    repo_id: str
    repo_name: str


@dataclass(frozen=True, slots=True)
class PermissionRemoval(shared_types.UserIdentity):
    """One explicit repository permission to remove for one user."""

    repo_id: str
    repo_name: str


PermissionChange: TypeAlias = PermissionAddition | PermissionRemoval


def set_repo_permissions(
    client: src.SourcegraphClient,
    repo_id: str,
    user_perms: list[dict[str, str]],
) -> None:
    """Overwrite a repo's explicit permissions with `user_perms` in one call.

    `user_perms` is a list of `{"bindID": <username>, "permission": "READ"}`.
    bindID is always the Sourcegraph username — validate_site_config()
    enforces that the site is configured with `bindID: "username"`.

    Retries on transient transport failures (network errors, HTTP 408/429/5xx)
    happen inside the shared Sourcegraph client — every GraphQL call goes through the
    same retry plumbing. Application-level GraphQL errors (auth, validation,
    schema) are NOT retried — they propagate on the first attempt.
    """
    with src.event(
        "set_repo_perms",
        repo_id=repo_id,
        user_count=len(user_perms),
    ):
        client.graphql(
            queries.MUTATION_SET_REPO_PERMISSIONS,
            cast(src.JSONDict, {"repo": repo_id, "userPerms": user_perms}),
        )


def set_repo_permissions_for_usernames(
    client: src.SourcegraphClient,
    repo_id: str,
    usernames: Sequence[str],
) -> None:
    """Overwrite a repo's explicit permissions, building GraphQL input lazily."""
    set_repo_permissions(
        client,
        repo_id,
        [{"bindID": username, "permission": "READ"} for username in usernames],
    )


def _mutate_repo_permission_for_user(
    client: src.SourcegraphClient,
    change: PermissionChange,
    mutation: str,
    event_name: str,
) -> None:
    """Apply one additive repo-permission edge mutation."""
    with src.event(
        event_name,
        repo_id=change.repo_id,
        username=change.username,
    ):
        client.graphql(
            mutation,
            cast(src.JSONDict, {"repo": change.repo_id, "user": change.user_id}),
        )


def _apply_permission_changes(
    client: src.SourcegraphClient,
    changes: Sequence[PermissionChange],
    *,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
    mutation: str,
    event_name: str,
    action: str,
) -> shared_types.MutationCounts:
    """Dispatch additive edge mutations across a thread pool."""
    with src.event(
        f"apply_{action}_payloads",
        payload_count=len(changes),
        parallelism=parallelism,
    ) as batch_event:
        succeeded = 0
        failed = 0
        canceled = 0
        breaker = CircuitBreaker()
        with run_context.thread_pool(parallelism, worker_pool) as executor:
            futures = {
                src.submit_with_log_context(
                    executor,
                    _mutate_repo_permission_for_user,
                    client,
                    change,
                    mutation,
                    event_name,
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
                        "  OK %s %s → %s (id=%d).",
                        action,
                        change.username,
                        change.repo_name,
                        src.decode_repository_id(change.repo_id),
                    )
                except CancelledError:
                    canceled += 1
                    continue
                except Exception as exception:
                    failed += 1
                    breaker.record(success=False)
                    log.error(
                        "  FAIL %s %s → %s (id=%d): %s",
                        action,
                        change.username,
                        change.repo_name,
                        src.decode_repository_id(change.repo_id),
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


def apply_additions(
    client: src.SourcegraphClient,
    additions: Sequence[PermissionAddition],
    *,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    """Add explicit repo permissions while preserving existing grants."""
    return _apply_permission_changes(
        client,
        additions,
        parallelism=parallelism,
        worker_pool=worker_pool,
        mutation=queries.MUTATION_ADD_REPO_PERMISSION,
        event_name="add_repo_permission",
        action="add",
    )


def apply_removals(
    client: src.SourcegraphClient,
    removals: Sequence[PermissionRemoval],
    *,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    """Remove explicit repo permissions while preserving other grants."""
    return _apply_permission_changes(
        client,
        removals,
        parallelism=parallelism,
        worker_pool=worker_pool,
        mutation=queries.MUTATION_REMOVE_REPO_PERMISSION,
        event_name="remove_repo_permission",
        action="remove",
    )


def _apply_repo_overwrite_plans(
    client: src.SourcegraphClient,
    overwrites: Sequence[permission_types.RepositoryUsernameOverwrite],
    *,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    """Dispatch per-repo overwrite mutations with bounded in-flight work."""
    max_pending_futures = max(1, parallelism * 2)
    payload_grant_count = sum(len(overwrite.usernames) for overwrite in overwrites)
    with src.event(
        "apply_username_overwrites",
        payload_count=len(overwrites),
        parallelism=parallelism,
        payload_grant_count=payload_grant_count,
        max_pending_futures=max_pending_futures,
    ) as batch_event:
        succeeded = 0
        failed = 0
        canceled = 0
        submitted_count = 0
        submissions_stopped = False
        breaker = CircuitBreaker()
        overwrite_iterator = iter(overwrites)
        futures: dict[Future[None], permission_types.RepositoryUsernameOverwrite] = {}

        def _submit_next(executor: ThreadPoolExecutor) -> bool:
            nonlocal submitted_count
            try:
                overwrite = next(overwrite_iterator)
            except StopIteration:
                return False
            future = cast(
                Future[None],
                src.submit_with_log_context(
                    executor,
                    set_repo_permissions_for_usernames,
                    client,
                    overwrite.repository_id,
                    overwrite.usernames,
                ),
            )
            futures[future] = overwrite
            submitted_count += 1
            return True

        def _stop_submissions() -> None:
            nonlocal submissions_stopped
            if submissions_stopped:
                return
            submissions_stopped = True
            for pending_future in futures:
                if not pending_future.done():
                    pending_future.cancel()

        with run_context.thread_pool(parallelism, worker_pool) as executor:
            while len(futures) < max_pending_futures and _submit_next(executor):
                pass

            while futures:
                done_futures, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in done_futures:
                    overwrite = futures.pop(future)
                    try:
                        future.result()
                        succeeded += 1
                        breaker.record(success=True)
                        log.info(
                            "  OK %s (id=%d) — %d users.",
                            overwrite.repository_name,
                            src.decode_repository_id(overwrite.repository_id),
                            len(overwrite.usernames),
                        )
                    except CancelledError:
                        # Cancelled by the breaker; not counted as a failure
                        # because we never gave the server a chance to apply it.
                        canceled += 1
                        continue
                    except Exception as exception:
                        failed += 1
                        breaker.record(success=False)
                        log.error(
                            "  FAIL %s (id=%d): %s",
                            overwrite.repository_name,
                            src.decode_repository_id(overwrite.repository_id),
                            exception,
                        )

                    if breaker.is_open():
                        _stop_submissions()

                while (
                    not submissions_stopped
                    and len(futures) < max_pending_futures
                    and _submit_next(executor)
                ):
                    pass

        if submissions_stopped:
            canceled += len(overwrites) - submitted_count
        batch_event["succeeded"] = succeeded
        batch_event["failed"] = failed
        batch_event["canceled"] = canceled
        batch_event["circuit_broken"] = breaker.is_open()
        batch_event["submitted"] = submitted_count
        return shared_types.MutationCounts(
            succeeded=succeeded,
            failed=failed,
            canceled=canceled,
        )


def apply_username_overwrites(
    client: src.SourcegraphClient,
    overwrites: Sequence[permission_types.RepositoryUsernameOverwrite],
    *,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> shared_types.MutationCounts:
    """Dispatch repo overwrite mutations, building GraphQL dicts in workers."""
    return _apply_repo_overwrite_plans(
        client,
        overwrites,
        parallelism=parallelism,
        worker_pool=worker_pool,
    )
