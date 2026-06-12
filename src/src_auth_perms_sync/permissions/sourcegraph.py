"""Sourcegraph GraphQL list helpers for repo-permission sync."""

from __future__ import annotations

import datetime
import logging
import time
from collections import deque
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any, cast

import src_py_lib as src

from ..shared import run_context
from ..shared import sourcegraph as shared_sourcegraph
from ..shared import types as shared_types
from . import queries
from . import types as permission_types

log = logging.getLogger(__name__)
SITE_USER_CANDIDATE_PAGE_SIZE = 1000
REPOSITORY_PAGE_SIZE = 1000
USER_HYDRATION_BATCH_SIZE = 25


@dataclass(frozen=True)
class SiteUserCandidateSelection:
    """Active user candidates after filtering explicit repo-permission owners."""

    candidates: list[shared_types.SiteUserCandidate]
    explicit_user_count: int


@dataclass(frozen=True)
class _SiteUserCandidatePage:
    offset: int
    candidates: list[shared_types.SiteUserCandidate]


@dataclass(frozen=True)
class RepositoryCandidate:
    """Repository selected for repo-scoped get/set work."""

    repository: permission_types.Repository
    created_at: str
    external_service_ids: tuple[str, ...]


def list_external_services(client: src.SourcegraphClient) -> list[permission_types.ExternalService]:
    return [
        cast(permission_types.ExternalService, node)
        for node in client.stream_connection_nodes(
            queries.QUERY_EXTERNAL_SERVICES,
            connection_path=("externalServices",),
            page_size=shared_sourcegraph.DEFAULT_PAGE_SIZE,
        )
    ]


def list_repos_for_external_service(
    client: src.SourcegraphClient, external_service_id: str
) -> list[permission_types.Repository]:
    return [
        cast(permission_types.Repository, node)
        for node in client.stream_connection_nodes(
            queries.QUERY_REPOS_BY_EXTERNAL_SERVICE,
            {"esID": external_service_id},
            connection_path=("repositories",),
            page_size=REPOSITORY_PAGE_SIZE,
        )
    ]


def list_repository_candidates_by_names(
    client: src.SourcegraphClient,
    repository_names: Sequence[str],
) -> list[RepositoryCandidate]:
    """Return repositories whose names exactly match `repository_names`."""
    unique_names = tuple(dict.fromkeys(repository_names))
    if not unique_names:
        return []
    return [
        _repository_candidate_from_node(node)
        for node in client.stream_connection_nodes(
            queries.QUERY_REPOSITORIES_BY_NAMES,
            {"names": list(unique_names)},
            connection_path=("repositories",),
            page_size=REPOSITORY_PAGE_SIZE,
        )
    ]


def list_repository_candidates(client: src.SourcegraphClient) -> list[RepositoryCandidate]:
    """Return all repositories with enough metadata for repo filtering."""
    return [
        _repository_candidate_from_node(node)
        for node in client.stream_connection_nodes(
            queries.QUERY_REPOSITORY_CANDIDATES,
            connection_path=("repositories",),
            page_size=REPOSITORY_PAGE_SIZE,
        )
    ]


def list_repository_candidates_created_on_or_after(
    client: src.SourcegraphClient,
    created_after: str,
) -> list[RepositoryCandidate]:
    """Return repositories with Sourcegraph rows created on or after a timestamp."""
    threshold = _parse_sourcegraph_datetime(created_after)
    candidates: list[RepositoryCandidate] = []
    for node in client.stream_connection_nodes(
        queries.QUERY_REPOSITORY_CANDIDATES_BY_CREATED_AT,
        connection_path=("repositories",),
        page_size=REPOSITORY_PAGE_SIZE,
    ):
        candidate = _repository_candidate_from_node(node)
        if _parse_sourcegraph_datetime(candidate.created_at) < threshold:
            break
        candidates.append(candidate)
    return candidates


def _repository_candidate_from_node(node: dict[str, Any]) -> RepositoryCandidate:
    repository_id = src.json_str(node, "id")
    repository_name = src.json_str(node, "name")
    created_at = src.json_str(node, "createdAt")
    external_services = src.json_dict(node.get("externalServices"))
    external_service_ids = tuple(
        external_service_id
        for external_service_id in (
            src.json_dict(external_service).get("id")
            for external_service in src.json_list(external_services.get("nodes"))
        )
        if isinstance(external_service_id, str)
    )
    return RepositoryCandidate(
        repository={"id": repository_id, "name": repository_name},
        created_at=created_at,
        external_service_ids=external_service_ids,
    )


def _parse_sourcegraph_datetime(value: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def get_user_by_username(
    client: src.SourcegraphClient,
    username: str,
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
) -> shared_types.User | None:
    """Return the exact Sourcegraph user for `username`, if it exists."""
    data = cast(
        dict[str, Any],
        client.graphql(
            queries.query_user_by_username(
                include_emails=include_emails,
                include_account_data=include_account_data,
            ),
            cast(src.JSONDict, {"username": username}),
        ),
    )
    return cast(shared_types.User | None, data.get("user"))


def get_user_by_email(
    client: src.SourcegraphClient,
    email: str,
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
) -> shared_types.User | None:
    """Return the user owning the verified email address, if it exists."""
    data = cast(
        dict[str, Any],
        client.graphql(
            queries.query_user_by_email(
                include_emails=include_emails,
                include_account_data=include_account_data,
            ),
            cast(src.JSONDict, {"email": email}),
        ),
    )
    return cast(shared_types.User | None, data.get("user"))


def get_user_by_id(
    client: src.SourcegraphClient,
    user_id: str,
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
) -> shared_types.User | None:
    """Hydrate a User node by GraphQL ID."""
    data = cast(
        dict[str, Any],
        client.graphql(
            queries.query_user_by_id(
                include_emails=include_emails,
                include_account_data=include_account_data,
            ),
            cast(src.JSONDict, {"id": user_id}),
        ),
    )
    return cast(shared_types.User | None, data.get("node"))


def get_users_by_ids(
    client: src.SourcegraphClient,
    user_ids: Sequence[str],
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    parallelism: int = 1,
    worker_pool: ThreadPoolExecutor | None = None,
    progress_label: str | None = None,
) -> list[shared_types.User | None]:
    """Hydrate User nodes by GraphQL ID in aliased batches.

    Returns one entry per requested ID, in order; `None` marks users that
    no longer exist.
    """

    def fetch_batch(batch: Sequence[str]) -> list[shared_types.User | None]:
        data = client.graphql(
            queries.users_by_ids_batch_query(
                len(batch),
                include_emails=include_emails,
                include_account_data=include_account_data,
            ),
            cast(src.JSONDict, {f"user{index}": user_id for index, user_id in enumerate(batch)}),
            follow_pages=False,
        )
        users: list[shared_types.User | None] = []
        for index in range(len(batch)):
            node = src.json_dict(data.get(f"user{index}"))
            users.append(cast(shared_types.User, node) if node.get("id") else None)
        return users

    users: list[shared_types.User | None] = []
    for batch_users in run_context.parallel_map(
        fetch_batch,
        _batches(tuple(user_ids), USER_HYDRATION_BATCH_SIZE),
        parallelism=parallelism,
        worker_pool=worker_pool,
        progress_label=progress_label,
    ):
        users.extend(batch_users)
    return users


def list_site_user_candidates(
    client: src.SourcegraphClient,
    created_after: str | None,
    *,
    parallelism: int = 1,
    worker_pool: ThreadPoolExecutor | None = None,
) -> list[shared_types.SiteUserCandidate]:
    """Return non-deleted site users, optionally filtered by creation time."""
    created_filter = {"gte": created_after} if created_after is not None else None
    created_filter_label = f" created on or after {created_after}" if created_after else ""
    log.info("Querying active Sourcegraph user candidates%s ...", created_filter_label)
    started = time.perf_counter()
    first_page, total_count = _site_user_candidate_page(
        client,
        created_filter,
        offset=0,
        page_size=SITE_USER_CANDIDATE_PAGE_SIZE,
    )
    if not first_page or len(first_page) >= total_count:
        return first_page

    # If the server caps `nodes(limit:)` below our requested page size, use
    # the observed first-page width so parallel offset requests do not skip
    # rows.
    page_size = len(first_page)
    page_count = (total_count + page_size - 1) // page_size
    log.info(
        "Loading %d active Sourcegraph user candidate(s)%s across %d page(s) "
        "of %d users/page with parallelism=%d ...",
        total_count,
        created_filter_label,
        page_count,
        page_size,
        parallelism,
    )
    pages: list[tuple[int, list[shared_types.SiteUserCandidate]]] = [(0, first_page)]

    def fetch_page(offset: int) -> tuple[int, list[shared_types.SiteUserCandidate]]:
        nodes, _ = _site_user_candidate_page(
            client,
            created_filter,
            offset=offset,
            page_size=SITE_USER_CANDIDATE_PAGE_SIZE,
        )
        return offset, nodes

    pages.extend(
        run_context.parallel_map(
            fetch_page,
            range(page_size, total_count, page_size),
            parallelism=parallelism,
            worker_pool=worker_pool,
            progress_label="Loaded active Sourcegraph user candidate pages",
        )
    )
    candidates = _dedupe_site_user_candidate_pages(pages)
    _log_user_candidate_load_progress(len(candidates), total_count, started)
    return candidates


def list_site_user_candidates_without_explicit_repos(
    client: src.SourcegraphClient,
    created_after: str | None,
    *,
    batch_size: int,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> SiteUserCandidateSelection:
    """Return active site users that do not already have explicit API grants.

    Candidate pages and explicit-permission checks are pipelined so the slow
    permission checks can start as soon as the first candidate page yields a
    full batch of users.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")

    created_filter = {"gte": created_after} if created_after is not None else None
    created_filter_label = f" created on or after {created_after}" if created_after else ""
    log.info("Querying active Sourcegraph user candidates%s ...", created_filter_label)
    started = time.perf_counter()
    first_page, total_count = _site_user_candidate_page(
        client,
        created_filter,
        offset=0,
        page_size=SITE_USER_CANDIDATE_PAGE_SIZE,
    )
    if not first_page:
        return SiteUserCandidateSelection(candidates=[], explicit_user_count=0)

    if len(first_page) >= total_count or parallelism <= 1:
        # Sequential path: still page through ALL candidates. If the server
        # caps `nodes(limit:)` below our requested page size, use the
        # observed first-page width so offset steps do not skip rows.
        sequential_pages: list[tuple[int, list[shared_types.SiteUserCandidate]]] = [(0, first_page)]
        observed_page_size = len(first_page)
        for offset in range(observed_page_size, total_count, observed_page_size):
            nodes, _ = _site_user_candidate_page(
                client,
                created_filter,
                offset=offset,
                page_size=SITE_USER_CANDIDATE_PAGE_SIZE,
            )
            sequential_pages.append((offset, nodes))
        sequential_candidates = _dedupe_site_user_candidate_pages(sequential_pages)
        _log_user_candidate_load_progress(len(sequential_candidates), total_count, started)
        log.info(
            "Checking %d active user candidate(s)%s for existing explicit repo permissions "
            "in batches of %d ...",
            len(sequential_candidates),
            created_filter_label,
            batch_size,
        )
        explicit_user_ids = user_ids_with_explicit_repos(
            client,
            [candidate["id"] for candidate in sequential_candidates],
            batch_size=batch_size,
            parallelism=parallelism,
            worker_pool=worker_pool,
        )
        return SiteUserCandidateSelection(
            candidates=[
                candidate
                for candidate in sequential_candidates
                if candidate["id"] not in explicit_user_ids
            ],
            explicit_user_count=len(explicit_user_ids),
        )

    page_size = len(first_page)
    page_count = (total_count + page_size - 1) // page_size
    log.info(
        "Loading %d active Sourcegraph user candidate(s)%s across %d page(s) "
        "of %d users/page, while checking explicit repo permissions in batches "
        "of %d with parallelism=%d ...",
        total_count,
        created_filter_label,
        page_count,
        page_size,
        batch_size,
        parallelism,
    )
    pages, explicit_user_ids = _load_candidate_pages_and_explicit_user_ids(
        client,
        created_filter,
        first_page,
        total_count=total_count,
        page_size=page_size,
        batch_size=batch_size,
        parallelism=parallelism,
        worker_pool=worker_pool,
        started=started,
    )
    candidates = _dedupe_site_user_candidate_pages(pages)
    _log_user_candidate_load_progress(len(candidates), total_count, started)
    return SiteUserCandidateSelection(
        candidates=[
            candidate for candidate in candidates if candidate["id"] not in explicit_user_ids
        ],
        explicit_user_count=len(explicit_user_ids),
    )


def _site_user_candidate_page(
    client: src.SourcegraphClient,
    created_filter: dict[str, str] | None,
    *,
    offset: int,
    page_size: int,
) -> tuple[list[shared_types.SiteUserCandidate], int]:
    data = cast(
        dict[str, Any],
        client.graphql(
            queries.QUERY_SITE_USERS,
            cast(
                src.JSONDict,
                {
                    "limit": page_size,
                    "offset": offset,
                    "createdAt": created_filter,
                },
            ),
        ),
    )
    site_users = cast(dict[str, Any], data["site"]["users"])
    total_count = int(cast(float, site_users["totalCount"]))
    nodes = cast(list[shared_types.SiteUserCandidate], site_users["nodes"])
    return nodes, total_count


def _load_candidate_pages_and_explicit_user_ids(
    client: src.SourcegraphClient,
    created_filter: dict[str, str] | None,
    first_page: list[shared_types.SiteUserCandidate],
    *,
    total_count: int,
    page_size: int,
    batch_size: int,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None,
    started: float,
) -> tuple[list[tuple[int, list[shared_types.SiteUserCandidate]]], set[str]]:
    pages: list[tuple[int, list[shared_types.SiteUserCandidate]]] = [(0, first_page)]
    explicit_user_ids: set[str] = set()
    queued_user_ids: set[str] = set()
    candidate_batch_buffer: list[str] = []
    ready_user_batches = deque[tuple[str, ...]]()
    page_offsets = iter(range(page_size, total_count, page_size))
    page_count = (total_count + page_size - 1) // page_size
    total_batch_count = (total_count + batch_size - 1) // batch_size
    completed_page_count = 1
    completed_batch_count = 0
    pages_exhausted = False
    page_pending_limit = max(1, parallelism // 2)
    early_permission_pending_limit = max(1, parallelism - page_pending_limit)
    pending_page_futures: dict[Future[_SiteUserCandidatePage], int] = {}
    pending_permission_futures: dict[Future[set[str]], tuple[str, ...]] = {}

    def queue_user_batches(candidates: Sequence[shared_types.SiteUserCandidate]) -> None:
        for candidate in candidates:
            user_id = candidate["id"]
            if user_id in queued_user_ids:
                continue
            queued_user_ids.add(user_id)
            candidate_batch_buffer.append(user_id)
            if len(candidate_batch_buffer) == batch_size:
                ready_user_batches.append(tuple(candidate_batch_buffer))
                candidate_batch_buffer.clear()

    def fetch_page(offset: int) -> _SiteUserCandidatePage:
        candidates, _ = _site_user_candidate_page(
            client,
            created_filter,
            offset=offset,
            page_size=SITE_USER_CANDIDATE_PAGE_SIZE,
        )
        return _SiteUserCandidatePage(offset=offset, candidates=candidates)

    def submit_candidate_pages(executor: ThreadPoolExecutor) -> None:
        nonlocal pages_exhausted
        while not pages_exhausted and len(pending_page_futures) < page_pending_limit:
            try:
                offset = next(page_offsets)
            except StopIteration:
                pages_exhausted = True
                return
            future = cast(
                Future[_SiteUserCandidatePage],
                src.submit_with_log_context(executor, fetch_page, offset),
            )
            pending_page_futures[future] = offset

    def flush_final_user_batch() -> None:
        if pages_exhausted and not pending_page_futures and candidate_batch_buffer:
            ready_user_batches.append(tuple(candidate_batch_buffer))
            candidate_batch_buffer.clear()

    def permission_pending_limit() -> int:
        if pages_exhausted and not pending_page_futures:
            return parallelism
        return early_permission_pending_limit

    def submit_permission_batches(executor: ThreadPoolExecutor) -> None:
        while ready_user_batches and len(pending_permission_futures) < permission_pending_limit():
            user_batch = ready_user_batches.popleft()
            future = cast(
                Future[set[str]],
                src.submit_with_log_context(
                    executor,
                    _user_ids_with_explicit_repos_batch,
                    client,
                    user_batch,
                ),
            )
            pending_permission_futures[future] = user_batch

    def cancel_pending_futures() -> None:
        for future in list(pending_page_futures) + list(pending_permission_futures):
            future.cancel()

    queue_user_batches(first_page)
    with run_context.thread_pool(parallelism, worker_pool) as executor:
        try:
            submit_candidate_pages(executor)
            flush_final_user_batch()
            submit_permission_batches(executor)
            while pending_page_futures or pending_permission_futures:
                pending_futures: set[Future[object]] = {
                    cast(Future[object], future) for future in pending_page_futures
                }
                pending_futures.update(
                    cast(Future[object], future) for future in pending_permission_futures
                )
                completed_futures, _ = wait(
                    pending_futures,
                    return_when=FIRST_COMPLETED,
                )
                for completed_future in completed_futures:
                    page_future = cast(Future[_SiteUserCandidatePage], completed_future)
                    if page_future in pending_page_futures:
                        page = page_future.result()
                        pending_page_futures.pop(page_future)
                        pages.append((page.offset, page.candidates))
                        completed_page_count += 1
                        if run_context.parallel_progress_due(completed_page_count, page_count):
                            run_context.log_parallel_progress(
                                "Loaded active Sourcegraph user candidate pages",
                                completed_page_count,
                                page_count,
                                started,
                            )
                        queue_user_batches(page.candidates)
                    else:
                        permission_future = cast(Future[set[str]], completed_future)
                        pending_permission_futures.pop(permission_future)
                        explicit_user_ids.update(permission_future.result())
                        completed_batch_count += 1
                        if run_context.parallel_progress_due(
                            completed_batch_count,
                            total_batch_count,
                        ):
                            run_context.log_parallel_progress(
                                "Checked explicit repo permissions for user batches",
                                completed_batch_count,
                                total_batch_count,
                                started,
                            )
                submit_candidate_pages(executor)
                flush_final_user_batch()
                submit_permission_batches(executor)
        except BaseException:
            cancel_pending_futures()
            raise
    return pages, explicit_user_ids


def _dedupe_site_user_candidate_pages(
    pages: Iterable[tuple[int, Sequence[shared_types.SiteUserCandidate]]],
) -> list[shared_types.SiteUserCandidate]:
    candidates: list[shared_types.SiteUserCandidate] = []
    seen_user_ids: set[str] = set()
    for _, page_candidates in sorted(pages, key=lambda page: page[0]):
        for candidate in page_candidates:
            user_id = candidate["id"]
            if user_id in seen_user_ids:
                continue
            seen_user_ids.add(user_id)
            candidates.append(candidate)
    return candidates


def _log_user_candidate_load_progress(completed: int, total_count: int, started: float) -> None:
    elapsed = time.perf_counter() - started
    rate = completed / elapsed if elapsed > 0 else 0.0
    remaining = max(total_count - completed, 0)
    eta_seconds = remaining / rate if rate > 0 else 0.0
    log.info(
        "Loaded %d / %d active Sourcegraph user candidate(s) (%.0f%%) "
        "in %.0fs (%.0f users/sec, ETA %.0fs).",
        completed,
        total_count,
        100.0 * completed / total_count,
        elapsed,
        rate,
        eta_seconds,
    )


def user_ids_with_explicit_repos(
    client: src.SourcegraphClient,
    user_ids: Sequence[str],
    *,
    batch_size: int,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> set[str]:
    """Return user IDs that have at least one explicit API repository grant."""
    batches = list(_batches(tuple(dict.fromkeys(user_ids)), batch_size))

    def fetch_batch(batch: Sequence[str]) -> set[str]:
        return _user_ids_with_explicit_repos_batch(client, batch)

    explicit_user_ids: set[str] = set()
    for batch_result in run_context.parallel_map(
        fetch_batch,
        batches,
        parallelism=parallelism,
        worker_pool=worker_pool,
        progress_label="Checked explicit repo permissions for user batches",
    ):
        explicit_user_ids.update(batch_result)
    return explicit_user_ids


def _user_ids_with_explicit_repos_batch(
    client: src.SourcegraphClient,
    user_ids: Sequence[str],
) -> set[str]:
    data = client.graphql(
        _user_explicit_repo_exists_batch_query(len(user_ids)),
        _user_explicit_repo_exists_batch_variables(user_ids),
        follow_pages=False,
    )
    explicit_user_ids: set[str] = set()
    for index, user_id in enumerate(user_ids):
        connection = _user_explicit_repos_connection(data, index)
        if connection is not None and src.json_list(connection.get("nodes")):
            explicit_user_ids.add(user_id)
    return explicit_user_ids


def _user_explicit_repo_exists_batch_variables(user_ids: Sequence[str]) -> src.JSONDict:
    variables: src.JSONDict = {}
    for index, user_id in enumerate(user_ids):
        variables[f"user{index}"] = user_id
    return variables


def list_user_explicit_repos(
    client: src.SourcegraphClient, user_id: str
) -> list[permission_types.Repository]:
    """Return all repos with `source: API` grants for `user_id`.

    Returns a list of `{id, name}` repository objects (matching the
    Repository TypedDict shape). Empty list if the user has no explicit
    grants OR if `permissionsInfo` is null (e.g. soft-deleted user).
    """
    return _repositories_from_ids(client, list_user_explicit_repo_ids(client, user_id))


def list_user_explicit_repo_ids(client: src.SourcegraphClient, user_id: str) -> list[str]:
    """Return repository IDs with `source: API` grants for `user_id`."""
    repository_ids: list[str] = []
    for node in client.stream_connection_nodes(
        queries.QUERY_USER_EXPLICIT_REPOS,
        {"id": user_id},
        connection_path=("node", "permissionsInfo", "repositories"),
        page_size=shared_sourcegraph.DEFAULT_PAGE_SIZE,
    ):
        repository_id = _permission_node_repository_id(node)
        if repository_id is not None:
            repository_ids.append(repository_id)
    return repository_ids


def list_users_explicit_repos(
    client: src.SourcegraphClient,
    user_ids: Sequence[str],
    *,
    batch_size: int,
) -> dict[str, list[permission_types.Repository]]:
    """Return explicit API repository grants for many users using GraphQL aliases."""
    return _repositories_by_user_id(
        client,
        list_users_explicit_repo_ids(client, user_ids, batch_size=batch_size),
    )


def list_users_explicit_repo_ids(
    client: src.SourcegraphClient,
    user_ids: Sequence[str],
    *,
    batch_size: int,
) -> dict[str, list[str]]:
    """Return explicit API repository IDs for many users using GraphQL aliases."""
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")

    repository_ids_by_user_id: dict[str, list[str]] = {user_id: [] for user_id in user_ids}
    pending_pages: list[tuple[str, str | None]] = [(user_id, None) for user_id in user_ids]
    while pending_pages:
        batch = pending_pages[:batch_size]
        del pending_pages[:batch_size]
        data = client.graphql(
            _user_explicit_repos_batch_query(len(batch)),
            _user_explicit_repos_batch_variables(batch),
            follow_pages=False,
        )
        for index, (user_id, previous_cursor) in enumerate(batch):
            connection = _user_explicit_repos_connection(data, index)
            if connection is None:
                continue
            repository_ids_by_user_id[user_id].extend(_connection_repository_ids(connection))
            page_info = src.json_dict(connection.get("pageInfo"))
            has_next_page = page_info.get("hasNextPage")
            if not isinstance(has_next_page, bool):
                raise src.GraphQLError(
                    f"UserExplicitReposBatch user{index} missing pageInfo.hasNextPage"
                )
            if has_next_page:
                next_cursor = src.json_str(page_info, "endCursor")
                if not next_cursor:
                    raise src.GraphQLError(
                        f"UserExplicitReposBatch user{index} missing pageInfo.endCursor"
                    )
                if next_cursor == previous_cursor:
                    raise src.GraphQLError(
                        f"UserExplicitReposBatch user{index} cursor stalled at {next_cursor!r}"
                    )
                pending_pages.append((user_id, next_cursor))
    return repository_ids_by_user_id


def list_repositories_by_ids(
    client: src.SourcegraphClient,
    repository_ids: Iterable[str],
    *,
    batch_size: int = shared_sourcegraph.DEFAULT_PAGE_SIZE,
) -> dict[str, permission_types.Repository]:
    """Return repository `{id, name}` objects for unique GraphQL repository IDs."""
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")

    unique_repository_ids = list(dict.fromkeys(repository_ids))
    repositories: dict[str, permission_types.Repository] = {}
    for batch in _batches(unique_repository_ids, batch_size):
        data = cast(
            dict[str, Any],
            client.graphql(
                _repositories_by_id_query(len(batch)),
                _repositories_by_id_variables(batch),
            ),
        )
        for index, requested_repository_id in enumerate(batch):
            repository = src.json_dict(data.get(f"repo{index}"))
            returned_repository_id = repository.get("id")
            repository_name = repository.get("name")
            if isinstance(returned_repository_id, str) and isinstance(repository_name, str):
                repositories[requested_repository_id] = {
                    "id": returned_repository_id,
                    "name": repository_name,
                }
    return repositories


def _batches(values: Sequence[str], batch_size: int) -> Iterator[Sequence[str]]:
    for start_index in range(0, len(values), batch_size):
        yield values[start_index : start_index + batch_size]


def _user_explicit_repos_batch_query(batch_size: int) -> str:
    variables = ["$first: Int!"]
    fields: list[str] = []
    for index in range(batch_size):
        variables.extend((f"$user{index}: ID!", f"$after{index}: String"))
        fields.append(
            f"""
  user{index}: node(id: $user{index}) {{
    ... on User {{
      permissionsInfo {{
        repositories(source: API, first: $first, after: $after{index}) {{
          nodes {{
            id
          }}
          pageInfo {{ hasNextPage endCursor }}
        }}
      }}
    }}
  }}"""
        )
    return "query UserExplicitReposBatch(" + ", ".join(variables) + ") {" + "".join(fields) + "\n}"


def _user_explicit_repo_exists_batch_query(batch_size: int) -> str:
    variables = [f"$user{index}: ID!" for index in range(batch_size)]
    fields = [
        f"""
  user{index}: node(id: $user{index}) {{
    ... on User {{
      permissionsInfo {{
        repositories(source: API, first: 1) {{
          nodes {{ id }}
        }}
      }}
    }}
  }}"""
        for index in range(batch_size)
    ]
    return (
        "query UserExplicitRepoExistsBatch("
        + ", ".join(variables)
        + ") {"
        + "".join(fields)
        + "\n}"
    )


def _user_explicit_repos_batch_variables(
    batch: Sequence[tuple[str, str | None]],
) -> src.JSONDict:
    variables: src.JSONDict = {"first": shared_sourcegraph.DEFAULT_PAGE_SIZE}
    for index, (user_id, cursor) in enumerate(batch):
        variables[f"user{index}"] = user_id
        variables[f"after{index}"] = cursor
    return variables


def _user_explicit_repos_connection(data: src.JSONDict, index: int) -> src.JSONDict | None:
    node = src.json_dict(data.get(f"user{index}"))
    permissions_info = src.json_dict(node.get("permissionsInfo"))
    connection = src.json_dict(permissions_info.get("repositories"))
    return connection or None


def _connection_repository_ids(connection: src.JSONDict) -> list[str]:
    repository_ids: list[str] = []
    for permission_node_value in src.json_list(connection.get("nodes")):
        permission_node = src.json_dict(permission_node_value)
        repository_id = _permission_node_repository_id(permission_node)
        if repository_id is not None:
            repository_ids.append(repository_id)
    return repository_ids


def _permission_node_repository_id(permission_node: src.JSONDict) -> str | None:
    repository_id = permission_node.get("id")
    return repository_id if isinstance(repository_id, str) else None


def _repositories_from_ids(
    client: src.SourcegraphClient,
    repository_ids: Sequence[str],
) -> list[permission_types.Repository]:
    repositories_by_id = list_repositories_by_ids(client, repository_ids)
    return [
        _repository_or_placeholder(repositories_by_id, repository_id)
        for repository_id in repository_ids
    ]


def _repositories_by_user_id(
    client: src.SourcegraphClient,
    repository_ids_by_user_id: dict[str, list[str]],
) -> dict[str, list[permission_types.Repository]]:
    unique_repository_ids = list(
        dict.fromkeys(
            repository_id
            for repository_ids in repository_ids_by_user_id.values()
            for repository_id in repository_ids
        )
    )
    repositories_by_id = list_repositories_by_ids(client, unique_repository_ids)
    missing_repository_ids = set(unique_repository_ids) - set(repositories_by_id)
    if missing_repository_ids:
        log.warning(
            "Could not hydrate names for %d repository ID(s); using ID placeholders.",
            len(missing_repository_ids),
        )
    return {
        user_id: [
            _repository_or_placeholder(repositories_by_id, repository_id)
            for repository_id in repository_ids
        ]
        for user_id, repository_ids in repository_ids_by_user_id.items()
    }


def _repository_or_placeholder(
    repositories_by_id: dict[str, permission_types.Repository],
    repository_id: str,
) -> permission_types.Repository:
    repository = repositories_by_id.get(repository_id)
    if repository is not None:
        return repository
    return _missing_repository(repository_id)


def _missing_repository(repository_id: str) -> permission_types.Repository:
    try:
        decoded_repository_id = src.decode_repository_id(repository_id)
        repository_name = f"<repository id={decoded_repository_id}>"
    except ValueError:
        repository_name = f"<repository id={repository_id}>"
    return {"id": repository_id, "name": repository_name}


def _repositories_by_id_query(batch_size: int) -> str:
    variables = [f"$repo{index}: ID!" for index in range(batch_size)]
    fields = [
        f"""
  repo{index}: node(id: $repo{index}) {{
    ... on Repository {{
      id
      name
    }}
  }}"""
        for index in range(batch_size)
    ]
    return "query RepositoryNamesByID(" + ", ".join(variables) + ") {" + "".join(fields) + "\n}"


def _repositories_by_id_variables(repository_ids: Sequence[str]) -> src.JSONDict:
    return cast(
        src.JSONDict,
        {f"repo{index}": repository_id for index, repository_id in enumerate(repository_ids)},
    )


def list_pending_bind_ids(client: src.SourcegraphClient) -> list[str]:
    """Return explicit-grant bindIDs pending a real User match."""
    data = cast(dict[str, Any], client.graphql(queries.QUERY_PENDING_BINDIDS))
    return cast(list[str], data["usersWithPendingPermissions"])
