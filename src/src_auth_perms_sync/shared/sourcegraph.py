"""Typed Sourcegraph GraphQL auth-provider/user helpers."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

import src_py_lib as src

from . import queries
from . import types as shared_types

# Default page size for every paginated GraphQL connection. Sourcegraph
# caps `first:` at 5000 across most schemas; 100 is a reasonable middle
# ground (small enough to keep p50 latency low and to limit memory per
# response, large enough to bound round-trips on big instances).
DEFAULT_PAGE_SIZE: int = 100


def list_auth_providers(client: src.SourcegraphClient) -> list[shared_types.AuthProvider]:
    data = cast(dict[str, Any], client.graphql(queries.QUERY_AUTH_PROVIDERS))
    return cast(list[shared_types.AuthProvider], data["site"]["authProviders"]["nodes"])


def count_users(client: src.SourcegraphClient) -> int:
    """Return the total number of users on the instance via `users.totalCount`.

    Cheap single-page query used to inform the user up-front how many users
    the subsequent `list_users_with_accounts()` pagination will iterate over.
    """
    data = cast(dict[str, Any], client.graphql(queries.QUERY_USER_COUNT))
    return cast(int, data["users"]["totalCount"])


def list_users_with_accounts(
    client: src.SourcegraphClient,
    *,
    include_emails: bool = False,
) -> list[shared_types.User]:
    return [
        cast(shared_types.User, node)
        for node in client.stream_connection_nodes(
            queries.query_users(include_emails=include_emails),
            connection_path=("users",),
            page_size=DEFAULT_PAGE_SIZE,
        )
    ]


def list_users_streaming(
    client: src.SourcegraphClient,
    collect_into: list[shared_types.User] | None = None,
    *,
    include_emails: bool = False,
) -> Iterator[shared_types.User]:
    """Stream ListUsers pages one at a time, yielding each User as it arrives.

    The caller can dispatch per-user work from inside the iteration loop;
    while the iterator blocks on the next ListUsers page, workers continue
    processing already-submitted tasks. Net effect is that a long ListUsers
    pagination overlaps with whatever per-user work the consumer has queued.

    If `collect_into` is provided, every yielded user is appended to that
    list, so the caller ends up with the materialized list AND the
    streaming benefit in one pass — no double-pagination.
    """
    for node in client.stream_connection_nodes(
        queries.query_users(include_emails=include_emails),
        connection_path=("users",),
        page_size=DEFAULT_PAGE_SIZE,
    ):
        user = cast(shared_types.User, node)
        if collect_into is not None:
            collect_into.append(user)
        yield user
