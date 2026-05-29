"""Sourcegraph GraphQL list helpers for repo-permission sync."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator, Sequence
from typing import Any, cast

import src_py_lib as src

from ..shared import id_codec
from ..shared import sourcegraph as shared_sourcegraph
from ..shared import types as shared_types
from . import queries
from . import types as permission_types

log = logging.getLogger(__name__)


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
            page_size=shared_sourcegraph.DEFAULT_PAGE_SIZE,
        )
    ]


def get_user_by_username(client: src.SourcegraphClient, username: str) -> shared_types.User | None:
    """Return the exact Sourcegraph user for `username`, if it exists."""
    data = cast(
        dict[str, Any],
        client.graphql(queries.QUERY_USER_BY_USERNAME, cast(src.JSONDict, {"username": username})),
    )
    return cast(shared_types.User | None, data.get("user"))


def get_user_by_email(client: src.SourcegraphClient, email: str) -> shared_types.User | None:
    """Return the user owning the verified email address, if it exists."""
    data = cast(
        dict[str, Any],
        client.graphql(queries.QUERY_USER_BY_EMAIL, cast(src.JSONDict, {"email": email})),
    )
    return cast(shared_types.User | None, data.get("user"))


def get_user_by_id(client: src.SourcegraphClient, user_id: str) -> shared_types.User | None:
    """Hydrate a User node by GraphQL ID."""
    data = cast(
        dict[str, Any],
        client.graphql(queries.QUERY_USER_BY_ID, cast(src.JSONDict, {"id": user_id})),
    )
    return cast(shared_types.User | None, data.get("node"))


def list_site_user_candidates(
    client: src.SourcegraphClient,
    created_after: str | None,
) -> list[shared_types.SiteUserCandidate]:
    """Return non-deleted site users, optionally filtered by creation time."""
    candidates: list[shared_types.SiteUserCandidate] = []
    offset = 0
    created_filter = {"gte": created_after} if created_after is not None else None
    while True:
        data = cast(
            dict[str, Any],
            client.graphql(
                queries.QUERY_SITE_USERS,
                cast(
                    src.JSONDict,
                    {
                        "limit": shared_sourcegraph.DEFAULT_PAGE_SIZE,
                        "offset": offset,
                        "createdAt": created_filter,
                    },
                ),
            ),
        )
        site_users = cast(dict[str, Any], data["site"]["users"])
        total_count = int(cast(float, site_users["totalCount"]))
        nodes = cast(list[shared_types.SiteUserCandidate], site_users["nodes"])
        candidates.extend(nodes)
        if not nodes or len(candidates) >= total_count:
            return candidates
        offset += len(nodes)


def user_has_explicit_repos(client: src.SourcegraphClient, user_id: str) -> bool:
    """Return whether the user has any explicit API repository grant."""
    data = cast(
        dict[str, Any],
        client.graphql(
            queries.QUERY_USER_EXPLICIT_REPO_EXISTS,
            cast(src.JSONDict, {"id": user_id}),
        ),
    )
    node = cast(dict[str, Any] | None, data.get("node"))
    if node is None:
        return False
    permissions_info = cast(dict[str, Any] | None, node.get("permissionsInfo"))
    if permissions_info is None:
        return False
    repositories = cast(dict[str, Any], permissions_info["repositories"])
    return bool(src.json_list(repositories.get("nodes")))


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
    graphql_client = _graphql_client_without_auto_pagination(client)
    while pending_pages:
        batch = pending_pages[:batch_size]
        del pending_pages[:batch_size]
        data = graphql_client.execute(
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


def _graphql_client_without_auto_pagination(client: src.SourcegraphClient) -> src.GraphQLClient:
    return src.GraphQLClient(
        url=f"{client.endpoint}/.api/graphql",
        headers={"Authorization": f"token {client.token}"},
        label="Sourcegraph",
        http=client.http,
    )


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
        decoded_repository_id = id_codec.decode_repository_id(repository_id)
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
