"""Encode/decode Sourcegraph opaque GraphQL Node IDs for workflows.

Sourcegraph follows the [Relay Object Identification spec](
https://relay.dev/graphql/objectidentification.htm): every node has a
globally-unique opaque `id` of the form

    base64(f"{TypeName}:{DatabasePrimaryKey}")

e.g. `ExternalService:5` → `RXh0ZXJuYWxTZXJ2aWNlOjU=`.

These helpers translate between the opaque GraphQL form (used on the
wire) and the integer primary key (used in our YAML config and logs).
The integer form is much friendlier for a human authoring mapping
rules — base64 strings of internal type names leak abstraction and are
hard to copy/diff by eye.
"""

from __future__ import annotations

import base64

EXTERNAL_SERVICE_TYPE_PREFIX = "ExternalService"
REPOSITORY_TYPE_PREFIX = "Repository"


def _encode_node_id(type_prefix: str, db_id: int) -> str:
    raw = f"{type_prefix}:{db_id}".encode()
    return base64.b64encode(raw).decode()


def _decode_node_id(type_prefix: str, graphql_id: str) -> int:
    try:
        raw = base64.b64decode(graphql_id, validate=True).decode()
    except (ValueError, UnicodeDecodeError) as exception:
        raise ValueError(f"not a valid base64 GraphQL Node ID: {graphql_id!r}") from exception
    prefix, separator, suffix = raw.partition(":")
    if not separator or prefix != type_prefix:
        raise ValueError(f"not a {type_prefix} Node ID: {graphql_id!r} (decoded: {raw!r})")
    try:
        return int(suffix)
    except ValueError as exception:
        raise ValueError(
            f"{type_prefix} Node ID has non-integer suffix: {graphql_id!r} (decoded: {raw!r})"
        ) from exception


def decode_external_service_id(graphql_id: str) -> int:
    """Opaque ExternalService GraphQL Node ID → integer DB primary key.

    Raises ValueError if `graphql_id` is not a well-formed
    `ExternalService:<int>` node ID.
    """
    return _decode_node_id(EXTERNAL_SERVICE_TYPE_PREFIX, graphql_id)


def encode_repository_id(db_id: int) -> str:
    """Integer DB primary key → opaque Repository GraphQL Node ID."""
    return _encode_node_id(REPOSITORY_TYPE_PREFIX, db_id)


def decode_repository_id(graphql_id: str) -> int:
    """Opaque Repository GraphQL Node ID → integer DB primary key.

    Raises ValueError if `graphql_id` is not a well-formed
    `Repository:<int>` node ID.
    """
    return _decode_node_id(REPOSITORY_TYPE_PREFIX, graphql_id)
