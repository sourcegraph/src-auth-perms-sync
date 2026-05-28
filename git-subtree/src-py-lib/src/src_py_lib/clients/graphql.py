"""Shared GraphQL client primitives."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from src_py_lib.utils.http import HTTPClient, HTTPClientError
from src_py_lib.utils.json_types import JSONDict, JSONValue, json_dict, json_list, json_str
from src_py_lib.utils.logging import event

_OPERATION_NAME_RE = re.compile(r"\b(?:query|mutation|subscription)\s+(\w+)")

GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
""".strip()


class GraphQLError(RuntimeError):
    """Raised for GraphQL transport or application errors."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        is_application_error: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.is_application_error = is_application_error


@dataclass
class GraphQLClient:
    """POST JSON GraphQL operations and return the `data` object."""

    url: str
    headers: dict[str, str]
    label: str
    http: HTTPClient = field(default_factory=HTTPClient)
    tolerate_partial_errors: bool = False

    def execute(
        self,
        query: str,
        variables: Mapping[str, JSONValue] | None = None,
        *,
        follow_pages: bool = True,
        page_size: int | None = None,
        first_variable: str = "first",
        after_variable: str = "after",
    ) -> JSONDict:
        page_variables: JSONDict = dict(variables) if variables is not None else {}
        if page_size is not None:
            page_variables[first_variable] = page_size
        if (
            follow_pages
            and after_variable not in page_variables
            and _query_uses_variable(query, after_variable)
        ):
            page_variables[after_variable] = None

        page_number = 1
        data = self._execute_once(
            query,
            page_variables,
            page_number=page_number,
            first_variable=first_variable,
            after_variable=after_variable,
        )
        if follow_pages:

            def execute_next_page(next_variables: JSONDict) -> JSONDict:
                nonlocal page_number
                page_number += 1
                return self._execute_once(
                    query,
                    next_variables,
                    page_number=page_number,
                    first_variable=first_variable,
                    after_variable=after_variable,
                )

            _fetch_remaining_pages(
                execute_next_page,
                data,
                page_variables,
                after_variable=after_variable,
                query_uses_after_variable=_query_uses_variable(query, after_variable),
            )
        return data

    def stream_connection_nodes(
        self,
        query: str,
        variables: Mapping[str, JSONValue] | None = None,
        *,
        connection_path: Sequence[str],
        page_size: int | None = None,
        first_variable: str = "first",
        after_variable: str = "after",
    ) -> Iterator[JSONDict]:
        """Stream one GraphQL connection's nodes page by page.

        `connection_path` is the response path to the connection object that
        contains `nodes` and `pageInfo`, for example `("viewer", "items")`.
        Unlike `execute(..., follow_pages=True)`, this does not accumulate all
        nodes in memory before returning.
        """
        page_number = 1

        def execute_page(
            operation: str, page_variables: Mapping[str, JSONValue] | None
        ) -> JSONDict:
            nonlocal page_number
            data = self._execute_once(
                operation,
                dict(page_variables or {}),
                page_number=page_number,
                first_variable=first_variable,
                after_variable=after_variable,
            )
            page_number += 1
            return data

        yield from stream_connection_nodes(
            execute_page,
            query,
            variables,
            connection_path=connection_path,
            page_size=page_size,
            first_variable=first_variable,
            after_variable=after_variable,
        )

    def _execute_once(
        self,
        query: str,
        variables: JSONDict,
        *,
        page_number: int = 1,
        first_variable: str = "first",
        after_variable: str = "after",
    ) -> JSONDict:
        body = {"query": query, "variables": variables or {}}
        with event(
            "graphql_query",
            level="debug",
            graphql_client=self.label,
            query_name=operation_name(query),
            page_number=page_number,
            page_size=_int_variable(variables, first_variable),
            cursor_present=variables.get(after_variable) is not None,
            url=self.url,
            variable_names=sorted(variables),
            query_bytes=len(query.encode("utf-8")),
        ) as fields:
            try:
                payload = self.http.json("POST", self.url, headers=self.headers, json_body=body)
            except HTTPClientError as exception:
                raise GraphQLError(
                    f"{self.label} GraphQL request failed: {exception}",
                    status_code=exception.status_code,
                ) from exception
            errors = payload.get("errors")
            data = json_dict(payload.get("data"))
            fields["response_fields"] = sorted(data)
            if errors:
                fields["graphql_errors"] = len(errors) if isinstance(errors, list) else 1
            if errors and not (self.tolerate_partial_errors and data):
                raise GraphQLError(
                    f"{self.label} GraphQL errors: {errors}",
                    is_application_error=True,
                )
            return data


def operation_name(query: str) -> str:
    """Extract the operation name from a GraphQL document."""
    match = _OPERATION_NAME_RE.search(query)
    return match.group(1) if match else "anonymous"


def stream_connection_nodes(
    execute: Callable[[str, Mapping[str, JSONValue] | None], JSONDict],
    query: str,
    variables: Mapping[str, JSONValue] | None = None,
    *,
    connection_path: Sequence[str],
    page_size: int | None = None,
    first_variable: str = "first",
    after_variable: str = "after",
) -> Iterator[JSONDict]:
    """Stream one GraphQL connection's nodes through any execute callable."""
    page_variables: JSONDict = dict(variables) if variables is not None else {}
    if page_size is not None:
        page_variables[first_variable] = page_size
    query_uses_after_variable = _query_uses_variable(query, after_variable)
    if query_uses_after_variable and after_variable not in page_variables:
        page_variables[after_variable] = None

    path = tuple(connection_path)
    current_cursor = page_variables.get(after_variable)
    while True:
        data = execute(query, dict(page_variables))
        page = _node_page_at_path(data, path)
        for node in json_list(page.get("nodes")):
            yield json_dict(node)

        page_info = json_dict(page.get("pageInfo"))
        has_next_page = page_info.get("hasNextPage")
        if not isinstance(has_next_page, bool):
            raise GraphQLError(
                f"GraphQL pagination path {_path_label(path)} missing pageInfo.hasNextPage"
            )
        if not has_next_page:
            return
        if not query_uses_after_variable:
            raise GraphQLError(
                f"GraphQL query returned more pages but does not use ${after_variable}"
            )
        next_cursor = _next_page_cursor(page_info, path, current_cursor)
        page_variables[after_variable] = next_cursor
        current_cursor = next_cursor


def _int_variable(variables: JSONDict, name: str) -> int | None:
    value = variables.get(name)
    return value if isinstance(value, int) else None


def introspect_schema(
    client_or_execute: GraphQLClient | Callable[[str], JSONDict],
    *,
    output_file: Path | str | None = None,
) -> JSONDict | None:
    """Fetch a GraphQL introspection schema or write it to `output_file`.

    Pass either a `GraphQLClient` or a callable such as `SourcegraphClient.graphql`.
    When `output_file` is supplied, the schema JSON is written there and `None` is
    returned. Otherwise, the introspection `__schema` object is returned.
    """
    if isinstance(client_or_execute, GraphQLClient):
        data = client_or_execute.execute(GRAPHQL_INTROSPECTION_QUERY, follow_pages=False)
    else:
        data = client_or_execute(GRAPHQL_INTROSPECTION_QUERY)
    schema = json_dict(data.get("__schema"))
    if not schema:
        raise GraphQLError("GraphQL introspection response did not include __schema.")
    if output_file is None:
        return schema

    path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    return None


def aliased_batched_query(
    keys: list[str],
    *,
    batch_size: int,
    build_alias: Callable[[int, str], str | None],
    parse_node: Callable[[JSONDict], object | None],
    post: Callable[[str], JSONDict],
) -> dict[str, object]:
    """Look up many keys with GraphQL aliases in fixed-size batches."""
    results: dict[str, object] = {}
    for chunk_start in range(0, len(keys), batch_size):
        chunk = keys[chunk_start : chunk_start + batch_size]
        parts: list[str] = []
        for index, key in enumerate(chunk):
            alias = build_alias(index, key)
            if alias is not None:
                parts.append(f"q{index}: {alias}")
        if not parts:
            continue
        data = post("query { " + " ".join(parts) + " }")
        for index, key in enumerate(chunk):
            node = json_dict(data.get(f"q{index}"))
            if not node:
                continue
            value = parse_node(node)
            if value is not None:
                results[key] = value
    return results


def _fetch_remaining_pages(
    execute: Callable[[JSONDict], JSONDict],
    data: JSONDict,
    variables: JSONDict,
    *,
    after_variable: str,
    query_uses_after_variable: bool,
) -> None:
    paths = _next_page_paths(data)
    if not paths:
        return
    if len(paths) > 1:
        joined = ", ".join(".".join(path) for path in paths)
        raise GraphQLError(f"GraphQL query returned multiple paginated node lists: {joined}")
    if not query_uses_after_variable:
        raise GraphQLError(f"GraphQL query returned more pages but does not use ${after_variable}")

    path = paths[0]
    target_page = _node_page_at_path(data, path)
    target_nodes = json_list(target_page.get("nodes"))
    page_info = json_dict(target_page.get("pageInfo"))
    after = _next_page_cursor(page_info, path, variables.get(after_variable))

    while after:
        page_variables = dict(variables)
        page_variables[after_variable] = after
        next_data = execute(page_variables)
        next_page = _node_page_at_path(next_data, path)
        target_nodes.extend(json_list(next_page.get("nodes")))
        target_page["nodes"] = target_nodes
        target_page["pageInfo"] = next_page.get("pageInfo")

        next_page_info = json_dict(next_page.get("pageInfo"))
        has_next_page = next_page_info.get("hasNextPage")
        if not isinstance(has_next_page, bool):
            raise GraphQLError(
                f"GraphQL pagination path {'.'.join(path)} missing pageInfo.hasNextPage"
            )
        if not has_next_page:
            return
        after = _next_page_cursor(next_page_info, path, after)


def _next_page_paths(data: JSONDict) -> list[tuple[str, ...]]:
    paths: list[tuple[str, ...]] = []

    def visit(value: object, path: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            mapping = cast(JSONDict, value)
            page_info = json_dict(mapping.get("pageInfo"))
            if isinstance(mapping.get("nodes"), list) and page_info.get("hasNextPage") is True:
                paths.append(path)
                return
            for key, child in mapping.items():
                visit(child, (*path, key))
        elif isinstance(value, list):
            for child in cast(list[object], value):
                visit(child, path)

    visit(data, ())
    return paths


def _node_page_at_path(data: JSONDict, path: tuple[str, ...]) -> JSONDict:
    current: object = data
    for key in path:
        current = json_dict(current).get(key)
    page = json_dict(current)
    if not page:
        raise GraphQLError(f"GraphQL response did not include pagination path {_path_label(path)}")
    return page


def _next_page_cursor(page_info: JSONDict, path: tuple[str, ...], current_cursor: object) -> str:
    next_cursor = json_str(page_info, "endCursor")
    if not next_cursor:
        raise GraphQLError(
            f"GraphQL pagination path {_path_label(path)} missing pageInfo.endCursor"
        )
    if isinstance(current_cursor, str) and next_cursor == current_cursor:
        raise GraphQLError(
            f"GraphQL pagination path {_path_label(path)} stalled: "
            f"pageInfo.endCursor did not advance from {current_cursor!r}"
        )
    return next_cursor


def _path_label(path: tuple[str, ...]) -> str:
    return ".".join(path) or "<root>"


def _query_uses_variable(query: str, variable: str) -> bool:
    return re.search(rf"\${re.escape(variable)}\b", query) is not None
