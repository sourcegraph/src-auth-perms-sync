"""Sourcegraph GraphQL API client."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from src_py_lib.clients.graphql import GraphQLClient, stream_connection_nodes
from src_py_lib.utils.config import Config, config_field
from src_py_lib.utils.http import HTTPClient
from src_py_lib.utils.json_types import JSONDict, JSONValue, json_dict

DEFAULT_SOURCEGRAPH_ENDPOINT = "https://sourcegraph.com"
SOURCEGRAPH_VALIDATE_QUERY = """
query SourcegraphClientValidate {
  currentUser {
    username
  }
}
"""


def normalize_sourcegraph_endpoint(endpoint: str, *, require_https: bool = False) -> str:
    """Return a stable Sourcegraph base URL, or raise ValueError."""
    normalized_endpoint = endpoint.strip().rstrip("/")
    endpoint_parts = urlsplit(normalized_endpoint)
    if require_https and endpoint_parts.scheme != "https":
        raise ValueError(
            f"Sourcegraph endpoint must be an https:// URL (got {endpoint_parts.scheme!r})"
        )
    if endpoint_parts.scheme not in {"http", "https"}:
        raise ValueError(
            "Sourcegraph endpoint must be an http:// or https:// URL "
            f"(got {endpoint_parts.scheme!r})"
        )
    if not endpoint_parts.hostname:
        raise ValueError(
            f"could not parse hostname from Sourcegraph endpoint {normalized_endpoint!r}"
        )
    return normalized_endpoint


class SourcegraphClientConfig(Config):
    """Config fields needed to build a Sourcegraph API client."""

    src_endpoint: str = config_field(
        default=DEFAULT_SOURCEGRAPH_ENDPOINT,
        env_var="SRC_ENDPOINT",
        cli_flag="--src-endpoint",
        metavar="URL",
        help=f"Sourcegraph instance URL (default: {DEFAULT_SOURCEGRAPH_ENDPOINT})",
    )
    src_access_token: str = config_field(
        default="",
        env_var="SRC_ACCESS_TOKEN",
        cli_flag="--src-access-token",
        metavar="TOKEN",
        help="Sourcegraph access token, or op:// secret reference",
        secret=True,
        required=True,
    )


@dataclass
class SourcegraphClient:
    """Small Sourcegraph GraphQL client.

    `endpoint` should be the instance base URL, for example
    `https://sourcegraph.example.com`.
    """

    endpoint: str
    token: str
    http: HTTPClient = field(default_factory=HTTPClient)

    def __post_init__(self) -> None:
        self.endpoint = normalize_sourcegraph_endpoint(self.endpoint)

    def graphql(self, query: str, variables: Mapping[str, JSONValue] | None = None) -> JSONDict:
        return self._client().execute(query, variables)

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
        """Stream one Sourcegraph GraphQL connection's nodes."""
        return stream_connection_nodes(
            self.graphql,
            query,
            variables,
            connection_path=connection_path,
            page_size=page_size,
            first_variable=first_variable,
            after_variable=after_variable,
        )

    def validate(self) -> JSONDict:
        """Validate the token with a cheap current user query and return the user."""
        current_user = json_dict(self.graphql(SOURCEGRAPH_VALIDATE_QUERY).get("currentUser"))
        if not current_user.get("username"):
            raise RuntimeError(
                "Sourcegraph current user response did not include currentUser.username."
            )
        return current_user

    def _client(self) -> GraphQLClient:
        return GraphQLClient(
            url=f"{self.endpoint}/.api/graphql",
            headers={"Authorization": f"token {self.token}"},
            label="Sourcegraph",
            http=self.http,
        )


def sourcegraph_client_from_config(config: SourcegraphClientConfig) -> SourcegraphClient:
    """Return a Sourcegraph API client from shared Sourcegraph Config fields."""
    return SourcegraphClient(
        endpoint=config.src_endpoint,
        token=config.src_access_token,
    )
