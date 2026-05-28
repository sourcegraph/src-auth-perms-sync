"""GitHub GraphQL API client."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import TypedDict, cast
from urllib.parse import urlsplit

from src_py_lib.clients.graphql import GraphQLClient, aliased_batched_query
from src_py_lib.utils.http import HTTPClient
from src_py_lib.utils.json_types import JSONDict, json_dict, json_str

DEFAULT_GITHUB_URL = "https://github.com"
DEFAULT_PR_BATCH_SIZE = 50
GITHUB_VALIDATE_QUERY = """
query GitHubClientValidate {
  viewer {
    login
  }
}
"""
PR_REF_RE = re.compile(r"^(?P<owner>[^/]+)/(?P<repo>[^/#]+)#(?P<number>\d+)$")
PR_URL_RE = re.compile(
    r"https?://[^/\s)>|]+/(?P<owner>[^/\s)>|]+)/(?P<repo>[^/\s)>|]+)/pull/(?P<number>\d+)"
)


class PullRequest(TypedDict):
    title: str
    url: str
    state: str
    createdAt: str
    mergedAt: str
    closedAt: str
    author: str


@dataclass
class GitHubClient:
    token: str
    github_url: str = DEFAULT_GITHUB_URL
    http: HTTPClient = field(default_factory=HTTPClient)

    @classmethod
    def from_gh_cli(
        cls, *, github_url: str = DEFAULT_GITHUB_URL, http: HTTPClient | None = None
    ) -> GitHubClient:
        token = gh_cli_token(github_url=github_url)
        if not token:
            raise RuntimeError("No GitHub token from `gh auth token`.")
        return cls(token=token, github_url=github_url, http=http or HTTPClient())

    def graphql(self, query: str, variables: JSONDict | None = None) -> JSONDict:
        return GraphQLClient(
            url=graphql_api_url(self.github_url),
            headers={"Authorization": f"bearer {self.token}"},
            label="GitHub",
            http=self.http,
            tolerate_partial_errors=True,
        ).execute(query, variables)

    def validate(self) -> JSONDict:
        """Validate the token with a cheap viewer query and return the viewer."""
        viewer = json_dict(self.graphql(GITHUB_VALIDATE_QUERY).get("viewer"))
        if not viewer.get("login"):
            raise RuntimeError("GitHub viewer response did not include viewer.login.")
        return viewer

    def get_pull_requests(
        self, refs: list[str], *, batch_size: int = DEFAULT_PR_BATCH_SIZE
    ) -> dict[str, PullRequest]:
        return cast(
            dict[str, PullRequest],
            aliased_batched_query(
                refs,
                batch_size=batch_size,
                build_alias=_build_pr_alias,
                parse_node=_project_pull_request,
                post=self.graphql,
            ),
        )


def graphql_api_url(github_url: str = DEFAULT_GITHUB_URL) -> str:
    """Return the GraphQL API URL for github.com or a GitHub Enterprise host."""
    normalized = _normalize_github_url(github_url)
    split = urlsplit(normalized)
    if split.hostname == "github.com":
        return f"{split.scheme}://api.github.com/graphql"
    return f"{normalized}/api/graphql"


def gh_cli_token(*, github_url: str = DEFAULT_GITHUB_URL) -> str | None:
    """Return `gh auth token`, or None when gh is unavailable/not logged in."""
    split = urlsplit(_normalize_github_url(github_url))
    command = ["gh", "auth", "token"]
    if split.hostname and split.hostname != "github.com":
        command.extend(["--hostname", split.netloc])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except OSError:
        return None
    except subprocess.SubprocessError:
        return None
    token = result.stdout.strip()
    return token if result.returncode == 0 and token else None


def _normalize_github_url(github_url: str) -> str:
    stripped = github_url.strip().rstrip("/")
    if "://" not in stripped:
        stripped = f"https://{stripped}"
    return stripped


def parse_pr_ref(ref: str) -> tuple[str, str, int]:
    match = PR_REF_RE.match(ref)
    if not match:
        raise ValueError(f"invalid GitHub PR ref: {ref!r}")
    return match.group("owner"), match.group("repo"), int(match.group("number"))


def pr_ref_from_url(url: str) -> str | None:
    match = PR_URL_RE.search(url)
    if not match:
        return None
    return f"{match.group('owner')}/{match.group('repo')}#{match.group('number')}"


def _build_pr_alias(_index: int, ref: str) -> str | None:
    try:
        owner, repo, number = parse_pr_ref(ref)
    except ValueError:
        return None
    return (
        f"repository(owner: {json.dumps(owner)}, name: {json.dumps(repo)}) "
        f"{{ pullRequest(number: {number}) "
        "{ title url state createdAt mergedAt closedAt author { login } } }"
    )


def _project_pull_request(node: JSONDict) -> PullRequest | None:
    pull_request = json_dict(node.get("pullRequest"))
    if not pull_request:
        return None
    return {
        "title": json_str(pull_request, "title"),
        "url": json_str(pull_request, "url"),
        "state": json_str(pull_request, "state"),
        "createdAt": json_str(pull_request, "createdAt"),
        "mergedAt": json_str(pull_request, "mergedAt"),
        "closedAt": json_str(pull_request, "closedAt"),
        "author": json_str(json_dict(pull_request.get("author")), "login"),
    }
