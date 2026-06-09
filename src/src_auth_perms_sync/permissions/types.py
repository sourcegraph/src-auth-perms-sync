"""TypedDict shapes for repo-permission sync."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypeAlias, TypedDict

from ..shared import types as shared_types

SetCommandMode: TypeAlias = Literal[
    "full",
    "users",
    "users_without_explicit_perms",
    "created_after",
]


@dataclass(frozen=True)
class SetCommandOptions:
    """Operator-selected mode for the set command."""

    mode: SetCommandMode
    user_identifiers: tuple[str, ...] = ()
    user_created_after: str | None = None


class UserRef(TypedDict):
    username: str


class ExternalService(TypedDict):
    id: str
    kind: str
    displayName: str
    url: str
    repoCount: int
    createdAt: str
    updatedAt: str
    lastSyncAt: str | None
    nextSyncAt: str | None
    lastSyncError: str | None
    warning: str | None
    unrestricted: bool
    suspended: bool
    hasConnectionCheck: bool
    supportsRepoExclusion: bool
    creator: UserRef | None
    lastUpdater: UserRef | None
    config: str


class Repository(TypedDict):
    id: str
    name: str


@dataclass(frozen=True, slots=True)
class RepositoryUsernameOverwrite:
    """One repo overwrite plan using Sourcegraph usernames as bindIDs."""

    repository_id: str
    repository_name: str
    usernames: tuple[str, ...]


class AuthProviderMatcher(TypedDict, total=False):
    """Match users by Sourcegraph auth provider discovery fields."""

    type: str
    serviceID: str
    clientID: str
    displayName: str
    configID: str
    samlGroup: str


class CodeHostConnectionMatcher(TypedDict, total=False):
    """Match repos by Sourcegraph code-host connection discovery fields."""

    kind: str
    displayName: str
    url: str
    username: str


class UserSelector(TypedDict, total=False):
    """User selectors. Fields AND together; values inside each field OR."""

    authProvider: AuthProviderMatcher
    emails: list[str]
    emailRegexes: list[str]
    usernames: list[str]
    usernameRegexes: list[str]


class RepositorySelector(TypedDict, total=False):
    """Repository selectors. Fields AND together; values inside each field OR."""

    codeHostConnection: CodeHostConnectionMatcher
    names: list[str]
    nameRegexes: list[str]


class MappingRule(TypedDict):
    name: str
    users: UserSelector
    repos: RepositorySelector


class ConfigFile(TypedDict, total=False):
    authProviders: list[dict[str, Any]]
    codeHostConnections: list[dict[str, Any]]
    maps: list[MappingRule]


@dataclass(frozen=True)
class MappingContext:
    """Discovery state needed by permission mapping."""

    mapping_rules: list[MappingRule]
    providers: list[shared_types.AuthProvider]
    saml_groups_attribute_names: dict[tuple[str, str], str]
    services_by_id: dict[int, ExternalService]
    repos_by_external_service_id: dict[int, list[Repository]]
    all_repos_by_id: dict[str, Repository]
